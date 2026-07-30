.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Cross-component contracts
=========================

Surfaces that two components must agree on. Changing one side without the other
ships either a build that fails to link or a mixed-version fleet that silently
stops interoperating.

Attestation report wire format
==============================

The attestation report (``include/attestation.h``, serialized by
``src/agent/report.c``, parsed by ``src/verifier/types/report.go``) has a fixed
struct followed by variable-length sections: the BPF event array, the TPM event
log, and the ESRT firmware-version descriptor.

**Every section is mandatory.** The verifier accepts exactly one report wire
version and rejects any other, so there is no mixed-version fleet to parse
defensively for: a report that stops before a section is truncated, not old. A
platform with nothing to report says so in the section's own fields -- the ESRT
descriptor carries ``present = 0`` where the firmware exposes no System
Firmware entry.

A breaking layout change -- adding, removing or reordering a field, or adding a
section -- bumps ``LOTA_VERSION_MAJOR`` in ``include/lota.h`` and
``ReportVersion`` in ``types/report.go`` together. That is a flag-day: roll the
verifier tier first, then the agents. Version 2 dropped the always-empty
``ek_certificate`` field (the Privacy CA model means the verifier never sees an
EK) and made the ESRT section mandatory.

Nothing links the C serializer and the Go parser at build time: the serializer
``memcpy``\ s a packed struct, the parser walks hand-computed offsets. Three
checks stand in for that missing link, and a layout change must satisfy all
three:

* ``src/agent/report.c`` pins ``sizeof`` for each wire struct with
  ``_Static_assert``, so a field added or removed on the C side fails the build
  with the name of the constant to update.
* ``TestParseReport_FieldOffsetsMatchCLayout`` (``types/report_test.go``)
  writes a distinct marker at each expected offset and requires the parsed
  report to expose it in the matching field -- a positive check, not a bounds
  test.
* ``make test`` runs the pair
  ``tests/cross_lang/report_gen.c`` -> ``report_verify.go``: C serializes a
  report whose every field carries a position-derived pattern, Go parses it
  with the production parser and checks each field against the same patterns.
  The patterns are restated in both files on purpose.

Baseline store migrations
=========================

The verifier's per-client baseline lives in the ``baselines`` table
(``src/verifier/store/db.go``). Both backends ship **one consolidated
migration**: a fresh database is created at its final shape in a single step,
and there is no incremental history to walk.

The migration list stays because the schema evolves the same way from here:
never edit the shipped entry, append a new one, so a database already in
service reaches the current shape by applying what it is missing.

An appended migration must also be **additive**: add a table, a column, or an
index, but never drop or rename one or retype a column in place. A live
database is migrated by whichever instance starts first, under an advisory
lock, while the rest of the fleet keeps operating it -- only an additive change
is invisible to them. ``migrations_test.go`` enforces this mechanically: a
destructive migration fails the build, and ``PgTargetSchemaVersion`` /
``SQLiteTargetSchemaVersion`` report the schema a binary builds up to (surfaced
to operators by ``lota-verifier --print-versions``).

The operator-facing side of this contract is
:doc:`../../operator/protocol-versions`.

The ``ReanchorStorer`` interface (``verify/baseline.go``) has three backends
(in-memory, SQLite, Postgres) that must stay behaviourally identical; the
in-memory store is the contract reference exercised by ``boot_baseline_test.go``.

Baseline store concurrency
==========================

The write fence of the Postgres baseline store is the **per-client**
transaction-scoped advisory lock
(``pg_advisory_xact_lock(hashtextextended(client_id, 0))``): every writer
for one ``client_id`` serializes, and nothing wider does. Independent
clients must commit concurrently -- that property is what lets a
registration burst and steady-state attestation scale with the connection
pool, and ``pg_integration_test.go``
(``TestPostgresAttestationIndependentClientsDoNotSerialize``) enforces it
mechanically: a store-level mutex around the transactions reintroduces a
process-wide write lock and fails the test.

The SQLite store is different by design, not by accident: SQLite's
single-writer model serializes all writes in one file, so its throughput
is a property of the backend, not a contract to fix. Deployments that
need write concurrency use the Postgres backend (``--pg-dsn``).

The nonce store follows the same rule: ``NonceStore`` (``verify/nonce.go``)
holds its mutex only around the in-memory maps and calls the used-nonce
backend -- a database round trip per call on the persistent backends --
outside the lock, so ``UsedNonceBackend`` implementations must be safe for
concurrent use, and consumption stays one-time because the pending-map
delete under the mutex has exactly one winner
(``TestNonceStore_IndependentVerificationsDoNotSerializeOnBackend``).

Per-report bookkeeping writes must also be no-ops when nothing changed:
the tenant stamp (``SetClientTenant``) runs on every verified report, and
an unconditional row rewrite costs a WAL record and a commit fsync each
time, so the UPDATE is conditional on a real tenant change
(``TestPostgresRepeatedTenantStampDoesNotRewriteRow``).

Attestation log durability
==========================

The attestation decision log (``attestation_log`` table) is an append-only
audit trail, not an attestation gate: a failed or delayed log write never
changes a verdict. To keep the audit write off the verification hot path,
the durable backends are wrapped in ``store.BatchedAttestationLog``
(``src/verifier/store/attestation_batch.go``). ``Record`` only buffers the
entry and returns; a background worker flushes the buffer to the backend as
a single batch -- one commit fsync per flush instead of one per report --
on a timer or once the buffer fills.

The contract this creates:

- **Eventual consistency, bounded.** A recorded decision becomes durable
  within one flush interval (default one second). ``QueryAttestations``
  flushes first, so the monitoring API always reads its own recent writes.
- **Crash-loss bound.** An ungraceful stop loses at most the records
  buffered since the last flush. This is acceptable precisely because the
  log gates nothing; the anti-replay nonce, baseline and session writes
  that *do* gate stay synchronous. A graceful shutdown flushes the tail.
- **Bounded memory.** Under a stalled database the buffer drops its oldest
  records past ``MaxBuffer`` rather than growing without limit, counting
  the loss. The hot path is never blocked and never sees the error.

Any new attestation-log backend implements ``BatchRecorder`` so a batch
costs one round trip; a backend that does not is still correct through the
per-record fallback, only slower.

Store sharding
==============

When a deployment runs with ``--pg-shard-dsn`` the per-client write stores
are partitioned across N databases (``verify/shard.go``,
``verify/shard_baseline.go``). The contract every shard router upholds:

- **Shard by the operation's own key.** The baseline routes by client ID,
  a nonce by its key, a session token by its bytes. No operation needs
  data from two shards, so there is never a cross-shard transaction.
- **Deterministic, process-independent routing.** The index is
  ``FNV-1a(key) mod N``. Two verifier instances given the same shard list
  in the same order route every key identically -- this is what preserves
  replay protection (a nonce's Record and Contains hit one shard) and the
  cross-instance session guarantee (a token issued on one instance
  validates on another).
- **Per-client atomicity is preserved.** A client's baseline lives on
  exactly one shard, so the underlying store's atomic read-modify-write
  (``AtomicBaselineStorer``) is unchanged; sharding never splits one
  client's decision across databases.
- **No silent capability loss.** ``ShardedBaselineStore`` reproduces the
  full baseline capability set and asserts every shard provides it at
  construction, so boot-PCR pinning, tenancy and re-anchor keep working
  under sharding. A compile-time check pins that the wrapper satisfies the
  set the verifier probes.
- **The shard set is pinned, not assumed.** Routing is positional, so a
  divergent list is a correctness bug an operator cannot see: it breaks
  replay protection and cross-instance sessions for whichever clients it
  moves. Each database mints a stable identity (``shard_identity``) and the
  control database records the fingerprint of the ordered list
  (``shard_set``, ``store/shard_identity.go``); a mismatch fails startup
  closed. Identity is per database rather than per DSN because the same
  database is reachable under different credentials, hostnames or a pooler,
  and none of that changes routing.

Fleet-global, read-mostly state (revocations, bans, audit, attestation
log) is not sharded; it lives on the first shard, the control database.
The operator-facing side is :doc:`../../operator/ha-deployment`.

Connection pool and group commit
================================

Postgres commits concurrent transactions in a single WAL fsync (group
commit), so the per-instance connection pool ceiling
(``--pg-max-open-conns``, ``store.DefaultPGMaxOpenConns``) is not just a
resource cap -- it bounds how many enrollment/attestation writes coalesce
per fsync. A wider pool therefore lifts burst throughput until it reaches
the database's ``max_connections``, which is shared by every instance's
pool (and every shard's, since each shard is a separate database). The
default stays conservative (20) so an untuned multi-instance deployment
cannot exhaust ``max_connections``; raising it is an operator trade against
that budget, documented in :doc:`../../operator/ha-deployment`.

The value is validated rather than trusted. A pool below 1 is refused at
startup: ``database/sql`` reads 0 as *unlimited*, and the store's own
non-positive fallback would otherwise hand back the default without the
operator knowing. Against the server, ``store.ServerMaxConnections``
reports the budget and the verifier warns when the pool exceeds it or
leaves no room for a second instance. Those comparisons stay advisory, and
an unreadable setting is treated as unknown: behind a connection pooler the
backend's ``max_connections`` is not the limit that applies, so failing
closed on it would refuse a legitimate topology.

Publisher selection over IPC
----------------------------

``LOTA_IPC_CMD_SET_PROFILE`` binds a connection to one publisher, named by the
SHA-256 of that publisher's CA trust anchor SubjectPublicKeyInfo -- the same
identity ``/var/lib/lota/profiles/`` is keyed by. It is connection state, not a
per-request argument, because a title plays for one publisher: after it,
``GET_TOKEN`` quotes with that publisher's AIK and ``GET_STATUS`` answers with
that publisher's verdict and validity window.

Three rules the agent holds to:

* An identity the host has no profile for is **refused**
  (``LOTA_IPC_ERR_UNKNOWN_PROFILE``), never quietly answered for another
  publisher.
* The attestation loop leaves the TPM bound to the first profile between
  rounds, so a connection bound elsewhere rebinds for its quote and restores
  the binding afterwards. They share one TPM and the loop expects the binding
  it left.
* A connection that never sends it keeps the host-wide answers: attested only
  while every configured publisher is satisfied.

``LOTA_IPC_VERSION`` is 2 for this command. The agent refuses any other
version outright rather than negotiating: ``lota_ipc.h`` is internal, and the
agent and the SDK that speaks to it ship together.

Status flags are the same bits on both sides of that boundary:
``LOTA_STATUS_*`` in ``include/lota_ipc.h`` and ``LOTA_FLAG_*`` in
``include/lota_gaming.h`` are two names for one wire value, and the SDK copies
the word through rather than translating it. A flag added to one header
without the other silently means something different to the title than to the
agent, so ``test_publisher_profile`` asserts the agreement.

``LOTA_STATUS_TOKEN_ONLY`` is the flag that makes a cleared
``LOTA_STATUS_ATTESTED`` readable. A publisher configured with
``verifier = none`` is never reported to, so the host holds no verdict of
theirs; without a second bit, a title could not tell that from a machine that
failed verification, and the two call for opposite behaviour. It is set on a
connection bound to such a publisher, and on the host-wide answer when no
configured publisher runs a verifier at all.

GET_TOKEN rate limits
=====================

Every ``GET_TOKEN`` costs a fresh TPM quote, so the agent limits how fast
they can be asked for. The limits are two, and they measure different things
(``TOKEN_RATE_LIMIT_PER_SESSION`` and ``TOKEN_RATE_LIMIT`` in
``src/agent/ipc.h``).

The **session budget** is what one title may spend. A connection is a
session, and a title holds one, so the budget is held on the connection and
dies with it. It is sized so no realistic heartbeat reaches it.

The **uid ceiling** is the bound on how much of the TPM one user may consume.
It has to hold several sessions at once, because on a player's machine every
title runs as the same uid: a ceiling sized for one title throttles the second
game for what the first one spent.

Both are needed. Without the session budget one title can spend the whole uid
allowance; without the uid ceiling a caller opens connections until the TPM is
saturated. Three ``_Static_assert``\ s in ``ipc.h`` keep the relationship
honest: the session budget must exceed the reference heartbeat rate, the uid
ceiling must cover at least two sessions, and the session budget must stay
the tighter of the two. Changing either constant without the other fails the
build rather than starving a title at runtime.

Attestation token quote binding
===============================

The token's TPM quote signs one 32-byte value, its ``extraData``, and that
value is what ties every other field in the token to the signature:

.. code-block:: text

   extraData = SHA256(valid_until || flags || pcr_mask || nonce ||
                      policy_digest || runtime_protect_digest ||
                      runtime_protect_epoch)

Integers are little-endian. Three implementations must agree on it byte for
byte: the agent that builds the quote
(``include/lota_token_quote_nonce.h``), the C verifier
(``lota_server_verify_token()`` in ``src/sdk/lota_server.c``) and the Go one
(``ComputeTokenQuoteNonce`` in ``sdk/server/verify.go``). A field that is not
in this digest is *not* signed, however trustworthy it looks in the struct,
so adding one to the token means adding it here in all three places.

A relying party should call one of the two verifiers rather than
reimplement the binding.

Both also apply the same freshness window, and that is the second thing
they must agree on. The token carries an expiry and no issue time, so
``valid_until`` is the only temporal anchor: an agent on the default
attestation interval mints a token expiring one interval from now, and both
verifiers refuse one whose expiry is further ahead than
``LOTA_SERVER_MAX_TOKEN_AGE_SEC`` plus ``LOTA_SERVER_MAX_CLOCK_SKEW_SEC``
(``DefaultMaxTokenAge`` and ``MaxClockSkew`` in Go). Raising the agent's
``attest_interval`` above that window makes every token it mints
unverifiable, so the two move together. A relying party that wants a
tighter bound than the window applies it to the verified ``valid_until``
itself.

IPC token payload budget
========================

Signed token returned over the local socket (``struct lota_ipc_token`` in
``include/lota_ipc.h``, built by ``src/agent/ipc.c``, parsed by the SDK in
``src/sdk/lota_gaming.c``) must fit ``LOTA_IPC_MAX_PAYLOAD``. Every protected
PID costs four bytes in the PID list plus a 32-byte kernel image digest in a
v2 token, so ``LOTA_IPC_TOKEN_MAX_PROTECT_PIDS`` is derived from the payload
budget left after the header, a maximum quote and a maximum signature -- it is
the real per-token limit, not a round number.

Both sides take the cap from the shared header, so the agent and the SDK
parser stay in lockstep; changing the payload size or the per-PID cost must
keep the derived cap and that test in agreement.

Installer probes and agent gates
================================

The guided installer's stage probes (``installer/probe.c``) must mirror the
agent's startup gates in ``src/agent/bpf_loader.c``. When a gate changes,
change the matching probe and the pinned parser tests in
``tests/test_installer_probe.c`` (part of ``make test-unit``); otherwise the
installer reports a host green that the agent would refuse to run on.
