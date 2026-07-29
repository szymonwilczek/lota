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
``src/agent/report.c``, parsed by ``src/verifier/types/report.go``) ends with
optional variable-length sections. A new trailing section must be appended
after the existing ones and parsed defensively -- absent for older agents -- so
a mixed-version fleet keeps interoperating without a wire-version bump. The
ESRT firmware-version section (``src/agent/esrt.c``, ``test_esrt``) follows
that pattern.

Keep the C serializer and the Go parser in lockstep when the layout changes.

Baseline store migrations
=========================

The verifier's per-client baseline lives in the ``baselines`` table
(``src/verifier/store/db.go``) and evolves through append-only migrations:
never edit a shipped migration, add a new one, so a database at any
intermediate revision still upgrades cleanly.

New migrations must also be **additive**: add a table, a column, or an index,
but never drop or rename one or retype a column in place.

Multi-instance fleet rolls new verifier binaries in against one shared Postgres
while old binaries keep serving, so the old binary must still read and write
a schema a newer peer has already migrated forward. ``migrations_test.go`` enforces
this mechanically -- a destructive migration fails the build -- and
``PgTargetSchemaVersion`` / ``SQLiteTargetSchemaVersion`` report the schema
a binary targets (surfaced to operators by ``lota-verifier --print-versions``).

The operator-facing side of this contract is
:doc:`../../operator/rolling-upgrade`.

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
