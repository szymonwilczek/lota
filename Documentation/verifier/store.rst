.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============
Baseline store
==============

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
:doc:`../admin-guide/protocol-versions`.

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

What a decision-log row means
=============================

A row in ``attestation_log`` records an event on one host, not a round. A
trusted round matching the host's newest trusted row (tenant, client,
hardware ID, PCR 14, kernel hash, detail) extends it: ``last_seen`` moves
and ``rounds`` counts it. Every other round opens a row: a first round, any
non-trusted verdict, a recovery, a round behind ``last_seen``, or one past
``--attestation-log-window`` from the row's opening (default one hour; zero
writes a row per round). A steady host leaves one row per window.

Both SQL stores read and extend the newest row in one transaction; Postgres
also holds an advisory lock per tenant and client until commit, so
instances sharing a database record one host serially, first round
included. SQLite serializes on its mutex. An unreadable newest row is never
extended.

Both of a row's times are written in UTC and compared as instants, so
verifiers in different zones agree.

``QueryAttestations`` narrows a read by window, verdict, events-only and
client. A window returns the rows that overlap it, not only those opened
inside it. Both SQL stores build the clauses with one function.

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
  that *do* gate stay synchronous. A graceful shutdown flushes the tail,
  bounded: a backend that has stopped answering does not hold the process
  open, and what is still buffered at the deadline is counted as lost.
- **Bounded memory, shedding heartbeats first.** Past ``MaxBuffer`` the
  buffer sheds trusted rounds, oldest first; their standing row already
  says what they say. Refusals go only when no trusted round is left. The
  hot path never blocks and never sees the error.
- **What a shed costs.** A shed first sighting or verdict change to trusted
  is not lost: the next trusted round opens the row, at its later time.
- **Reported loss.** What the writer could not keep reaches somebody: a
  rate-limited warning naming the running total, the
  ``lota_attestation_log_dropped_total`` and
  ``lota_attestation_log_failed_total`` counters, and one summary line at
  shutdown. A deployment that lost part of its decision log has to look
  different from one that did not, so a counter with no reader is not
  counting.
- **What kind of loss.** ``lota_attestation_log_events_lost_total`` counts
  the events among it, shed or never landed. Shed trusted rounds are the
  bound working; a lost refusal is a hole in the audit trail.

Any new attestation-log backend implements ``BatchRecorder`` so a batch
costs one round trip; a backend that does not is still correct through the
per-record fallback, only slower.

Store sharding
==============

When a deployment runs with ``--pg-shard-dsn`` the per-client write stores
are partitioned across N databases (``verify/shard.go``,
``verify/shard_baseline.go``). The contract every shard router upholds:

- **Shard by the operation's own key.** The baseline routes by client ID
  and a nonce by its key. No operation needs data from two shards, so there
  is never a cross-shard transaction.
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
The operator-facing side is :doc:`../admin-guide/ha-deployment`.

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
that budget, documented in :doc:`../admin-guide/ha-deployment`.

The value is validated rather than trusted. A pool below 1 is refused at
startup: ``database/sql`` reads 0 as *unlimited*, and the store's own
non-positive fallback would otherwise hand back the default without the
operator knowing. Against the server, ``store.ServerMaxConnections``
reports the budget and the verifier warns when the pool exceeds it or
leaves no room for a second instance. Those comparisons stay advisory, and
an unreadable setting is treated as unknown: behind a connection pooler the
backend's ``max_connections`` is not the limit that applies, so failing
closed on it would refuse a legitimate topology.
