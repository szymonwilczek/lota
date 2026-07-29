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
