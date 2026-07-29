.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===========================
LOTA performance evaluation
===========================

Baseline measurements of the LOTA hot paths. Methodology, tooling, and the
L2/L3 runbooks live in :ghsrc:`benchmarks/README.rst`; regenerate the raw data with
``make bench`` or :ghsrc:`benchmarks/scripts/run_all.sh`.

This document is a **snapshot**. Absolute values scale with the CPU, but the
relative cost ordering (RSA verify >> parse/codec) is stable.

Baseline host
=============

.. list-table::
   :widths: 25 75

   * - CPU
     - AMD Ryzen 7 5700X (8C/16T)
   * - Toolchain
     - Go 1.26, gcc 16
   * - Build
     - ``-O2`` + full hardening CFLAGS (see Makefile)
   * - Date
     - 2026-06-02

| All L1 figures are **single-threaded** (one core).
| Throughput is per-core: see the scaling note at the end.

L1 -- micro-benchmarks
======================

Crypto / attestation verify (verifier + server SDK)
---------------------------------------------------

The per-attestation cost a verifier or game server pays is dominated by the
RSA-2048 quote-signature verification.

.. list-table::
   :header-rows: 1
   :widths: 30 12 16 12 30

   * - Operation
     - ns/op
     - ops/sec/core
     - allocs/op
     - Notes
   * - RSASSA quote verify (``verify``)
     - 24 161
     - ~41 400
     - 11
     - per attestation
   * - RSAPSS quote verify (``verify``)
     - 24 368
     - ~41 000
     - 15
     - alt scheme
   * - ``server.VerifyToken`` (sdk)
     - 24 424
     - ~40 900
     - 29
     - verify + nonce + parse
   * - ``server.ParseToken`` (sdk)
     - 430
     - ~2 325 000
     - 17
     - untrusted parse only
   * - ``types.ParseReport``
     - 925
     - ~1 081 000
     - 1
     - wire report parse

**Reading it:** end-to-end token verification (``VerifyToken``) costs almost
exactly one RSA verify -- parsing and the nonce-binding check are noise next to
the public-key op. Optimisation effort belongs in the crypto path (batch
verification, or offloading), not the parser.

Enrollment / credential activation (attestca)
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 12 16 12 30

   * - Operation
     - ns/op
     - ops/sec/core
     - allocs/op
     - Notes
   * - ``GenerateChallenge`` (MakeCredential)
     - 29 358
     - ~34 100
     - 88
     - per enrollment Begin
   * - ``ValidateAIK``
     - 3 806
     - ~262 000
     - 45
     - AIK template parse

**Reading it:** ``GenerateChallenge`` is the RSA ``MakeCredential`` that the
per-source-IP Begin rate limit bounds (default 10/min/IP). One core sustains
~34 k MakeCredentials/sec, so the limiter exists to stop an unauthenticated
flood from monopolising that capacity, not because a single op is slow.

Store (verifier persistence)
----------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 12 16 12 30

   * - Operation
     - ns/op
     - ops/sec/core
     - allocs/op
     - Notes
   * - ``SQLiteAIKStore.GetAIK``
     - 6 791
     - ~147 000
     - 24
     - per-attestation AIK lookup

The AIK lookup (6.8 us) is ~3.5x cheaper than the RSA verify it precedes, so it
does not bound steady-state attestation throughput on this host.

Enrollment wire codec (attestca)
--------------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 14 22 14

   * - Operation
     - ns/op
     - throughput
     - allocs/op
   * - ``EncodeBegin``
     - 412
     - --
     - 3
   * - ``DecodeBegin``
     - 306
     - ~7.8 GB/s
     - 3
   * - ``EncodeResult``
     - 243
     - --
     - 4
   * - ``DecodeResult``
     - 147
     - ~4.9 GB/s
     - 4

SDK C hot paths (``cbench.h``)
------------------------------

median over auto-calibrated batches, ``BENCH_REPS=50``.

.. list-table::
   :header-rows: 1
   :widths: 28 14 12 18 28

   * - Operation
     - median ns
     - p99 ns
     - ops/sec
     - Notes
   * - game-binding hash (1 MiB exe)
     - 603 409
     - 636 024
     - 1 657
     - ~1.65 GiB/s SHA-256
   * - token serialize
     - 21.3
     - 21.8
     - ~46 900 000
     - client -> wire
   * - token parse
     - 11.7
     - 12.1
     - ~85 100 000
     - server, no signature check

**Reading it:** the game-binding hash cost is linear in executable size (it is
SHA-256 over the image); 1.65 GiB/s is the per-core SHA-256 rate.

Scaling note
============

Per-attestation verification (``VerifyToken`` / RSASSA verify) has no shared
state, so it scales linearly across cores: ~41 k/sec/core x 16 cores giving
about **~660 k attestations/sec** on this host, crypto-bound. Writes are the
tier that does not scale with cores, and which backend bounds them differs:
SQLite's single-writer model serialises every write in one file -- a property
of that backend, suited to single-node deployments -- while the Postgres
backend (``--pg-dsn``) commits independent clients concurrently under
per-client advisory locks and is bounded by the database host's WAL fsync
rate (measured below). The verifier itself holds no process-wide lock on the
attestation path; the store-concurrency contract that keeps it that way is
in the contributor documentation.

L2 fleet scale (synthetic, measured)
====================================

Measured with :doc:`lota-loadgen <load-testing>` on the L1 host (8c/16t
Ryzen 7 5700X, NVMe, Postgres 16 in a local container, TLS loopback),
10 000-agent rig, production verifier configuration (certificate chain,
strict policy):

.. list-table::
   :header-rows: 1
   :widths: 44 16 16 24

   * - Run
     - Rate
     - p99
     - Notes
   * - Storm, in-memory/file stores
     - 3 854/s
     - 62 ms
     - crypto tier; not the bottleneck
   * - Storm, Postgres, first attest
     - 350/s
     - 843 ms
     - registration commit per agent
   * - Storm, Postgres, re-attest
     - 1 124/s
     - 260 ms
     - WAL-fsync bound
   * - Steady 10k @ 60 s, Postgres
     - 166.6/s
     - 931 ms
     - 3 min; 29 998/29 998 verified, 0 timeouts

An 18-minute dual-instance soak (2 x 5 000 agents at 60 s, one shared
Postgres) held the same rate through a ``kill -9`` of one instance
(only its agents affected; recovered next interval; 20/20 of its
session tokens validated on the survivor) and a ~2 s Postgres restart
(fail-closed rejections inside the window only; all 10 000
registrations intact). Operator-facing conclusions from these runs are
in :doc:`the sizing guide <../operator/sizing>`.

L2 write-tier scaling (measured)
======================================

Three optimisations attack the per-database WAL-fsync ceiling above. All
were measured on the same L1 host.

* **Attestation-log batching.** The audit write, one of the per-report
  durable writes, is moved off the hot path and flushed in batches (one
  commit per flush). In isolation against real Postgres the audit write
  went from ~110-590 rows/s (one fsync per row, highly variable with host
  fsync latency) to ~18 000-66 000 rows/s batched (one fsync per ~256).
  Both ends move with the host's fsync latency, so the ratio between a
  given pair of runs spans ~30-600x; the structural change is the one
  that holds -- the audit trail costs one fsync per batch, not per row.
* **Connection-pool / enrollment scaling.** Baseline-insert (enrollment)
  throughput scales with the pool because Postgres group-commits
  concurrent transactions: ~496/s at pool 8, ~4 655/s at pool 20,
  ~15 145/s at pool 64 (~3.3x); pool 128 hit the container's default
  ``max_connections`` of 100. Enrollment is a pool/``max_connections``
  knob, not a fixed 350/s limit.
* **Sharding distribution and aggregate scaling.** Across four shard
  databases, 8 000 clients routed exactly 25.0 % per shard
  (2 000 each, deterministic, every client on its hash's shard, all
  persisted). Aggregate write throughput over the four shards ran only
  **1.1-2.4x** the single-shard rate on this single-NVMe host, because
  the shards share one fsync device.

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - Measurement
     - Result
     - Status
   * - Audit write, per-row vs batched
     - ~110-590/s -> ~18k-66k/s (one fsync per ~256 rows)
     - measured
   * - Enrollment vs pool (8 / 20 / 64)
     - ~496 / 4 655 / 15 145 inserts/s
     - measured
   * - Shard routing distribution (4 shards)
     - 25.0 % each, exact, deterministic
     - measured
   * - Shard aggregate write scaling (1 disk)
     - 1.1-2.4x at N=4 (ideal 4.0x)
     - measured, storage-bound
   * - Shard aggregate on independent storage
     - ~Nx
     - **extrapolated** (needs multi-host)

The linear-to-Nx shard scaling and the one-million-agent envelope
(16 shards + ~56 stateless instances) are honest arithmetic over these
measured building blocks; the aggregate on independent storage is not yet
measured (single-disk rig). A multi-host run will replace the 1.1-2.4x
figure. The 1M reasoning is in :doc:`the sizing guide <../operator/sizing>`.

L2 swtpm / L3 kernel (TBA)
==========================

* **L2 macro (swtpm):** ``--attest`` round-trip and enrollment ceremony
  wall-clock with ``hyperfine``. Includes the real TPM quote, IPC, and TLS --
  the latency a session actually sees.
* **L3 kernel (BPF LSM):** ``perf stat`` delta on ``execve`` / ``mmap`` with the
  LSM loaded vs unloaded -- microseconds and cycles added per gated syscall.
  Requires root and a loaded BPF object.
