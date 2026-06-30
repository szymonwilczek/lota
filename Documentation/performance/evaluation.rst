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
about **~660 k attestations/sec** on this host, crypto-bound. The sqlite store
serialises writes, so registration (enrollment commit) does **not** scale the
same way -- it is gated by the DB write lock, not the CPU.

L2 / L3 (TBA)
=============

* **L2 macro (swtpm):** ``--attest`` round-trip and enrollment ceremony
  wall-clock with ``hyperfine``. Includes the real TPM quote, IPC, and TLS --
  the latency a session actually sees.
* **L3 kernel (BPF LSM):** ``perf stat`` delta on ``execve`` / ``mmap`` with the
  LSM loaded vs unloaded -- microseconds and cycles added per gated syscall.
  Requires root and a loaded BPF object.
