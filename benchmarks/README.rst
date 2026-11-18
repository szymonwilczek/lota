.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

================
Micro-benchmarks
================

The micro-benchmarks time the CPU-bound steps of verification, enrollment
and the SDK, one operation at a time. They need no TPM, no agent and no
root. The figures taken on the reference host are in
``Documentation/performance/evaluation.rst``.

Running
=======

.. code-block:: console

   $ make bench          # bench-c, then bench-go
   $ make bench-c        # the C SDK benchmarks
   $ make bench-go       # the Go benchmarks
   $ make bench-clean    # removes the results and build/bench_sdk

``bench-go`` runs ``go test -run '^$' -bench=. -benchmem`` in
``src/verifier``, ``sdk/server`` and ``src/attestca``, each benchmark
``BENCH_COUNT`` times (default 6) for ``BENCH_TIME`` (default ``1s``):

.. code-block:: console

   $ make bench-go BENCH_COUNT=10 BENCH_TIME=2s

The output goes to the terminal and to ``benchmarks/results/``:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - File
     - Contents
   * - ``go-src-verifier.txt``
     - ``go test`` output of ``src/verifier``
   * - ``go-sdk-server.txt``
     - ``go test`` output of ``sdk/server``
   * - ``go-src-attestca.txt``
     - ``go test`` output of ``src/attestca``
   * - ``c-sdk.txt``
     - the table ``build/bench_sdk`` prints
   * - ``c-sdk.json``
     - one JSON object per C benchmark

Each run replaces the files. A runner that exits non-zero leaves its file
behind, the target reports that the file is not a measurement, and
``make`` fails.

``benchmarks/scripts/run_all.sh`` prints the kernel, the CPU model and the
Go version, runs ``make bench-c`` and ``make bench-go`` with
``BENCH_COUNT`` of 10 unless set, and then runs ``benchstat`` over each Go
file when ``benchstat`` is installed.

Go benchmarks
=============

The benchmarks are ``testing.B`` functions next to the code they time:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Package
     - Benchmarks
   * - ``src/verifier/verify``
     - ``RSASSAVerify``, ``RSAPSSVerify``, ``RSASSAVerifyParallel``
   * - ``src/verifier/types``
     - ``ParseReport``
   * - ``sdk/server``
     - ``VerifyToken``, ``ParseToken``
   * - ``src/attestca/credential``
     - ``GenerateChallenge``, ``ValidateAIK``
   * - ``src/attestca/wire``
     - ``EncodeBegin``, ``DecodeBegin``, ``EncodeResult``, ``DecodeResult``

Each reports ``ns/op``, ``B/op`` and ``allocs/op``.
``RSASSAVerifyParallel`` runs the check on ``GOMAXPROCS`` goroutines, so
its ``-cpu`` list gives the scaling over cores.

``benchstat`` (``golang.org/x/perf/cmd/benchstat``) summarises the
samples of one file, and compares two files of the same benchmarks:

.. code-block:: console

   $ make bench-go
   $ cp benchmarks/results/go-src-verifier.txt old.txt
   ... change the tree ...
   $ make bench-go
   $ benchstat old.txt benchmarks/results/go-src-verifier.txt

C benchmarks
============

``build/bench_sdk`` (``benchmarks/c/bench_sdk.c``) times three SDK calls:

``game_binding_hash``
   ``lota_ac_compute_game_binding_hash()`` over a file of
   ``BENCH_EXE_KIB`` KiB (default 1024), written under ``/tmp`` at start
   and removed at exit. A size that does not fit in the free space of
   ``/tmp`` is refused, and the runner exits with 1.

``token_serialize``
   ``lota_token_serialize()`` of a token with a 120-byte quote and a
   256-byte signature.

``token_parse``
   ``lota_server_parse_token()`` of that token, which checks no signature.

Before the table it prints the file size and the token's wire size to
standard error, as ``suite=sdk exe_bytes=... token_wire=...``.

The harness, ``benchmarks/include/cbench.h``, needs only the header.
For each benchmark it doubles a batch of calls until one batch takes
``BENCH_TARGET_MS``, runs ``BENCH_WARMUP`` batches it discards, then times
``BENCH_REPS`` batches with ``CLOCK_MONOTONIC_RAW``. A sample is the
batch's time over its size. It prints the median, the 99th percentile,
the minimum and the standard deviation of the samples in nanoseconds, and
the calls per second at the median.

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Variable
     - Default
     - Meaning
   * - ``BENCH_REPS``
     - 50
     - samples per benchmark
   * - ``BENCH_WARMUP``
     - 5
     - batches run and discarded
   * - ``BENCH_TARGET_MS``
     - 5
     - the time of one batch, in milliseconds
   * - ``BENCH_JSON``
     - unset
     - a file to append one JSON object per benchmark to
   * - ``BENCH_EXE_KIB``
     - 1024
     - the size of the hashed file, in KiB

For the four numeric variables, a value that does not start with a digit,
has characters after the number, or is zero leaves the default. When the
samples of a benchmark cannot be allocated, the harness prints ``cbench:
OOM`` and skips it, and the runner exits with 1.
``make bench-c`` removes ``c-sdk.json`` and sets ``BENCH_JSON`` to it. An
object carries ``suite``, ``name``, ``median_ns``, ``p99_ns``, ``min_ns``,
``stddev_ns``, ``ops_per_sec``, ``samples`` and ``batch``.

.. code-block:: console

   $ BENCH_REPS=100 BENCH_TARGET_MS=10 make bench-c
   $ BENCH_EXE_KIB=8192 build/bench_sdk

In CI
=====

The ``benchmarks`` job of ``.github/workflows/ci.yml`` runs ``make
bench-c`` with ``BENCH_REPS=3``, ``BENCH_TARGET_MS=1`` and
``BENCH_EXE_KIB=64``, and ``make bench-go BENCH_COUNT=1 BENCH_TIME=1x``. It
fails when a benchmark does not build or its runner exits non-zero. The
runners are shared, so their timings are not figures.

Taking figures
==============

The figures in ``evaluation.rst`` carry the host, the date and the commit
they were taken at. To take them again:

* set the ``performance`` governor, for instance with ``cpupower
  frequency-set -g performance``;
* leave the host idle during the run;
* run ``make bench-c`` and ``make bench-go`` at a clean tree, and record
  the commit with the figures.
