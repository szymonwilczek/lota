.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

LOTA benchmarks
===============

Performance measurement for the whole tree, organised in three layers by what
each needs to run. Numbers feed ``Documentation/performance/evaluation.rst`` and locate the hot paths worth
optimising.

Layers
------

+---------------+--------------------------------+-------------------+-------------------+
| Layer         | What it measures               | Tooling           | Needs             |
+===============+================================+===================+===================+
| **L1 micro**  | pure-CPU hot paths: crypto     | Go ``testing.B``  | nothing special;  |
|               | verify, parse/serialize, hash, | + ``benchstat``;  | runs in CI        |
|               | codec, DB lookup,              | header-only C     |                   |
|               | MakeCredential                 | harness           |                   |
|               |                                | (``cbench.h``)    |                   |
+---------------+--------------------------------+-------------------+-------------------+
| **L2 macro**  | end-to-end CLI wall-clock:     | ``hyperfine``     | ``swtpm``, the    |
|               | ``--attest``, enrollment       | over the swtpm    | demo sandbox      |
|               | ceremony, verifier round-trip  | sandbox           |                   |
+---------------+--------------------------------+-------------------+-------------------+
| **L3 kernel** | BPF LSM hook overhead on       | ``perf stat``,    | root, loaded BPF, |
|               | ``execve``/``mmap``/``ptrace`` | with vs without   | ``perf``          |
|               |                                | the LSM loaded    |                   |
+---------------+--------------------------------+-------------------+-------------------+

L1 is the default ``make bench``. L2/L3 are operator runbooks below; they are
not wired into ``make`` because they need a TPM sandbox or root and are not
reproducible in GitHub Actions.

L1 - micro-benchmarks (default)
-------------------------------

.. code:: sh

   make bench                     # C + Go
   make bench-go                  # Go only (verifier, sdk/server, attestca)
   make bench-c                   # C SDK only
   BENCH_COUNT=10 make bench-go   # more samples for benchstat
   benchmarks/scripts/run_all.sh  # both + benchstat summary + host info

The ``benchmarks`` job in ``.github/workflows/ci.yml`` runs both runners on
every push/PR as a **correctness gate** (``make bench-c`` with tiny reps,
``make bench-go BENCH_TIME=1x``): it proves every benchmark compiles and runs
without crashing. Shared CI runners are too noisy for real timings, so quotable
numbers come from a pinned host into ``Documentation/performance/evaluation.rst``.

Raw output is archived under ``benchmarks/results/``:

- ``go-src-*.txt`` - ``go test -bench`` output, one file per module (benchstat
  input).
- ``c-sdk.txt`` / ``c-sdk.json`` - C harness, human and machine-readable.

Go benchmarks
~~~~~~~~~~~~~

Standard ``testing.B``, co-located with each package, discovered by
``go test -bench=. ./...``. Reported as ``ns/op``, ``B/op``, ``allocs/op``. Use
```benchstat`` <https://pkg.go.dev/golang.org/x/perf/cmd/benchstat>`__ for mean
+- variation and A/B comparison between two runs:

.. code:: sh

   go install golang.org/x/perf/cmd/benchstat@latest
   benchstat benchmarks/results/go-src-verifier.txt
   # compare a change:
   git stash; make bench-go; mv benchmarks/results/go-src-verifier.txt old.txt
   git stash pop; make bench-go
   benchstat old.txt benchmarks/results/go-src-verifier.txt

Covered: verifier ``verify`` (RSASSA/RSAPSS quote verify), ``types`` (report
parse), ``store`` (sqlite AIK lookup); ``sdk/server`` (VerifyToken,
ParseToken); ``attestca`` ``credential`` (GenerateChallenge = MakeCredential,
ValidateAIK) and ``wire`` (codec).

.. _c-harness-cbenchh:

C harness (``cbench.h``)
~~~~~~~~~~~~~~~~~~~~~~~~

Header-only. Auto-calibrates a batch size so each sample lasts
``BENCH_TARGET_MS`` (amortising ``clock_gettime`` overhead), then collects
``BENCH_REPS`` samples and reports median / p99 / min / stddev / ops-per-sec.
``CLOCK_MONOTONIC_RAW`` is used so NTP slewing cannot perturb a sample.

.. code:: sh

   BENCH_REPS=100 BENCH_TARGET_MS=10 make bench-c   # tighter distribution
   BENCH_EXE_KIB=8192 build/bench_sdk               # hash an 8 MiB image
   BENCH_JSON=/tmp/c.json build/bench_sdk           # append machine-readable rows

Covered: game-binding hash (SHA-256 over the executable image), token
serialize, token parse.

.. _l2---macro--end-to-end-swtpm:

L2 - macro / end-to-end (swtpm)
-------------------------------

Wall-clock of the real binaries against the demo's isolated swtpm sandbox.
Bring the sandbox up first (``examples/demo/setup.sh --keep-tmp``), then:

.. code:: sh

   sudo dnf install hyperfine

   # Attestation round-trip latency (agent <-> verifier), warmed up:
   hyperfine --warmup 3 --runs 50 \
     'lota-agent --attest --verifier 127.0.0.1:9443 --ca-cert <ca.crt>'

   # Enrollment ceremony (EK verify + MakeCredential + ActivateCredential):
   hyperfine --warmup 2 --runs 30 \
     'lota-agent --enroll --ca-server 127.0.0.1 --ca-port 8444 --ca-cert <tls.crt>'

Report p50/p95 wall-clock. These include IPC, the TPM quote, and TLS, so they
are the numbers a deploying studio actually feels per session.

.. _l3---kernel--bpf-lsm-overhead-root:

L3 - kernel / BPF LSM overhead (root)
-------------------------------------

The cost the LSM adds to the syscalls it gates. Measure a tight workload with
the agent's BPF programs loaded vs unloaded:

.. code:: sh

   # exec hook (bprm_creds_for_exec): many execve of /bin/true
   perf stat -r 20 -- sh -c 'for i in $(seq 1 2000); do /bin/true; done'

   # mmap/mprotect W^X gate: a microbench doing N mmap+mprotect cycles
   perf stat -r 20 -- ./mmap_churn 100000

Run each twice - once with ``lota-agent --mode enforce`` active, once with the
LSM unloaded - and report the per-operation delta (microseconds/op).

Methodology notes
-----------------

- Pin the governor to ``performance`` and disable turbo for stable numbers:
  ``sudo cpupower frequency-set -g performance``.
- Quiesce the box (no browser, no compiles) during a run.
- L1 is single-threaded per benchmark; throughput figures are per-core.
  Multiply by core count only after confirming the path has no shared lock (the
  verifier's per-attestation crypto is independent; the sqlite store serialises
  writes).
- Commit a refreshed ``Documentation/performance/evaluation.rst`` whenever a hot path changes materially.
