.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======================
Performance evaluation
======================

The figures below come from one reference host. Absolute values follow the
CPU; take them again on the hardware that will run the verifier before
planning capacity on them (:doc:`../admin-guide/sizing`).

Reference host
==============

.. list-table::
   :widths: 25 75

   * - CPU
     - AMD Ryzen 7 5700X, 8 cores, 16 threads
   * - Kernel
     - Linux 7.1, ``performance`` governor
   * - Toolchain
     - Go 1.26, GCC 16, the tree's ``CFLAGS`` (``-O2`` and hardening)
   * - Storage
     - one NVMe disk

Micro-benchmarks
================

Taken on 2026-11-18 at commit ``0fa8bef502`` with:

.. code-block:: console

   $ make bench-c
   $ make bench-go

``bench-go`` runs each benchmark six times for one second
(:ghsrc:`benchmarks/README.rst`). A figure is the median of the six. In
that run, the fastest and slowest of the six differ by at most 3.2 % of the
median, 9 % for ``ParseReport`` and 12 % for ``DecodeBegin``. Each
benchmark runs one operation at a time, so a rate is what one core
sustains.

Verification
------------

.. list-table::
   :header-rows: 1
   :widths: 40 15 20 12

   * - Operation
     - ns/op
     - ops/s
     - allocs/op
   * - RSASSA quote signature (``verify``)
     - 24 686
     - about 40 500
     - 11
   * - RSAPSS quote signature (``verify``)
     - 25 288
     - about 39 500
     - 15
   * - ``server.VerifyToken``
     - 25 013
     - about 40 000
     - 29
   * - ``server.ParseToken``
     - 427
     - about 2 340 000
     - 17
   * - ``types.ParseReport``
     - 512
     - about 1 950 000
     - 2

``VerifyToken`` checks the token's RSASSA signature, its nonce binding and
its fields (:ghsrc:`sdk/server/bench_test.go`), and costs about what the
signature check alone costs. The parsers cost about a fiftieth of it.

Enrollment
----------

.. list-table::
   :header-rows: 1
   :widths: 40 15 20 12

   * - Operation
     - ns/op
     - ops/s
     - allocs/op
   * - ``credential.GenerateChallenge``
     - 30 547
     - about 32 700
     - 88
   * - ``credential.ValidateAIK``
     - 3 873
     - about 258 000
     - 46
   * - ``wire.EncodeBegin``
     - 408
     - about 2 450 000
     - 3
   * - ``wire.DecodeBegin``
     - 326
     - about 3 070 000
     - 3
   * - ``wire.EncodeResult``
     - 248
     - about 4 040 000
     - 4
   * - ``wire.DecodeResult``
     - 147
     - about 6 820 000
     - 4

``GenerateChallenge`` is the RSA ``MakeCredential`` of an enrollment's
first request. The attestation CA takes at most 10 such requests a minute
from one source address by default
(:ghsrc:`src/attestca/server/server.go`), far below what one core computes.

SDK
---

``bench_sdk`` with ``BENCH_REPS=50`` and a 1 MiB executable:

.. list-table::
   :header-rows: 1
   :widths: 40 15 15 20

   * - Operation
     - median ns
     - p99 ns
     - ops/s
   * - game binding hash
     - 604 458
     - 639 818
     - 1 654
   * - token serialize
     - 17.8
     - 18.0
     - about 56 100 000
   * - token parse, no signature check
     - 12.5
     - 12.8
     - about 80 100 000

The game binding hash reads the executable and hashes it with SHA-256
(:ghsrc:`src/sdk/lota_anticheat.c`), so its cost grows with the file:
about 1.6 GiB a second here.

Cores
=====

``BenchmarkRSASSAVerifyParallel`` runs the RSASSA check over ``GOMAXPROCS``
goroutines. Taken on the same day and commit, in ``src/verifier``:

.. code-block:: console

   $ go test -run '^$' -bench=RSASSAVerifyParallel -cpu=1,4,8,16 \
         -count=6 ./verify/

.. list-table::
   :header-rows: 1
   :widths: 15 20 25 20

   * - ``-cpu``
     - ns/op
     - checks/s
     - against one
   * - 1
     - 24 221
     - about 41 300
     - 1.0x
   * - 4
     - 6 209
     - about 161 000
     - 3.9x
   * - 8
     - 3 370
     - about 297 000
     - 7.2x
   * - 16
     - 3 434
     - about 291 000
     - 7.1x

In that run, the fastest and slowest of a row differ by at most 4.6 % of
its median.
The rate stops at the eight physical cores: the second thread of a core adds
nothing to the signature check.

Fleet runs
==========

``lota-loadgen`` (:doc:`load-testing`) drove a 10 000-agent rig against one
verifier with a certificate chain and a strict policy, over TLS on
loopback. Postgres 16 ran in a local container; the generator, the
verifier and the database shared the host. These runs were taken on
2026-07-19 at commit ``4293e9cc20``. A rate counts the rounds the verifier
passed, in runs where every agent passed.

.. list-table::
   :header-rows: 1
   :widths: 42 16 14 28

   * - Run
     - Rate
     - p99
     - Notes
   * - storm, in-memory and file stores
     - 3 854/s
     - 62 ms
     - the report checks
   * - storm, Postgres, first round
     - 350/s
     - 843 ms
     - a baseline insert per agent
   * - storm, Postgres, re-attest
     - 1 124/s
     - 260 ms
     - the database's commits
   * - steady, Postgres, 60 s interval
     - 166.6/s
     - 931 ms
     - 3 minutes, 29 998 of 29 998 passed, no timeout

The generator spends more CPU building the reports than the verifier spends
checking them, so these rates are a floor under the verifier.

Two instances on one Postgres, 5 000 agents each at 60 seconds, held the
same rate for 18 minutes. ``kill -9`` of one instance affected its own
agents only, which passed on their next interval, and the other instance
accepted 20 of 20 session tokens the stopped one had issued. A Postgres
restart of about 2 seconds refused rounds inside that window only, and all
10 000 registrations were intact after it.

Database
========

Taken on 2026-07-29 at commit ``40bb6ee1d5``, on the same host and
container.

First rounds insert a baseline each, and Postgres commits concurrent
inserts together, so their rate follows the pool
(``--pg-max-open-conns``):

====== =================
Pool   Baseline inserts
====== =================
8      about 496/s
20     about 4 655/s
64     about 15 145/s
====== =================

A pool of 128 passed the container's ``max_connections`` of 100.

Over four shard databases (``--pg-shard-dsn``), 8 000 clients landed 2 000
on each. The four shards shared one disk and took 1.1 to 2.4 times the
rounds of one; shards on separate storage are not measured.
