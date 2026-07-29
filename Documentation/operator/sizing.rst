.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
Sizing guide
============

How many agents one verifier carries, how many verifiers one Postgres
serves, and what an enrollment burst costs. Every number here was
measured with the synthetic fleet harness (:doc:`load testing
<../performance/load-testing>`) on the reference rig below; use the
formulas to scale to your fleet and re-run the harness on your own
hardware before committing to an envelope. The raw runs live in
:doc:`the performance evaluation <../performance/evaluation>`.

Reference rig
=============

All numbers: 8-core/16-thread desktop CPU (Ryzen 7 5700X), single NVMe
disk, Postgres 16 in a local container, TLS over loopback, verifier and
database on the same host. A production deployment with a network hop
between agents, verifiers and Postgres adds latency per attestation but
does not change the throughput ceilings, which are CPU- and
WAL-fsync-bound.

The three ceilings
==================

A verifier deployment saturates at one of three points, in this order:

.. list-table::
   :header-rows: 1
   :widths: 26 18 56

   * - Ceiling
     - Measured
     - What it bounds
   * - Verification crypto
     - ~3 850/s per instance
     - RSA/SHA-256 report verification with in-memory stores; scales
       with cores. Not the practical limit -- the database is.
   * - Postgres durable writes
     - ~1 100 verified reports/s
     - Each verified report commits several WAL-flushed writes
       (attestation log, used nonce, baseline counters, session
       token). This is a property of the Postgres host's fsync rate,
       shared by every verifier instance on that database.
   * - Registration (first attest)
     - ~350/s per instance
     - A client's first attestation additionally inserts its AIK
       registration and TOFU baseline. Only the first round of a new
       fleet pays this, and it is pool- and shard-tunable rather than
       fixed (see Enrollment bursts).

Steady-state attestation demand is ``fleet size / attestation
interval``. A 10 000-agent fleet at a 60 s interval is ~167 reports/s
-- about 15 % of the measured Postgres ceiling.

Agents per verifier
===================

**Measured:** 10 000 agents at a 60 s interval on one verifier instance
against Postgres, over a 3-minute run (three full rounds): every round
verified (29 998/29 998), p50 52 ms, p99 931 ms, zero timeouts. The
same instance has ~6.7x headroom to the warm-storm ceiling (1 124/s,
p99 260 ms). The longest run to date is the 18-minute dual-instance
soak below; treat anything past that as extrapolation and soak it on
your own hardware.

Rules of thumb, per verifier instance:

* **Size the connection cap:** the attestation listener refuses
  connections past ``--max-connections`` (default 256), so a stampede
  cannot spend unbounded TLS handshakes and verifications. A healthy
  steady fleet stays well under it -- in-flight work is roughly rate x
  latency, so the 10 000-agent run above peaks near 150 -- but a
  registration storm or a retry stampede reaches it, and refused agents
  retry on their next interval rather than failing for good. Raise it
  only after measuring; the harness's ``-in-flight`` models the client
  side of the same bound.
* Keep steady demand under **~300 reports/s per instance** if you want
  the measured sub-second p99; the instance ceiling is higher but p99
  grows with WAL contention well before throughput collapses.
* Longer intervals scale linearly: at 5 min, one instance's 300/s
  budget carries a 90 000-agent fleet's steady state -- Postgres, not
  the verifier, is then the tier to watch.

Verifiers per Postgres
======================

Verifier instances are stateless against ``--pg-dsn``; add instances
for availability and connection fan-out, not for write throughput --
the WAL ceiling (~1 100 verified reports/s on the reference rig)
belongs to the database host and is shared by all instances. Two
instances splitting a 10 000-agent fleet were soaked for 18 minutes
with mid-load failovers (below); the topology and health checks are in
:doc:`ha-deployment`.

Each instance opens up to ``--pg-max-open-conns`` connections per
database (default 20), so ``N instances x pool`` must fit the server's
``max_connections`` alongside anything else using it -- and every shard
that shares a server counts. Widening the pool lifts enrollment bursts
(see below); raise ``max_connections`` with it.

To raise a *single* database's write ceiling, tune the database, not the
verifier count: faster fsync (NVMe, battery-backed cache),
``commit_delay`` group commit, a wider connection pool
(``--pg-max-open-conns``, see below), or a dedicated Postgres host.
Relaxing ``synchronous_commit`` is an operator decision, not a default:
it puts the most recently committed verifier state at risk on a database
crash -- not only attestation-log entries, but the used-nonce history and
the baseline pins written in the same window. To scale *past* one
database, shard (next section).

Two optimisations change the per-report write cost above:

* **The attestation-log write is batched off the hot path** (async,
  one commit per flush instead of one per report), so the audit log is
  no longer one of the per-report WAL fsyncs. Measured in isolation on
  the reference rig, the audit write went from ~110-590 rows/s
  (one fsync per row) to tens of thousands of rows/s batched (one fsync
  per ~256). It becomes eventually consistent within one flush interval
  (~1 s); a crash loses at most that window of *audit* records, never a
  verdict or session.
* **The connection pool is tunable** (``--pg-max-open-conns``), which
  chiefly lifts enrollment bursts (see below).

Scaling past one database (sharding)
====================================

One database's WAL fsync rate is a hard per-host ceiling that adding
verifier instances cannot raise. To go beyond it, partition the
per-client write state (baseline, nonce, session) across N independent
databases with ``--pg-shard-dsn`` (:doc:`ha-deployment`). Each client's
writes are routed to one shard by a stable, process-independent hash, so
every instance agrees on the mapping and no operation ever spans two
shards.

Measured on the reference rig with **four shard databases**:

* **Routing distributes exactly evenly.** 8 000 clients landed
  2 000 / 2 000 / 2 000 / 2 000 (25.0 % each), deterministic across
  runs, every client on the shard its hash selects, all persisted.
* **Aggregate write throughput is bounded by shared storage.** On this
  single-NVMe rig the four shard databases contend on one fsync device,
  so aggregate baseline-insert throughput ran only 1.1-2.4x the
  single-shard rate (ideal 4.0x), highly variable with host fsync
  latency.

**Linear scaling to Nx requires independent storage per shard** --
separate database hosts or volumes -- which a one-disk rig cannot
demonstrate. That the shards are independent (no cross-shard
transaction, no shared lock) is a property of the design, not of the
measurement; the aggregate multiplier on real independent storage is
therefore an **extrapolation** pending a multi-host run.

.. note::

   Multi-host aggregate measurement — PLACEHOLDER. A run across
   *(lab: N separate machines, independent storage)* will replace the
   single-disk 1.1-2.4x figure with the real per-shard-host scaling
   curve. Until then the Nx claim below is arithmetic over measured
   building blocks, not a measured aggregate.

Toward one million agents
=========================

The target the product markets (large enterprise fleets and
game-launch populations) is well past 10 000. The path is fan-out on
both tiers, and it is arithmetic over the measured building blocks --
labelled here **measured** or **extrapolated** so nothing reads as a
demonstrated aggregate it is not.

* **Demand.** 1 000 000 agents at a 60 s interval is ~16 700 verified
  reports/s steady (``fleet / interval``).
* **Verifier tier (measured to fan out).** Instances are stateless; the
  soak proved two instances serving one fleet with failover and a
  shared session store. At the ~300 reports/s-per-instance sub-second-p99
  rule, ~16 700/s needs **~56 instances**. Adding instances is cheap and
  proven; this tier is not the wall.
* **Database tier (measured per-shard; aggregate extrapolated).** One
  database holds ~1 100 verified reports/s, i.e. ~66 000 agents at 60 s.
  ~16 700/s therefore needs **16 shard databases** on independent
  storage. Routing across shards is measured (exact, even, no
  cross-shard coupling); the linear aggregate is extrapolated until the
  multi-host run above.
* **Enrollment (measured to shard).** A 1 000 000-agent first-boot storm
  is bounded by the per-shard enrollment rate times the shard count and
  the pool (see below), not by a fixed figure.

So the architecture scales to one million by fan-out: ~56 stateless
instances in front of 16 independent shard databases. The building
blocks are measured; the headline aggregate is honest arithmetic
awaiting the multi-host measurement.

Enrollment bursts
=================

A cold fleet's first round is a registration burst -- a fresh baseline
INSERT per client. Its throughput is a **pool/``max_connections``
tuning knob, not a fixed limit**, because Postgres group-commits
concurrent transactions: on the reference rig the enrollment
(baseline-insert) ceiling scaled with ``--pg-max-open-conns`` as
~496/s at pool 8, ~4 655/s at pool 20 (the default), and
~15 145/s at pool 64 (~3.3x); a pool of 128 exceeded the container's
default ``max_connections`` of 100. Enrollment INSERTs also shard by
client ID, so the burst rate multiplies with shard count.

Bring a new fleet up by raising ``--pg-max-open-conns`` (and
``max_connections`` with it, keeping ``instances x pool`` under the
server budget), by letting the natural spread of a steady interval
absorb it, or by capping concurrent enrollments at the deployer (the
harness's ``-in-flight`` models this) so the burst does not crowd out
already-registered fleets on the shared database.

Failover behaviour under load
=============================

Measured in an 18-minute dual-instance soak (2 x 5 000 agents at 60 s,
one shared Postgres), with the fleet holding rate throughout:

* **Verifier instance killed (kill -9):** only that instance's agents
  are affected; they see connection errors until the instance returns
  and recover on their next interval unaided. The surviving instance
  served its fleet with zero errors. Session tokens issued by the dead
  instance kept validating on the survivor (20/20 replayed) -- the
  session store is shared.
* **Postgres restart (~2 s):** both instances reject the handful of
  attestations in flight during the outage window (fail-closed, no
  unverifiable report is accepted) and recover immediately with it;
  zero rejections or errors outside the window. Agents self-recover on
  the next interval; no registrations were lost (10 000/10 000 baseline
  rows after the drill, every agent attesting).

Size the fleet's attestation interval as the recovery unit: after any
single failure, the affected agents are green again within one
interval.

Checklist
=========

#. Compute steady demand: ``agents / interval seconds``.
#. Keep it under ~300/s per verifier instance and ~1 100/s per
   Postgres host (reference-rig numbers -- re-measure with
   ``lota-loadgen`` on your hardware).
#. Add one instance beyond capacity for failover; instances are
   stateless, the load balancer's health check is ``GET /health``.
#. Check the database's ``max_connections`` (not the listener's
   ``--max-connections``) covers ``instances x pool``
   (``--pg-max-open-conns``, default 20).
#. Plan new-fleet bring-up as an enrollment burst: raise the pool (and
   ``max_connections``) for it, or spread it over an interval.
#. Past one database's write ceiling, shard with ``--pg-shard-dsn``
   across independent storage; size 16 shards per million agents at a
   60 s interval and ~56 stateless instances (see Toward one million
   agents).
