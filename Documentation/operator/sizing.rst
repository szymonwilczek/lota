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
       fleet pays this.

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

Each instance opens at most 20 Postgres connections, so ``N instances
x 20`` must fit the server's ``max_connections`` alongside anything
else using the database.

To raise the write ceiling, tune the database, not the verifier count:
faster fsync (NVMe, battery-backed cache), ``commit_delay`` group
commit, or a dedicated Postgres host. Relaxing ``synchronous_commit``
is an operator decision, not a default: it puts the most recently
committed verifier state at risk on a database crash -- not only
attestation-log entries, but the used-nonce history and the baseline
pins written in the same window.

Enrollment bursts
=================

A cold fleet's first round is a registration burst: ~350
registrations/s per instance (measured with a 128-connection storm; a
10 000-agent fleet fully registers in ~30 s). Bring a new fleet up
either behind the natural spread of a steady interval, or cap the
concurrent enrollments at the deployer (the harness's ``-in-flight``
models this) so the burst does not crowd out already-registered
fleets' steady traffic on the shared database.

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
   ``--max-connections``) covers ``instances x 20``.
#. Plan new-fleet bring-up as a registration burst (~350/s per
   instance) or spread it over an interval.
