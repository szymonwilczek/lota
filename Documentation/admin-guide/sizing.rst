.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

======
Sizing
======

How many hosts one verifier instance carries, how many instances one Postgres
database serves, and what a first-boot burst costs. The figures were measured
with ``lota-loadgen`` (:doc:`../performance/load-testing`) on one reference
host, and the runs are in :doc:`../performance/evaluation`. Run the harness on
your own hardware before fixing a figure.

The reference host is an 8-core, 16-thread desktop CPU with one NVMe disk,
Postgres 16 in a local container, TLS over loopback, and the load generator,
the verifier and the database on the same host. The generator spends more CPU
building reports than the verifier spends checking them, so the rates are a
floor under the verifier.

Demand
======

A host reports every ``attest_interval`` seconds, 30 to 240; a host with
publisher profiles and no interval set reports every 240
(:doc:`../agent/configuration`). The steady load is::

   reports per second = hosts / interval

10 000 hosts at 60 seconds send about 167 reports a second; 1 000 000 hosts at
240 seconds, about 4 200.

Ceilings
========

.. list-table::
   :header-rows: 1
   :widths: 28 22 50

   * - Ceiling
     - Reference host
     - Bound by
   * - Report checks, no database
     - about 3 850/s per instance
     - CPU: the signature and hash checks. It grows with cores.
   * - Rounds on Postgres
     - about 1 100/s per database
     - The database's durable commits, shared by every instance on it.
   * - First rounds on Postgres
     - about 350/s per instance
     - The baseline insert of a client's first round. It grows with the
       pool and the shards (`First-boot bursts`_).

A passing round on Postgres writes the used nonce and the baseline's
``last_seen`` and count before its verdict is sent. The decision log is written
after, in batches of up to 256 rounds a commit ("Decision log" in
:doc:`../verifier/store`), and a host's passing rounds within
``--attestation-log-window``, default one hour, extend one row. The table
grows with the refusals and the changes, and its retention is the operator's.

Instances
=========

One instance on Postgres carried 10 000 hosts at 60 seconds over three
rounds: every report verified, 931 ms at the 99th percentile, no timeout.

* One instance on Postgres carried the re-attest storm of
  :doc:`../performance/evaluation` at about 1 100 rounds a second, 260 ms at
  the 99th percentile, at the database's ceiling. What one instance carries
  past it, on a faster database, is not measured.
* ``--max-connections``, default 256, caps the attestation connections an
  instance holds at once and closes the rest at accept. Steady load holds
  the rate times the mean latency; a first-boot burst or a
  wave of retries reaches the cap, and the hosts refused try again on their
  next interval.
* Add one instance past the load for failover. Instances add availability
  and CPU, and leave the database's ceiling where it is.

Database
========

An instance opens up to ``--pg-max-open-conns`` connections per database,
default 20, and every instance's pool draws on ``max_connections``, with
every shard on the same server counted ("Connection pool" in
:doc:`../verifier/store`).

A database takes more rounds with faster flushes (NVMe, a battery-backed
write cache), ``commit_delay``, a wider pool, or a host of its own. A
relaxed ``synchronous_commit`` puts the last commits at risk on a database
crash, the used nonces and the baselines among them, and is the operator's
choice. Past one database, shard (`Shards`_).

First-boot bursts
=================

A fleet's first round inserts a baseline per client. Postgres commits
concurrent inserts together, so the rate follows the pool. On the reference
host:

====== =================
Pool   Baseline inserts
====== =================
8      about 500/s
20     about 4 650/s
64     about 15 150/s
====== =================

A pool of 128 passed the container's ``max_connections`` of 100. The inserts
spread over the shards too.

A burst on a database that also serves a running fleet competes with it.
Raise the pool and ``max_connections`` for the burst, spread the first boots
over an interval, or cap the concurrent enrollments upstream; ``-in-flight``
in ``lota-loadgen`` models that cap.

Shards
======

``--pg-shard-dsn`` spreads the clients over databases by client ID
(:doc:`ha-deployment`). On the reference host, 8 000 clients over four shards
landed 2 000 on each. The four shards shared one disk, and together took 1.1
to 2.4 times the rounds of one: shards on one disk share its flushes.

No round spans two shards and no lock is shared between them, so shards on
storage of their own add their ceilings. That sum is arithmetic; it is not
measured on separate hosts.

Failover
========

Two instances on one database, 5 000 hosts each at 60 seconds, ran for 18
minutes:

* One instance killed with ``kill -9``: its hosts failed to connect until it
  returned, and passed on their next interval. The other instance served its
  hosts without an error.
* Postgres restarted, about 2 seconds: both instances refused the rounds in
  flight and passed the next ones. All 10 000 baselines were intact.

After one failure, the hosts it touched pass again within one interval.

A large fleet
=============

For 1 000 000 hosts, from the ceilings above:

============================ ============== ==============
Interval                     240 s          60 s
============================ ============== ==============
Reports per second           about 4 200    about 16 700
Instances at 1 100/s         4, plus one    16, plus one
Shards at 1 100/s            4              16
============================ ============== ==============

The shard count assumes each shard on storage of its own. Fix it before the
fleet enrolls: a new count moves nearly every client to a shard without its
baseline ("Shards" in :doc:`ha-deployment`).

Checklist
=========

#. Steady load: hosts divided by the interval in seconds.
#. Instances: the load over the measured rate of one, plus one.
#. Databases: the load over the measured rate of one, on storage of its own.
#. ``max_connections`` on each server: every instance's
   ``--pg-max-open-conns``, times the shards on that server, plus the other
   clients.
#. First boot: a wider pool for the burst, or the boots spread over an
   interval.
#. Measure on your own hardware with ``lota-loadgen``.
