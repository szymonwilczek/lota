.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===================
Verifier topologies
===================

Where the verifier keeps its state decides how many instances can run
(:doc:`../verifier/store`). This page lays out the topologies, what each
needs, and how they fail.

====================================== ======================================
Need                                   Topology
====================================== ======================================
A test host, no database               One instance, ``--state-db``
One verifier host                      One instance, ``--db``
Failover, more instances               Several instances, ``--pg-dsn``
More writes than one database takes    Several instances, ``--pg-shard-dsn``
Read load off the writers              ``--report-only`` beside any of these
====================================== ======================================

One instance
============

``--db``
  Every record in one SQLite file. The instance survives a restart with its
  baselines and clients.

``--state-db``
  The default when no backend is named. The nonce history, revocations,
  bans, audit log and decision log are in SQLite; the baselines are in
  memory. After a restart every client presents as new, and with no
  enrollment road its first round is refused (:doc:`../verifier/index`).

One instance has no failover. Its file is its state: back it up with the
SQLite tools, from the same host.

Several instances
=================

Every instance runs with ``--pg-dsn`` on one Postgres primary, behind a load
balancer that checks ``GET /health``:

.. code-block:: none

   hosts --> load balancer --> verifier --+
                           --> verifier --+--> Postgres primary
                           --> verifier --+

A client may reach any instance on any round:

* a baseline, a revocation or a ban written by one instance holds on all of
  them;
* a nonce used on one is refused as reused on all of them;
* ``GET /api/v1/clients`` lists the whole fleet on every instance;
* a host's passing rounds extend one decision-log row, whichever instance
  serves them: the writer locks the host in the database.

A challenge is held by the instance that sent it, and the report comes back
on the same TLS connection, so the balancer needs no affinity. The values an
instance keeps in memory are its own: ``lota_pending_challenges``, the
counters of ``/metrics`` and ``/api/v1/stats``, and ``monotonic_counter`` on a
client (:doc:`../verifier/monitoring-api`).

Give every instance the same build, policy files, ``--policy-pubkey``,
``--aik-ca-cert`` and ``--aik-crl``: the database holds none of them. A
database written by another build is refused at startup
(:doc:`protocol-versions`).

Database
--------

* Reach it over TLS, ``sslmode=verify-full`` in the DSN, with a role of its
  own. ``LOTA_PG_DSN`` keeps the DSN off the command line.
* An instance opens up to ``--pg-max-open-conns`` connections, default 20.
  ``max_connections`` must cover every instance's pool beside the other
  clients; Postgres ships 100. The verifier warns when its own pool exceeds
  ``max_connections`` or half of it, as the server it connects to reports
  it.
* Concurrent rounds commit together, so a wider pool takes a burst of first
  rounds faster, up to ``max_connections``.
* Instances that start together apply the migrations once, under a lock.
* Run the database with its own failover. An attesting instance needs the
  primary: it refuses a hot standby at startup with ``database is a
  read-only standby``.

Rolling out
-----------

On shutdown an instance closes its attestation listener first. With
``--shutdown-drain``, ``/health`` answers 503 ``degraded`` for that long
before the monitoring API stops, so the balancer stops routing to it
(:doc:`../verifier/command-line`).

Reporting instances
===================

``--report-only`` serves the monitoring API alone, from a database it never
writes, a hot standby or the primary:

.. code-block:: sh

   lota-verifier --report-only \
       --pg-dsn "postgres://lota@pg-replica.example/lota?sslmode=verify-full" \
       --http-addr 127.0.0.1:8081

* No attestation listener opens; ``--addr`` is not needed, and ``--cert``
  only for a monitoring API off loopback.
* The schema is checked, never applied. A database at an older version, or
  with no schema, is refused.
* Every admin route answers 503 before the key is read. Reader routes answer
  as on an attesting instance.
* ``/health`` answers 200 with ``mode`` ``reporting``.
* ``--policy`` is ignored, with a warning.

A standby lags the primary by its replication delay, and the reads show that
delay.

Shards
======

One Postgres primary takes the writes of every instance, and more instances
do not raise that ceiling (:doc:`sizing`). ``--pg-shard-dsn``, once per
database, spreads the clients over several:

.. code-block:: sh

   lota-verifier \
       --pg-shard-dsn "postgres://lota@pg-shard-0.example/lota?sslmode=verify-full" \
       --pg-shard-dsn "postgres://lota@pg-shard-1.example/lota?sslmode=verify-full" \
       --pg-shard-dsn "postgres://lota@pg-shard-2.example/lota?sslmode=verify-full"

``LOTA_PG_SHARD_DSNS`` takes the same list, comma-separated. A client's
baselines and nonce history live on the shard its client ID hashes to; the
revocations, bans, audit log and decision log live on the first shard
("Shards" in :doc:`../verifier/store`).

* Every instance names the same databases in the same order. The verifier
  pins the set on every shard and refuses to start on another list.
* Shards gain writes only on storage of their own. Shards on one disk share
  its flushes.
* Each shard carries its share of the clients and the pools of every
  instance; size its ``max_connections`` as for one database.
* A shard down refuses its clients' rounds with ``nonce_fail``, ``used-nonce
  history unavailable, refusing the round``, and the other shards' clients
  keep passing. The first shard down also stops revocation and ban checks,
  and every round is refused with ``internal_error``. Give each shard its own
  failover.
* The shard count is set for the fleet's life. A new count sends nearly
  every client to a shard without its baselines: every client presents as
  new, and its nonce history starts empty. Moving or re-enrolling the
  clients, then ``DELETE FROM shard_set`` on every shard, lets the next start
  pin the new set.

A single ``--pg-dsn`` is pinned as a set of one, so moving it to a shard list
takes the same steps.

The balancer in front needs no knowledge of the shards: every instance
routes each client alike.
