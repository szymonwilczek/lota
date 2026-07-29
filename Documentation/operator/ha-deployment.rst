.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============================
Verifier deployment topologies
==============================

The LOTA verifier persists two kinds of state: durable identity and enforcement
records (AIK registrations, per-client baselines, revocations, hardware bans,
the audit and attestation logs, used nonces) and short-lived session tokens
issued after a successful attestation. Where that state lives decides how many
verifier instances a deployment can run.

This document describes the supported topologies and the shared-state
requirement of each. It is written for operators standing up a verifier tier
and for contributors changing the store layer.

Single node (default)
=====================

One verifier process owns its state. Two equivalent storage layouts exist:

* **File + SQLite (production default).** The certificate-backed AIK store lives
  under ``--aik-store``; used nonces persist to a SQLite database
  (``--nonce-db``); revocation, ban, audit and attestation state are in-memory.
  This is what a ``--require-cert`` deployment runs today without ``--db`` or
  ``--pg-dsn``.
* **SQLite** (``--db``). All of the above persist to one SQLite file. This path
  does not verify AIK certificate chains (``--require-cert`` is refused), so it
  suits TOFU-only test fleets, not production.

Single node is the simplest topology and needs no external database. Its
ceiling is one process: there is no failover, and the in-memory enforcement
state of the production default is lost on restart.

N instances behind a load balancer (Postgres)
=============================================

Several stateless verifier instances point at one shared Postgres database,
selected with ``--pg-dsn`` (or ``LOTA_PG_DSN``, which keeps the connection
string out of the process argument list). A load balancer fans attestation and
validation traffic across them; the ``GET /health`` endpoint is the health
check.

::

    client --> load balancer --> verifier (1) --|
                             --> verifier (1) --|-->  Postgres (2)
                             --> verifier (1) --|

    (1) - stateless, identical config
    (2) - shared enforcement + session-token state

With ``--pg-dsn`` the shared database holds the baseline, used-nonce,
revocation, ban, audit, attestation and session-token state. The consequences:

* A baseline pinned, a client revoked, or hardware banned on one instance is
  enforced by every instance. The per-client baseline pin is committed under a
  transaction-scoped advisory lock, so the firmware/agent_hash TOFU contract
  holds across instances exactly as it does within one SQLite process.
* A used nonce recorded on one instance is rejected as replayed on all
  instances.
* A session token issued by one instance validates on every instance, and a
  single-use token (``consume=true``) is consumed exactly once across the fleet.

Unlike the SQLite ``--db`` path, the Postgres path supports the
certificate-backed AIK store, so a production ``--require-cert`` fleet can run
multiple instances. Run each instance with identical policy, CA roots and
storage configuration.

Shared-state requirements
-------------------------

* **One Postgres database, reachable from every instance.** Use TLS to the
  database (``sslmode=verify-full`` in the DSN) and a dedicated least-privilege
  role. Each instance opens its own connection pool; size Postgres
  ``max_connections`` for the instance count times the per-instance pool.
* **Schema migrations are safe to race.** Every instance runs migrations at
  startup under a Postgres advisory lock, so the schema is created exactly once
  regardless of start order.
* **AIK certificate roots and PCR policy are configuration, not shared state.**
  Distribute the same ``--aik-ca-cert``, ``--aik-crl``, ``--policy`` and
  ``--policy-pubkey`` material to every instance through the usual configuration
  channel; they are not stored in the database.
* **CA signing key.** The attestation CA is a separate service; its key handling
  (HSM/PKCS#11 or the dev-only PEM) is covered in
  :doc:`../security/ca-key <../security/ca-key>`.

Scaling the read path
---------------------

Session-token validation and other reads are single indexed lookups. At session
granularity their volume is far below the attestation path, so a single
Postgres node serves them comfortably. If a deployment ever needs more read
throughput, route reads to Postgres read replicas; because tokens are opaque
records in the shared store rather than self-describing blobs, this needs no
change to the token wire format or the SDK.

Scaling the write path (database sharding)
------------------------------------------

A single Postgres database bounds the fleet at its durable-write (WAL fsync)
rate, and that rate is *shared* by every instance pointed at it -- adding
verifier instances does not raise it. Past that ceiling, partition the
per-client write state across several independent databases with
``--pg-shard-dsn`` (repeatable, or ``LOTA_PG_SHARD_DSNS`` as a
comma-separated list), mutually exclusive with ``--pg-dsn``::

   lota-verifier \
     --pg-shard-dsn "postgres://…@pg-shard-0/lota?sslmode=verify-full" \
     --pg-shard-dsn "postgres://…@pg-shard-1/lota?sslmode=verify-full" \
     --pg-shard-dsn "postgres://…@pg-shard-2/lota?sslmode=verify-full"

Each per-client baseline, nonce and session token is routed to one shard by
a stable, process-independent hash of its key, so a given client's writes
always land on the same shard and every instance agrees on that mapping.
Because independent databases commit in parallel, aggregate durable-write
throughput scales with the number of shards **when each shard has
independent storage** (separate database hosts or volumes); shards packed
onto one disk still serialise on that disk's fsync.

Rules for a sharded deployment:

* **Give every instance the same shard list in the same order.** The shard
  index is positional; a divergent list would route the same client to
  different databases on different instances and break replay protection and
  cross-instance session validation. The verifier enforces this: each shard
  database carries its own identity and the control database pins the
  fingerprint of the ordered list, so an instance whose list does not
  reproduce it refuses to start instead of serving a routing its peers
  disagree with. Listing the same database twice is refused for the same
  reason.
* **The first shard is the control database.** Fleet-global, read-mostly
  state -- revocations, hardware bans, the audit trail and the attestation
  decision log -- lives on shard 0, not on the per-report path.
* **Size each shard for its slice.** A shard carries ``fleet / shards``
  clients; size ``max_connections`` on each for the instance count times the
  per-instance pool, as in the single-database case.
* **A shard is a failure domain.** Losing one shard fails closed only for the
  clients it owns (their next attestation errors and retries); the other
  shards keep serving. Run each shard with its own HA (primary/replica) as
  you would the single database.
* **Fix the shard count before you enrol the fleet.** The index is
  ``FNV-1a(key) mod N``, so changing ``N`` re-routes nearly every key.
  After adding or removing a shard, a client's baseline, its used-nonce
  history and its session tokens are looked up on a database that does not
  hold them: every client presents as a first attestation, which the default
  ``--allow-tofu-boot-baseline=false`` refuses unless a signed policy pins
  that client's PCR0/1/7; outstanding session tokens stop validating; and
  replay protection covers only the new routing until the history refills.
  Treat a shard-count change as a fleet-wide re-enrolment in a maintenance
  window -- migrate the baseline rows to their new shards first, or re-enrol
  the fleet -- not as a rolling capacity step. Size the shard count for the
  fleet you expect, not the one you have. The pinned shard set makes this
  explicit: a changed list is refused at startup until you clear the pin
  with ``DELETE FROM shard_set;`` on the control database, which is the
  point at which you confirm the migration is done. The same pin is
  recorded for a single ``--pg-dsn`` database, so switching an existing
  deployment to a sharded list is caught rather than silently re-routing
  every client.

Sharding composes with the multi-instance topology above: N stateless
instances in front of M shard databases. The client-to-verifier load
balancer needs no shard awareness -- any instance can serve any client
because all instances share the same shard set.

Choosing a topology
===================

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Need
     - Topology
   * - Test fleet, single host, no external DB
     - Single node (file + SQLite)
   * - Production, single verifier host
     - Single node (file + SQLite, ``--require-cert``)
   * - Production, failover or horizontal scale
     - N instances + Postgres (``--pg-dsn``, ``--require-cert``)
