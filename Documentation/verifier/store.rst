.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====
Store
=====

The verifier keeps its state in one backend, picked by the storage options
of :doc:`command-line`. The tables are created by
:ghsrc:`src/verifier/store/postgres.go` and :ghsrc:`src/verifier/store/db.go`;
the baseline and nonce stores are under :ghsrc:`src/verifier/verify`.

Backends
========

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - State
   * - ``--pg-dsn``
     - Everything, in one Postgres database that every instance shares.
   * - ``--pg-shard-dsn``
     - Everything, over several Postgres databases (`Shards`_).
   * - ``--db``
     - Everything, in one SQLite file. One instance only.
   * - ``--state-db``
     - Used nonces, revocations, bans, the audit log and the decision log in
       one SQLite file. The baselines stay in memory and are lost on restart.
   * - ``--allow-insecure-memory-state``
     - Nothing durable. The used-nonce history holds the last 10000 nonces.

The challenges a verifier has sent and not yet seen answered live in that
instance's memory on every backend: a report reaches the instance whose
challenge it answers, on the same connection.

Tables
======

``baselines``
  One row per client ID: the agent hash and PCR 14, PCR 0, 1 and 7, the event
  log and ESRT firmware version recorded with the pin, the re-anchor counters
  and their last times, the pending low-assurance review, the tenant, and the
  last kernel digest and machine keys (:doc:`index`).

``baseline_archive``
  The values a re-anchor replaced, with the time and the reason. A row is
  never removed, a client delete included.

``forced_reanchors``
  The clients an operator forced to re-anchor. The round that pins the
  client afresh spends the row.

``used_nonces``
  The nonces already answered, in hex, with the time of use. A nonce is kept
  for 15 minutes, three times the five-minute challenge lifetime.

``revocations``, ``hardware_bans``
  The revoked client IDs and the banned device pseudonyms, each with its
  tenant, the reason, the actor, the note and the time.

``audit_log``
  One row per operator action: the action, the target, the reason, the actor,
  the note, the tenant and the time.

``attestation_log``
  The decision log (`Decision log`_).

``shard_identity``, ``shard_set``
  Postgres only: the database's own identity and the shard set it belongs to
  (`Shards`_).

``schema_version``
  The migrations applied, each with its time and the schema fingerprint
  (`Schema`_).

Postgres serializes the writes for one client with a transaction-scoped
advisory lock on the client ID, and runs those of different clients in
parallel. The SQLite baseline store takes one process mutex for every
client.

Decision log
============

A row in ``attestation_log`` stands for a run of rounds on one host. It holds
the tenant, the client ID, the hardware ID, the verdict, PCR 14, the kernel
digest, the details, the peer address and the duration; ``timestamp`` is the
first round, ``last_seen`` the last and ``rounds`` the count.

A passing round extends the host's newest row when that row passed too, holds
the same hardware ID, PCR 14, kernel digest and details, and opened at most
``--attestation-log-window`` before (default ``1h``). Any other round opens a
row: the host's first, any refusal, the first pass after a refusal, a change
in the evidence, and a round dated before the row's ``last_seen``. A window
of 0 opens a row per round.

The log gates nothing, and a write that fails or is late never changes a
verdict (:ghsrc:`src/verifier/store/attestation_batch.go`):

* A round is buffered and written by a background worker, in batches of up
  to 256, every second or when a batch fills. A read through the monitoring
  API writes the buffer first.
* The buffer holds 4096 rounds. Past that it sheds passing rounds first,
  oldest first, then refusals. A shed pass costs little: the host's next
  pass opens the row.
* On shutdown the buffer gets 5 seconds to be written. A crash loses what is
  buffered.
* What is lost is logged as ``attestation-log buffer full; decision records
  shed`` (at most every 30 seconds) or ``attestation-log flush failed; records
  dropped``, and counted in ``lota_attestation_log_dropped_total``,
  ``lota_attestation_log_failed_total`` and, for the refusals among them,
  ``lota_attestation_log_events_lost_total``
  (:doc:`../admin-guide/observability`).

The used nonce and the baselines a round writes are written before its
verdict is sent.

Shards
======

With ``--pg-shard-dsn`` the baselines and used nonces of a client live on the
shard picked by the FNV-1a hash of its client ID, modulo the number of shards
(:ghsrc:`src/verifier/verify/shard.go`). A round touches one shard, and no
transaction spans two. Revocations, bans, the audit log and the decision log
live on the first shard. A single ``--pg-dsn`` is a set of one shard.

The hash is the same in every process, so instances route alike only when
they list the same databases in the same order. The verifier pins the set
(:ghsrc:`src/verifier/store/shard_identity.go`):

#. Each database records a random identity in ``shard_identity`` the first
   time a verifier opens it.
#. Each database records in ``shard_set`` the fingerprint of the ordered list
   of identities and the shard count, the first time a set is pinned on it.
#. At startup a list that names a database twice, or differs from a pin, is
   refused with ``shard set check failed``.

Changing the set moves clients to other shards, where their baselines and
used nonces are not. It takes moving or re-enrolling the clients, then
``DELETE FROM shard_set`` on every shard so the next start pins the new set.

A ``--report-only`` instance reads the identities and checks the pin, and
writes neither: a database no writer has opened is refused, and one with no
pin is logged as ``shard set is not pinned on every database``.

Schema
======

Each backend carries its own list of migrations, applied in order at startup
and each in its own transaction. On Postgres a session advisory lock
serializes the instances that start together. The schema is checked three
ways after the migrations, and each mismatch stops the verifier
(:ghsrc:`src/verifier/store/schema_identity.go`):

Version
  A version above the highest this build knows is refused with ``database
  schema is newer than this build``. Run that build, or restore a backup
  taken at this one.

Fingerprint
  The SHA-256 of every migration's version, description and SQL. A different
  recorded fingerprint is refused with ``database schema was written by a
  different build``. A database that records none is stamped, with a
  warning.

Tables
  The tables must be those the migrations create, apart from
  ``schema_version``. A missing or extra table is refused with ``database
  schema is not the shape this build creates``.

A writer refuses a hot standby before migrating, with ``database is a
read-only standby``. A ``--report-only`` instance applies nothing and refuses
a database below its version or with no schema, ``database carries no LOTA
schema``; a verifier on the primary builds and migrates it.

``lota-verifier --print-versions`` prints the version and fingerprint of each
backend (:doc:`../admin-guide/protocol-versions`).

A migration is appended and never edited, and adds a table, a column or an
index without dropping, renaming or retyping one, because the instances still
running the older build keep using the database. The tests in
:ghsrc:`src/verifier/store/migrations_test.go` refuse a destructive
migration.

Connection pool
===============

Each instance opens at most ``--pg-max-open-conns`` connections per database,
default 20, and keeps half of them idle. A connection is closed after 30
minutes, or 5 minutes idle. Every instance's pool draws on the database's
``max_connections``, and the verifier warns at startup when its pool alone
exceeds it (``connection pool exceeds the database's max_connections``) or
leaves no room for a second instance (``connection pool leaves no room for a
second instance``). Postgres commits concurrent transactions together, so a
wider pool takes more writes per commit (:doc:`../admin-guide/ha-deployment`).

The SQLite file is opened with write-ahead logging, a 5-second busy timeout
and up to 10 connections; its directory is created with mode 0700.
