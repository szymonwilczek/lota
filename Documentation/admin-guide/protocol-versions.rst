.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=================
Protocol versions
=================

The agent, the verifier and the attestation CA are released and upgraded
apart. What must agree are the three interfaces between them, each with its
own version:

================= ================ ============================================
Interface         Between          Rule
================= ================ ============================================
Attestation       agent, verifier  One version; the verifier accepts its own
                                   alone.
Enrollment        agent, CA        One version per frame; the CA answers in
                                   the version it was asked in.
Schema            verifier,        A version and a fingerprint; migrations are
                  database         appended and never destructive.
================= ================ ============================================

A release that keeps the three leaves the others to upgrade on their own
time.

Attestation
===========

Every frame of a round carries the report version, ``LOTA_REPORT_VERSION`` in
the agent and ``ReportVersion`` in the verifier, 1.0.0
(:doc:`../verifier/report-format`).

* The verifier refuses a report of another version with ``old_version``,
  once the report holds the 5360 bytes of its fixed part; a shorter one is
  ``report_malformed`` whatever its version. A report that does not parse in
  its version is ``report_malformed`` too.
* The agent does not read the version of the challenge or the result.
* The version changes with the layout: a field added, removed or moved, or a
  section added. A release that keeps the layout keeps the version.

A layout change is crossed by the agents and the verifiers together. Either
the fleet upgrades in one window after the verifiers, or a second verifier
endpoint takes the new version while the hosts move to it.

The PCR mask, the boot commitment and the initramfs lock are not negotiated:
every report carries them and the verifier requires them. A new derivation
takes a flag bit of its own.

Enrollment
==========

Each enrollment frame carries its version, 1
(:ghsrc:`src/attestca/wire/wire.go`, ``LOTA_ENROLL_VERSION`` in
:ghsrc:`include/lota_enroll.h`).

* The agent sends the newest version it speaks. The CA answers in the
  version of the request.
* Each side refuses a version its build does not implement, and a frame with
  bytes past its last field.
* A field every frame of a version carries, empty when unused: the
  enrollment token and the EK chain are a zero length and a zero count when a
  host has none.

A CA that speaks a new version answers the hosts on the old one, so the CA
goes first and the agents follow.

Schema
======

Each backend carries its list of migrations, and a database records the ones
applied ("Schema" in :doc:`../verifier/store`). A migration is appended,
never edited, and adds a table, a column or an index; it drops, renames and
retypes nothing. The tests in :ghsrc:`src/verifier/store/migrations_test.go`
refuse one that does. Instances on the older build keep using the columns
they know while a newer one migrates the database
(:doc:`ha-deployment`).

At startup the verifier logs ``schema_version`` and checks the database
against its own build:

``database schema is newer than this build``
  The database holds a migration this build does not. Run the newer build,
  or restore a backup taken at this one.

``database schema was written by a different build``
  The fingerprint differs: two builds hold different migrations at one
  version. Run the build that wrote it.

``database schema is not the shape this build creates``
  A table is missing or extra. The answer names them.

A database that records no fingerprint gets this build's, with a warning,
once its tables match. A ``--report-only`` instance applies nothing and
refuses a database behind its own version.

The SQLite and Postgres versions count their own migrations and need not
match.

Reading the versions
====================

.. code-block:: console

   $ lota-verifier --print-versions
   attestation report wire:  1.0.0
   postgres schema target:   1 (<fingerprint>)
   sqlite schema target:     1 (<fingerprint>)
   minimum TLS:              1.3

``attestation report wire``
  The version the agents must send.

``postgres schema target``, ``sqlite schema target``
  The version this build migrates a database to, and the first 12 hex digits
  of its migrations' fingerprint. A target above the ``schema_version`` a
  running instance logs means this build migrates the database. A refusal
  names both fingerprints, to compare with this one.

``minimum TLS``
  The lowest TLS version the attestation listener accepts.

Releases
========

A release number is not a compatibility check: the three versions above
are, and the release notes say which one a release moves. Until 1.0 a minor
release may move one.
