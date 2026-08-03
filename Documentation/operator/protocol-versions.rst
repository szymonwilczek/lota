.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=================
Protocol versions
=================

LOTA deployment is three cooperating programs that version independently: the
on-host **agent**, the **verifier**, and the **attestation CA**. They are almost
never upgraded in lockstep -- an operator rolls the verifier tier on its own
cadence, and an agent fleet (especially a player fleet the operator does not
control) updates whenever its hosts happen to. This document states how each
protocol surface is versioned and which combinations interoperate.

It is written for operators planning a deployment and for contributors changing
a wire format or the database schema.

What actually has to match
==========================

The three programs do not share one version number. They share three *protocol*
surfaces, and only the endpoints of each surface have to agree:

.. list-table::
   :header-rows: 1
   :widths: 26 22 26 26

   * - Surface
     - Endpoints
     - Versioned by
     - Break tolerance
   * - Attestation
     - agent - verifier
     - report wire version
     - Strict: exact equality
   * - Enrollment
     - agent - CA
     - enrollment wire version
     - Negotiated: additive, back-compatible
   * - Persistent schema
     - verifier - database
     - schema version
     - Additive: appended, never destructive

Because the surfaces are independent, a verifier upgrade does not require an
agent upgrade, and a CA upgrade does not require either -- provided each surface
stays inside the tolerance below.

Attestation protocol (agent - verifier)
=======================================

The attestation report carries a fixed wire version (``ReportVersion``, today
``0x00010000`` = wire **1.0.0**). The verifier checks it for **exact equality**
and rejects a mismatch with the ``old_version`` verdict; there is no partial
acceptance of a report from a wire the verifier does not implement. This is
deliberate: the report is the security-load-bearing message, so the verifier
refuses to guess at a layout it was not built to parse.

Consequences:

* The report wire version changes **only** on a breaking layout change, not on
  every release. Two releases that share a report wire version interoperate on
  the attestation path regardless of their release numbers.
* When the wire version *is* bumped, agents and verifiers must cross that
  boundary together. Move the verifier tier to the new wire first (it accepts
  only the new version), then the agents -- or run the two wire versions on
  separate verifier endpoints during the transition. A flag-day is unavoidable
  for a breaking report change; that is the cost the strict check pays for not
  parsing an unknown security message.

Feature flags inside the report (``pcr_mask``, the boot-commitment and
initramfs-lock flags) are gated by verifier policy *within* a wire version, not
by the wire version itself. An agent that omits an optional flag is handled by
policy, not by a wire-version bump.

Enrollment protocol (agent - CA)
================================

The enrollment wire also carries a version, but it is **additive and
negotiated**, not strict. The rule the project follows:

* A new field is introduced under a bumped enrollment version. The encoder emits
  the **lower** version when the new field is absent, and the CA **mirrors the
  version of the request it received** in its replies.
* A new agent that sends no new-field data therefore still speaks the old wire to
  an old CA, and a new CA still answers an old agent in the old wire. Only when a
  new agent actually uses a new field does it require a CA new enough to
  understand it.

The first use of this mechanism is the enrollment token that carries a device's
tenant to the CA: a token-bearing request is sent under the higher version, a
token-less request under the base version. An operator who has not deployed
tokens sees no version change on the enrollment path at all.

Consequence: the CA and the agent fleet can be brought up in either order.
Deploy the CA first if you intend to start using a new enrollment field, so the
field has somewhere to land; otherwise the order does not matter.

Persistent schema (verifier - database)
=======================================

The verifier creates its database at its final shape: both backends ship **one
consolidated migration**, so a fresh SQLite file or Postgres database reaches the
current schema in a single step.

The schema evolves from there by **appending** to that history, never by editing
the shipped entry. An appended migration must be **additive**: it may add a
table, a column, or an index; it may not drop or rename one, or retype a column
in place. ``migrations_test.go`` enforces this mechanically, so a destructive
migration fails the build.

The additive rule is what lets a multi-instance deployment share one database
(see :doc:`Verifier deployment topologies <ha-deployment>`):

* Whichever instance starts first applies the pending migration, under a Postgres
  advisory lock, so exactly one instance applies each one and the rest attach to
  the migrated schema.
* The instances already operating the database keep working through the change,
  because they only ever read and write the columns they already knew; an added
  column is invisible to them.

The SQLite and Postgres histories are versioned independently -- each number
counts its own backend's entries. There is no parity requirement between the two.

Reading the versions a binary reports
=====================================

Every version an operator needs is printed by the verifier itself:

.. code-block:: console

   $ lota-verifier --print-versions
   attestation report wire:  1.0.0
   postgres schema target:   1
   sqlite schema target:     1
   minimum TLS:              1.3

* **attestation report wire** is the number that must match the agent fleet's
  report wire; compare it across an agent and a verifier release before assuming
  they attest.
* **postgres schema target** and **sqlite schema target** are the schema this
  binary builds a database up to. Compare against the live database (logged as
  ``schema_version`` at startup) to see whether starting this binary runs a
  migration.

Release numbering
=================

LOTA release numbers follow semantic versioning, with the pre-1.0 caveat that
the public surface is still stabilising: until 1.0, a minor bump may change a
protocol wire or the schema, and this document (plus the release notes) is the
authority on which surface moved. From 1.0 on, a breaking change to any of the
three surfaces above is a major bump. The release number is not itself a
compatibility check -- the three protocol versions are; the release number only
tells you *where to look* for a surface that moved.
