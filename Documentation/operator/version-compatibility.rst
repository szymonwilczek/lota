.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================
Version compatibility
=====================

LOTA deployment is three cooperating programs that version independently: the
on-host **agent**, the **verifier**, and the **attestation CA**. They are almost
never upgraded in lockstep -- an operator rolls the verifier tier on its own
cadence, and an agent fleet (especially a player fleet the operator does not
control) updates whenever its hosts happen to. This document states which
version combinations are supported and why, so an upgrade can be planned.

It is written for operators planning an upgrade and for contributors changing a
wire format or the database schema.

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
     - Strict: majors must match
   * - Enrollment
     - agent - CA
     - enrollment wire version
     - Negotiated: additive, back-compatible
   * - Persistent schema
     - verifier - Postgres
     - schema version
     - Additive: old and new binaries coexist

Because the surfaces are independent, a verifier upgrade does not require an
agent upgrade, and a CA upgrade does not require either -- provided each surface
stays inside the tolerance below.

Attestation protocol (agent - verifier)
=======================================

Attestation report carries a fixed wire version (``ReportVersion``, today
``0x00010000`` = wire **1.0.0**). Verifier checks it for **exact equality**
and rejects a mismatch with the ``old_version`` verdict; there is no partial
acceptance of a report from a wire the verifier does not implement. This is
deliberate: the report is the security-load-bearing message, so the verifier
refuses to guess at a layout it was not built to parse.

Consequence for upgrades:

* The report wire version changes **only** on a breaking layout change, not on
  every release. Two releases that share a report wire version interoperate on
  the attestation path regardless of their release numbers.
* When the wire version *is* bumped, agents and verifiers must cross that
  boundary together. Roll the verifier tier to the new wire first (it accepts
  only the new version), then the agents -- or run the two wire versions on
  separate verifier endpoints during the transition. A flag-day is unavoidable
  for a breaking report change; that is the cost the strict check pays for not
  parsing an unknown security message.

Feature flags inside the report (``pcr_mask``, the boot-commitment and
initramfs-lock flags) are negotiated *within* a wire version and gated by
verifier policy, not by the wire version. An older agent that omits a newer
optional flag is handled by policy (for example ``--allow-no-initramfs-lock``),
not by a wire-version bump.

Enrollment protocol (agent - CA)
================================

Enrollment wire also carries a version, but it is **additive and
negotiated**, not strict. The rule the project follows:

* A new field is introduced under a bumped enrollment version. The encoder emits
  the **lower** version when the new field is absent, and the CA **mirrors the
  version of the request it received** in its replies.
* Therefore a new agent that sends no new-field data still speaks the old wire to
  an old CA, and a new CA still answers an old agent in the old wire. Only when a
  new agent actually uses a new field does it require a CA new enough to
  understand it.

The first use of this mechanism is the enrollment token that carries a device's
tenant to the CA: a token-bearing request is sent under the higher version, a
token-less request under the base version. An operator who has not deployed
tokens sees no version change on the enrollment path at all.

Consequence for upgrades: the CA and the agent fleet can be upgraded in either
order. Deploy the CA first if you intend to start using a new enrollment field,
so the field has somewhere to land; otherwise the order does not matter.

Persistent schema (verifier - Postgres)
=======================================

In a multi-instance deployment several verifier binaries of possibly different
releases share one Postgres database (see
:doc:`Verifier deployment topologies <ha-deployment>`). The schema is versioned
separately from everything above and evolves under one rule: **migrations are
additive and forward-only**. A migration may add a table, a column, or an index;
it may not drop or rename one, or retype a column in place.

The additive rule is what lets binaries of different releases share the database:

* The newest binary in the fleet migrates the schema forward on start, under a
  Postgres advisory lock, so exactly one instance applies each migration.
* An older binary keeps working against the migrated schema because it only ever
  reads and writes the columns it already knew; the added columns are invisible
  to it.

The SQLite and Postgres schema histories are versioned independently. SQLite
ships one consolidated schema for single-node deployments; Postgres carries the
incremental history a fleet migrates through. There is no parity requirement
between the two numbers.

The rolling procedure that relies on this rule -- and the rollback stance when an
upgrade must be undone -- is in
:doc:`Rolling verifier upgrades <rolling-upgrade>`.

Reading the versions a binary targets
=====================================

Every protocol version an operator needs to compare is printed by the verifier
itself:

.. code-block:: console

   $ lota-verifier --print-versions
   attestation report wire:  1.0.0
   postgres schema target:   3
   sqlite schema target:     6
   minimum TLS:              1.3

* **attestation report wire** is the only number that must match the agent
  fleet's report wire; compare it across an agent and a verifier release before
  assuming they attest.
* **postgres schema target** is the schema this binary migrates *up to*. Compare
  it against the live database (logged as ``schema_version`` at startup) to see
  whether starting this binary will run a migration.

Print the versions of the old and the new binary before a rolling upgrade; the
procedure in :doc:`rolling-upgrade` uses exactly these numbers.

Release numbering
=================

LOTA release numbers follow semantic versioning, with the pre-1.0 caveat that
the public surface is still stabilising: until 1.0, a minor bump may change a
protocol wire or the schema, and this document (plus the release notes) is the
authority on which surface moved. From 1.0 on, a breaking change to any of the
three surfaces above is a major bump. The release number is not itself a
compatibility check -- the three protocol versions are; the release number only
tells you *where to look* for a surface that moved.
