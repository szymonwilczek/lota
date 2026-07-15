.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Rolling verifier upgrades
=========================

This document is the procedure for upgrading a multi-instance verifier tier to a
new release without dropping attestation traffic. It assumes the Postgres
topology from :doc:`Verifier deployment topologies <ha-deployment>`: several
stateless verifier instances behind a load balancer, one shared Postgres.
Single-node deployment cannot roll -- see `Single node`_ at the end.

It relies on the compatibility rules in
:doc:`Version compatibility <version-compatibility>`; read that first. The short
version: the schema evolves by additive, forward-only migrations, so a binary of
the old release and a binary of the new release operate the same database at the
same time. That property is what makes the rollout below safe.

Before you start
================

Confirm the upgrade is actually rolling-safe, not a flag-day. Print the versions
of the old and the new binary and compare:

.. code-block:: console

   $ lota-verifier-old --print-versions
   $ lota-verifier-new --print-versions

* **attestation report wire** must be identical. If it changed, agents on the
  old wire cannot attest to the new binary; that is a coordinated wire
  migration, not a rolling upgrade (see
  :doc:`Version compatibility <version-compatibility>`). Stop here.
* **postgres schema target** of the new binary must be greater than or equal to
  the old one, and greater than or equal to the live ``schema_version`` the tier
  logs at startup. A new binary with a *lower* schema target than the live
  schema is an accidental downgrade -- do not start it.

The procedure
=============

Replace one instance at a time. At every step at least one instance is serving,
so the load balancer never has zero healthy backends.

#. **Drain one instance.** Remove it from the load balancer's rotation (or let
   its ``GET /health`` fail by stopping it); wait for in-flight requests to
   finish. The other instances keep serving.
#. **Replace the binary and start it.** The first new instance to start runs the
   pending migrations. Migrations execute under a Postgres advisory lock, so if
   several instances start at once exactly one applies each migration and the
   rest wait, then attach to the migrated schema. Because the migrations are
   additive, the still-running old instances are unaffected -- they never touch
   the new columns.
#. **Confirm it is healthy.** ``GET /health`` returns healthy and the startup log
   shows ``schema_version`` at the new target. Watch the verifier's metrics for a
   steady attestation success rate on the new instance before proceeding; a drop
   means the new binary is rejecting reports the old one accepted, which is a
   compatibility problem, not a rollout problem.
#. **Return it to rotation and repeat** for each remaining instance until the
   whole tier runs the new release.

Throughout, old and new instances share the one Postgres: a baseline pinned, a
client revoked, a nonce spent or a session token issued on any instance is
enforced on all of them, regardless of which release served the request. The
shared-state guarantees in :doc:`ha-deployment` hold across the mixed-version
window.

Rolling back
============

Rollback is the same procedure with the old binary, and it is safe for the
same reason: the additive migrations are never un-applied, and the old binary
simply ignores the columns a newer migration added. The schema stays at the
higher version; that is expected and harmless.

The only cases a rollback cannot recover from cleanly:

* **A report wire change** -- ruled out in `Before you start`_; a mixed wire tier
  cannot serve one agent fleet.
* **A destructive migration** -- forbidden by the additive gate in the store
  test suite precisely so that rollback stays possible. If one ever ships, the
  schema is no longer old-binary-readable and the rollback is a restore, not a
  roll.

Single node
===========

Single-node deployment (file+SQLite or one Postgres-backed process) has no
second instance to keep serving, so its upgrade is a brief stop-swap-start with
downtime, not a rolling one: stop the process, replace the binary, start it (it
migrates its own schema on the way up), confirm ``GET /health``. Schedule it in a
maintenance window. To get zero-downtime upgrades, move to the multi-instance
Postgres topology first.

The agent side
==============

Upgrading the on-host agent is a different procedure with its own constraint --
the agent's boot commitment only re-measures on a cold reboot, and its hash must
be pinned in verifier policy before the fleet rolls. See
:doc:`Agent updates and the reboot requirement <agent-update-reboot>`.
