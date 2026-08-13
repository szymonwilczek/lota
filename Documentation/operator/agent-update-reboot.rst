.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========================================
Agent updates and the reboot requirement
========================================

Updating the on-host agent is not like updating an ordinary daemon. The agent
measures its own binary into **PCR 14**, the TPM boot-commitment register, and
that register is only written at boot. Replacing ``/usr/bin/lota-agent`` on a
running host therefore does **not** change the committed measurement: the new
binary sits on disk, but the value the verifier checks against still reflects the
old one until the host cold-reboots and the new binary measures itself in.

Two more properties make the update a deliberate procedure rather than a package
swap:

* **The enforcing daemon is unkillable by design.** LOTA LSM hook refuses
  ``kill`` against the agent, so ``systemctl stop`` cannot bring it down. Use
  ``lota-agent --shutdown``, the in-band graceful-shutdown request, to stop it
  for replacement.
* **The binary carries an immutability proof** -- fs-verity on ext4/btrfs, or a
  signed ``security.ima`` xattr on XFS. Replacing the file drops that proof (a
  ``dnf upgrade`` in particular strips ``security.ima``), so it must be
  re-established before the agent will run under enforcement.

This document is the operator runbook for rolling a new agent build across a
fleet. It pairs with the binary-replacement note in
:doc:`../security/threat-model`.

The verifier must trust the new hash first
==========================================

The verifier pins the set of accepted agent self-hashes in its policy
(``agent_hashes``). New agent build has a new hash, so an agent that boots the
new binary before the verifier trusts that hash will **fail attestation**. Pin
the new hash *before* the fleet reboots:

#. Take the new agent's self-hash from the signed release, where the release
   notes publish it alongside the artifacts.
#. Add it to ``agent_hashes`` **alongside** the current hash -- both are pinned
   for the duration of the rollout -- re-sign the policy, and distribute it to
   the verifier tier. Listing it is also what lets each device move its own
   pinned baseline: a client reporting a listed hash re-pins itself and keeps
   attesting, so the rollout needs no per-device operator action (see
   ``policies/README.rst``, "Updating Policies"). Policy is configuration, not
   database state, so push it to every instance and reload them (restart the
   instances one at a time if they read policy at start).

Pinning both hashes is what creates the grace window in which old and new agents
both attest. How wide that window is depends on the deployment (see
`Grace window`_).

Per-host update
===============

On each host, once the new hash is pinned in the verifier tier:

#. **Update the package.** Install the new agent build (for example
   ``dnf upgrade lota-agent``).
#. **Check the immutability proof.** fs-verity is a property of the inode and
   the upgrade writes a new file, so the proof the old binary carried does not
   survive it. The package's post-install re-enables fs-verity on the new
   binary and says so; where the filesystem cannot carry it (XFS below 6.13,
   for instance) it says that instead, and the ``security.ima`` xattr has to be
   re-signed with the operator IMA key. One of the two is mandatory: without
   either, the agent refuses to start under enforcement, so a host that skips
   this comes back from its reboot with no agent at all.

   While the host waits for that reboot the agent reports
   ``LOTA_FLAG_UPDATE_PENDING`` alongside its normal flags, so a title can tell
   the player a restart is coming rather than letting them meet it as a launch
   failure. Attestation is unaffected until the reboot: PCR 14 commits to the
   build still running and the token names that build.
#. **Stop the running daemon.** ``lota-agent --shutdown`` -- ``systemctl stop``
   cannot, because the LSM hook blocks the kill.
#. **Cold-reboot the host.** A full power cycle, not a warm reboot: PCR 14 only
   resets on a hardware reset on most platforms, so a warm reboot may leave the
   stale commitment in place. On boot the new binary measures itself into a fresh
   PCR 14.
#. **Confirm attestation.** The agent attests with its new hash, which the
   verifier now trusts, and returns ``VERIFY_OK``. The post-reboot checks in
   :doc:`production-bringup/post-bringup` apply unchanged.

After the fleet has fully moved
===============================

Once every host runs the new build, remove the old hash from ``agent_hashes``,
re-sign, and redistribute, so a host that reappears on the old binary is no
longer accepted.

Grace window
============

The width of the both-hashes-pinned window is the operator's policy choice, and
it differs sharply between the two deployment shapes:

* **Enterprise fleet (operator-controlled hosts).** Reboots are scheduled, so the
  window is short and bounded. Pin both hashes, roll the reboots through the
  maintenance window, then tighten to the new hash only. The mixed-version window
  lasts as long as the reboot schedule, not longer.
* **Player fleet (hosts the operator does not control).** Players reboot on their
  own cadence -- typically when the game client that carries the agent update
  next restarts the machine. The backend keeps both hashes pinned for the whole
  rollout and gates entry on *either*, then removes the old hash once telemetry
  shows the old build has drained. Here the grace window is a product decision:
  accept the old build for a defined period, or hard-gate immediately and force
  the reboot as a condition of play.

In both shapes the mechanism is identical -- pin the new hash, keep the old one
until the fleet drains, then drop it. Only the timing policy changes.
