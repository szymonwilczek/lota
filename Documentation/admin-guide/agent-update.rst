.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
Agent updates
=============

The daemon commits the SHA-256 of its own binary to PCR 14 once per boot
(:doc:`../agent/lifecycle`). A new build therefore takes effect at the next
cold boot, and a verifier whose policy lists agent hashes has to list the
new one before hosts boot it.

The new hash
============

The agent hash is the SHA-256 of ``/usr/bin/lota-agent``. On a host with
the new build installed, ``sha256sum /usr/bin/lota-agent`` prints it, and
``lota-agent --export-policy`` writes it under ``agent_hashes``
(:ghsrc:`src/agent/policy.c`).

Add it to ``agent_hashes`` of each policy beside the hash in use, sign the
policy again when the verifier runs with ``--policy-pubkey``, and restart
each verifier instance: the verifier reads ``--policy`` only at start
(:doc:`../verifier/command-line`).

A client reporting a hash the policy does not list is refused with
``agent hash not in allowed list``. A client reporting a listed hash other
than its pinned one moves its pin to it, with PCR 14, at most once every
24 hours ("Agent updates" in :doc:`../verifier/index`). Inside that
interval the round is refused and the verifier logs::

   agent_hash re-pin refused: the per-client interval has not elapsed
     reported_agent_hash=... last_repin_at=... interval_elapses_at=...

The host attests again once ``interval_elapses_at`` has passed, or at once
after ``lota-fleet reanchor CLIENT-ID -reason R -actor A``
(:doc:`fleet-cli`).

A client whose PCR 14 was pinned without an agent hash has no pin to move.
The verifier logs ``agent_hash re-pin refused: the baseline carries no
pinned hash to move``, then ``baseline carries no pinned agent_hash;
refusing to adopt the reported one``, and refuses every round on a new
build until the client is re-anchored.

On the host
===========

#. Install the package (``dnf upgrade lota-agent``). The upgrade reloads
   the SELinux module when it is loaded, runs ``lota-install
   --unattended``, and leaves the running units alone
   (:ghsrc:`packaging/rpm/lota.spec`).

#. Until the reboot, the running daemon keeps attesting as the build that
   booted, and its status carries ``UPDATE_PENDING``
   (:doc:`../agent/ipc`), which a title can show to the player.

   A restart of ``lota-agent`` or ``lota-attest`` before the reboot runs the
   new binary against a PCR 14 that commits to the old one: both refuse
   with exit status 78 and stay failed until the reboot
   (:doc:`bringup/limitations`). The stop itself spends the commitment, so
   even the old binary would be refused.

#. Cold reboot. The new build commits itself to PCR 14 and its first round
   reports the new hash.

When every host runs the new build, remove the old hash from
``agent_hashes`` and restart the verifiers again, so a host that comes back
on the old build is refused.

How long both hashes stay listed is the operator's choice. A fleet that
schedules its reboots can remove the old hash after the last one. A fleet of
hosts that reboot on their own schedule keeps both for a set period; a host
still on the old build after it is refused until it reboots.
