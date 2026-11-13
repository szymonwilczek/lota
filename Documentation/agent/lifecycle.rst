.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===============
Agent lifecycle
===============

The agent runs as two units: the daemon, which enforces and answers titles,
and the attestation loop, which reports to verifiers. The daemon commits
its own binary to PCR 14 once per boot, so a stop lasts until the next
reboot. The startup order and the exit statuses are in :doc:`index`.

Units
=====

``lota-agent.socket``
  Listens on ``/run/lota/lota.sock``, mode 0660, owner ``root:lota``, and
  starts ``lota-agent.service`` (:doc:`ipc`).
  ``RemoveOnStop=yes`` unlinks the socket when the unit stops.

``lota-agent.service``
  Runs ``/usr/bin/lota-agent``, the daemon, ``Type=notify`` with a 60-second
  watchdog. ``ExecStop`` is ``lota-agent --shutdown``, ``ExecReload`` sends
  ``SIGHUP``. ``Restart=on-failure`` after 5 seconds, except on exit status
  78 or 3. It requires the socket unit.

``lota-attest.service``
  Runs ``lota-agent --attest``, the attestation loop, with a 60-second
  watchdog. ``Restart=on-failure`` after 30 seconds, except on exit status
  78. It holds no capabilities (``CapabilityBoundingSet=`` empty), reaches
  the TPM through ``DeviceAllow`` and loads no BPF.

``lota-sysusers.conf``
  Creates group ``lota``, the group of the IPC socket. The package applies
  it on install.

The units are in :ghsrc:`systemd/`. The package runs ``lota-install
--unattended`` (:doc:`../admin-guide/lota-install`) after it installs. It
enables and starts the socket, the daemon and the loop only when every
stage before them completes: a change to how the host boots that waits for
a reboot stops it at the reboot checkpoint, a stage that fails ends it, and
either way it starts no unit. Both services run with
``ProtectSystem=strict``, a private ``/tmp`` and ``/home`` and ``/root``
out of reach; they write only to ``/var/lib/lota`` and ``/run/lota``.

The boot commitment
===================

At a cold boot the initramfs helper ``lota-pcr14-lock``
(:ghsrc:`src/initramfs/lota-pcr14-lock.c`) records the value of PCR 14 in
``/run/lota/pcr14_baseline`` and extends it with a lock value. On a host
that did not boot through UEFI the helper refuses. The daemon then
extends PCR 14 with the hash of its own binary chained onto the lock, and
records the register and the TPM's ``resetCount`` in
``/var/lib/lota/clock_state.dat``. The register cannot be reset from user
space, so this happens once per boot (:ghsrc:`src/agent/tpm.c`,
``tpm_classify_pcr14()``).

At each start the daemon reads PCR 14 and decides:

The register holds the lock value
  It extends the commitment.

The register holds this binary's commitment
  It extends nothing: an earlier agent of this boot ended without a
  shutdown, or the host resumed from a suspend that keeps the PCRs. It
  logs ``An earlier agent of this boot ended without a shutdown; status
  and tokens say AGENT_RESTARTED until reboot``, and they do. When the
  snapshot shows the TPM was reset since, the same value means something
  extended it before the agent, and the start is refused as tampered.

Anything else
  The start is refused with exit status 78. The message names the case:

  * a shutdown on this host spent the commitment: reboot;
  * the initramfs lock did not run: rebuild the initramfs
    (``dracut -f --add lota``) and cold reboot;
  * the commitment belongs to another agent binary, as after an upgrade:
    cold reboot (:doc:`../admin-guide/agent-update`);
  * the register holds an unexpected value, with or without a snapshot to
    attribute it, was extended before the agent at this boot, or changed
    after the agent's extend: messages prefixed ``SECURITY:``;
  * the baseline handoff does not match the commitment;
  * the TPM reports a lower ``resetCount`` than the snapshot.

The attestation loop measures itself the same way, and a refusal ends it
with status 78 and the line ``Starting the loop again cannot clear this``.

Startup refusals before the commitment
--------------------------------------

The startup policy, the signature of the enforcement object and its
integrity layout are checked before PCR 14 is touched. A refusal logs one
of:

* ``Startup policy refused before the boot commitment was spent; the host
  keeps the agent it is running and PCR 14 is untouched.``
* ``Enforcement object PATH refused before the boot commitment was spent:
  why. The host keeps the agent it is running and PCR 14 is untouched.``,
  for the signature;
* ``Enforcement object PATH refused before the boot commitment was spent.
  The host keeps the agent it is running and PCR 14 is untouched.``, for
  the layout.

A transient cause (``EIO``, ``EMFILE``, ``ENFILE``, ``ENOMEM``,
``EAGAIN``, ``EINTR``, ``EBUSY``) exits 1 and the unit restarts; any other
exits 78 with what to fix (:ghsrc:`src/agent/exit_status.c`). The
commitment stays unspent, so a fixed configuration starts in the same boot.

Stopping
========

``lota-agent --shutdown`` (:doc:`command-line`), which ``systemctl stop
lota-agent`` runs, asks the daemon to leave its event loop (:doc:`ipc`).
On its way out with the LSM program loaded, the daemon extends PCR 14 with
a random value, records in ``clock_state.dat`` that it did, and logs
``Runtime PCR poisoned before BPF unload``. The next start in that boot is
refused as spent by a shutdown. A host stopped this way attests again after
a reboot, and every relying party sees the pause.

Nothing else stops the daemon (:doc:`protection`):

* every signal but 0 and ``SIGHUP`` is refused, from every process
  including PID 1, in every mode;
* a write to ``cgroup.kill`` or ``cgroup.freeze`` of the agent's cgroup or
  an ancestor is refused and logged as ``KILL_BLOCKED``. At startup the
  daemon logs ``Kill guard armed on N cgroup file(s) above PATH``; without a
  unified cgroup hierarchy it logs that there is nothing to guard, and a
  guard it cannot set up ends the start;
* a move of the agent to another cgroup ends the agent and every protected
  process before the move takes effect, logged as ``AGENT_MOVED``.

So ``systemctl kill`` and ``systemctl freeze`` do not reach the agent, and
neither does systemd's kill after ``TimeoutStopSec`` when ``--shutdown``
does not complete. ``systemctl restart`` of either ``lota-agent`` unit is a
stop followed by a start: ``Requires=`` carries the stop of the socket to
the service. In the same boot the next connection to the socket starts the
service, which exits 78 and stops the socket. Until reboot every start of
the service exits 78. Stopping the socket cancels the start job, so
``systemctl restart lota-agent`` reports the job as canceled; the refusal
is in ``journalctl -u lota-agent``.

A wedged agent
==============

A thread of the daemon pings the systemd watchdog while the main loop
advances (:ghsrc:`src/agent/watchdog.c`). After half the watchdog interval
with no progress it holds the ping and logs ``Watchdog: the main loop has
not advanced in N ms, holding the ping``; when the loop advances again it
logs that pings resumed. After the whole interval it logs ``Watchdog: the
main loop has not advanced in N ms, past the M ms interval. Ending the
process from inside: the signal systemd sends is refused by this agent's
own kill guard.`` and sends itself ``SIGKILL``.

A kill, like a crash, skips the PCR 14 poison. ``Restart=on-failure``
starts the daemon again, the commitment is found held, and the host carries
``AGENT_RESTARTED`` until reboot.

Reloading
=========

``systemctl reload lota-agent lota-attest`` sends ``SIGHUP``. The daemon
and the loop read the configuration again and PCR 14 stays as it is; what
a reload applies is in :doc:`configuration`. A publisher added
with ``--add-publisher`` reaches both this way (:doc:`publishers`).

The sockets
===========

The daemon watches ``/run/lota``. When something replaces or removes
``lota.sock`` it binds the path again and logs ``IPC socket
/run/lota/lota.sock was replaced; rebound, titles can reach the agent
again``.

A container listener (:doc:`ipc`) is laid down when the registered user's
runtime directory appears and released when it goes, with no restart.
``lota-steam-setup --install-systemd-dropin`` writes
``/etc/systemd/system/lota-agent.service.d/10-xdg-runtime.conf``
(example in :ghsrc:`systemd/lota-agent.service.d/10-xdg-runtime.conf.example`),
which sets ``XDG_RUNTIME_DIR=/run/user/<uid>`` for the daemon. Both the
drop-in and ``container_listener_uid`` are read at startup, so they apply
at the next boot.

The attestation loop
====================

The daemon reports to no verifier. ``lota-agent --attest`` reports to each
publisher's verifier on its cadence (:doc:`publishers`), renews the
certificates, and trades state with the daemon over
``/run/lota/lota.sock`` after each round: verdicts out, session counts and
enrollment requests in (``SYNC_ATTEST``, :doc:`ipc`). With
``attest_interval = 0`` and no profile it attests once to ``server`` and
exits (:doc:`configuration`).

Stopping ``lota-attest`` leaves titles answered, but the verdicts lapse and
session-gated publishers get no reports. With the daemon unreachable the
loop keeps attesting, logs ``Cannot reach the enforcement daemon on
/run/lota/lota.sock (...): session-gated publishers keep the session counts
it last reported until it answers``, and tries again every 30 seconds
(:ghsrc:`src/agent/attest_peer.c`).

A failed round logs the stage and the cause, then the failure count and
the backoff, which starts at 10 seconds and doubles up to 300:

.. code-block:: text

   Attestation round failed at STAGE: CAUSE
   Attestation FAILED for PUBLISHER (attempt N, backoff Ss)

The stages are ``TLS setup``, ``connecting to the verifier``, ``receiving
the challenge``, ``building the report``, ``serializing the report``,
``sending the report``, ``receiving the verdict`` and ``the verifier's
verdict`` (:ghsrc:`src/agent/attest_stage.c`).

``systemctl status lota-attest`` shows one of:

* ``Attested (N publisher), valid until T``, ``publishers`` for more than one;
* ``Idle: no publisher configured``;
* ``Idle: no title running, nothing reported``;
* ``Attestation incomplete``;
* ``AIK cert renewal failing for ID, expires in N s``.

The loop pings the watchdog at every point it passes once half the
interval has gone by, before a round and after a sleep, so a round that
hangs on the TPM or the network misses the deadline and systemd restarts
the loop.
