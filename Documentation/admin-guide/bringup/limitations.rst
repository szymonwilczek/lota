.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============
After bring-up
==============

A host that meets every check in :doc:`gate-matrix` can still refuse to
start, or start and refuse tokens. Each refusal below is a line in
``journalctl -u lota-agent``; the order of the checks and the exit
statuses are in :doc:`../../agent/index`, and the other lines of the
journal in :doc:`../../agent/journal`.

Fixed in the same boot
======================

These refusals come before the daemon extends PCR 14, so a start after the
fix brings the host up without a reboot. The daemon exits 78 and the unit
stays failed (:doc:`../../agent/lifecycle`).

``Kernel anti-tamper prerequisites are not satisfied``
  Lockdown, module signatures or the label of the TPM device; the lines
  before it name which (:doc:`gate-matrix`).

``BPF object signature verification failed for`` *PATH*
  The object and the key the daemon reads do not belong together. The
  package's ``/usr/lib/lota/enforcement.pub`` matches the package's
  object, so a key earlier in the lookup, ``/etc/lota/policy.pub`` or the
  one ``policy_pubkey`` names, did not sign it. Sign the object with that
  key, or move the key aside (:doc:`manual-reference`). A ``policy_pubkey``
  naming a file that does not read does not cause this: the daemon takes
  the next key in the lookup.

``Cannot trust lib`` *PATH* or ``Cannot measure fs-verity path`` *PATH*
  A ``--trust-lib`` or ``--allow-verity`` path the daemon cannot open. The
  unit runs with ``ProtectSystem=strict``, a private ``/tmp`` and
  ``/home`` and ``/root`` out of reach, so a path a shell sees there does
  not exist for the daemon. ``Startup policy refused before the boot
  commitment was spent`` follows.

``No process is running under PID`` *N*\ ``, so there is nothing to protect``
  A ``--protect-pid`` or ``protect_pid`` entry names no running process.
  The daemon reads the list at start and again on ``SIGHUP``; a process
  that starts later protects itself with ``lota_protect_self()``.

``The attestation key at 0x``\ *HANDLE* ``has no record``
  The TPM holds the AIK and ``aik_meta.dat`` is gone, from
  ``/var/lib/lota`` or from the publisher's profile. Restore it and the
  authorization file the line names from a backup, or run ``lota-agent
  --reprovision-aik`` (:doc:`../../agent/tpm`).

``This publisher's attestation key was created before each publisher``
  The publisher's key is the one every publisher of the host holds. Run
  ``lota-agent --reenroll --publisher ID``; the CA certifies the new key
  under the host's device ID. The attestation loop logs the same line and
  attempts no round for that publisher meanwhile.

Fixed by a cold reboot
======================

These refusals read PCR 14, which nothing resets while the host is up
(:doc:`../../agent/lifecycle`). The daemon exits 78.

``The agent is paused on this host``
  A shutdown requested here, ``lota-agent --shutdown``, ``lota-install
  --pause`` or ``systemctl stop lota-agent``, spent the commitment. Reboot.

``An earlier run of the agent in this boot failed after loading BPF``
  That run spent the commitment on its way out, and its own log names the
  error. Fix it and reboot.

``This is not the lota-agent build PCR 14 committed to when the host booted``
  The binary changed since the boot, as after an upgrade, or a second build
  runs by hand. Reboot into the installed build
  (:doc:`../agent-update`).

``PCR 14 never received the initramfs lock this boot``
  The initramfs did not carry ``lota-pcr14-lock``. Rebuild it
  ("Initramfs lock" in :doc:`manual-reference`) and cold reboot.

``The initramfs baseline handoff on /run is not the one``
  ``/run/lota/pcr14_baseline`` was replaced after the initramfs wrote it.
  Reboot. When the refusal comes back, something extended PCR 14 and
  rewrote ``/var/lib/lota/clock_state.dat`` to match; find what writes to
  ``/run/lota`` and ``/var/lib/lota``.

``PCR14 boot-commitment refused``
  A line prefixed ``SECURITY:`` before it names the case. For an
  unexpected value, or one that changed before or after the agent's
  extend, something outside the agent extended PCR 14: cold reboot, and
  find what opened ``/dev/tpmrm0``. For a ``resetCount`` below the one
  recorded, the TPM or ``/var/lib/lota/clock_state.dat`` was rolled back.

Refused tokens
==============

``Refusing GET_TOKEN for pid=``\ *PID*\ ``: no TPM on this agent``
  The server holds no TPM context, as under ``lota-agent --test-ipc``. The
  client gets ``LOTA_ERR_NO_TPM`` each round; ``--test-signed`` serves
  signed tokens (:doc:`../../agent/command-line`).

A refusal is written when the connection's answer changes, so a quiet
journal after one means it still stands (:doc:`../../agent/journal`).
