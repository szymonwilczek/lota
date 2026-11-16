.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============================================
What still fails, and operational constraints
=============================================

What still fails after bring-up
===============================

The most common failures, with the gate that produced them:

* ``Kernel anti-tamper prerequisites are not satisfied``. Check
  ``cat /sys/kernel/security/lockdown`` (must show ``[integrity]`` or
  ``[confidentiality]``), ``cat /sys/module/module/parameters/sig_enforce``
  (must be ``Y``), and the ``/dev/tpmrm0`` SELinux label (``ls -Z``, must
  carry ``lota_tpm_device_t``).
* ``BPF object signature verification failed``. The object and the key no
  longer belong to each other. A ``policy_pubkey`` line naming a file that is
  no longer there does not cause this: the agent treats a key that has stopped
  resolving as absent and falls back, so a host an older installer configured
  keeps enforcing after an upgrade moved the key. The packaged key at
  ``/usr/lib/lota/enforcement.pub`` always matches the packaged object, so this
  means a key at ``/etc/lota/policy.pub`` (or one named by ``policy_pubkey``)
  is taking precedence and did not sign this object: move it aside to fall back
  to the packaged one, or re-sign the object with the fleet key.
* ``The attestation key at 0x`` *handle* ``has no record``. The TPM has a
  persistent AIK but its record, ``aik_meta.dat`` in ``/var/lib/lota`` or in
  the publisher's profile, is gone. The agent and ``lota-agent --attest`` exit
  with status 78, so their units are not restarted. Restore the record and the
  authorization file the line names from a backup, or run ``lota-agent
  --reprovision-aik`` to write a new record and authorization for the key.
* ``PCR14 holds an unexpected value``. Cold reboot. PCR14 only resets on
  hardware reset; warm reboot keeps the value. On UEFI Secure Boot this also
  appears when the ``90lota`` initramfs lock did not run: shim leaves the MOK
  measurement in PCR14, and without the lock recording that baseline at
  ``/run/lota/pcr14_baseline`` the agent cannot anchor its derivation. Confirm
  the dracut module is installed and the initramfs was rebuilt (see
  :doc:`manual-reference`, section 4), then cold reboot.
* ``The agent is paused on this host``. Its boot commitment was spent by a
  shutdown requested here -- ``lota-agent --shutdown``, ``lota-install
  --pause``, or a ``systemctl stop`` that ran the unit's ``ExecStop``. PCR 14
  cannot be re-extended once poisoned, which is what makes a pause visible to
  every relying party. Reboot to attest again.
  ``lota-steam-setup --register-uid`` deliberately does **not** stop the agent
  for this reason: its setting takes effect at the next boot, and the command
  says so before it edits the configuration.
* ``Startup policy refused before the boot commitment was spent``. A path or
  PID named by the enforcement policy could not be resolved -- most often a
  ``--trust-lib`` or ``--allow-verity`` path the unit's sandbox hides, since
  ``ProtectSystem=strict`` and ``PrivateTmp=yes`` mean the agent does not see
  ``/tmp`` or ``/var/tmp`` the way the shell that wrote the drop-in does. The
  message names the path. Nothing has been spent: PCR 14 still holds the
  initramfs lock value, so correcting the policy and starting the unit again
  brings the host up in the same boot, with no reboot needed.
* ``No process is running under PID <n>, so there is nothing to protect``. A
  ``--protect-pid`` or ``protect_pid =`` entry names a process that is not up.
  The protected set is seeded at startup from processes that already exist, so
  a pid recorded before a restart is stale by the time the agent reads it. This
  refusal also arrives before the boot commitment, so the host keeps its
  attestation; a process that starts after the agent registers itself through
  the SDK, with ``lota_protect_self()``, and needs no entry here at all.
* ``Refusing GET_TOKEN for pid=<pid>: no TPM on this agent``. The agent holds
  no TPM context, so it has nothing to sign a token with, and it never issues
  an unsigned one -- a token nobody signed is not evidence. The SDK is
  answered ``LOTA_ERR_NO_TPM``, and no retry changes it.
  ``--test-ipc`` runs in exactly this state on purpose: it serves
  status, D-Bus and profile binding on a machine with no TPM -- both servers
  resolve ``SET_PROFILE`` against the publishers the configuration they were
  started with names, and say how many they bound -- and a title that needs a
  token there uses ``--test-signed`` instead. Both serve the simulated
  attested verdict they announce: the publishers they bound carry it, and a
  host that configures none is answered under one synthetic publisher no
  client can select. Neither reads the host's configuration to do it, so a
  ``/etc/lota/lota.conf`` this user cannot open is reported and stepped over;
  ``--config`` names a file that must load. Neither server enforces anything,
  so ``PROTECT_PID`` is refused there with
  ``LOTA_IPC_ERR_NO_ENFORCEMENT`` (``LOTA_ERR_NO_ENFORCEMENT`` in the SDK):
  runtime PID policy is a change to what the enforcement object holds, and only
  a daemon that applied a startup policy has one.
* ``This is not the lota-agent build PCR 14 committed to when the host
  booted``. The binary being run is not the one the register commits to, which
  is the expected answer after replacing the binary without rebooting, or when
  running a second build by hand. Install the build and cold reboot; PCR 14 is
  not rewritable while the host is up. This is a refusal by design, not a TPM
  fault.
* ``PCR14 no longer holds the value lota-agent extended in this boot session``.
  Something outside the agent extended PCR 14. Cold reboot, then audit what
  reached ``/dev/tpmrm0``.
* ``the baseline handoff at /run/lota/pcr14_baseline is not the one this
  commitment was built on``. PCR 14 and the binary match the record; the
  handoff the ``90lota`` initramfs lock writes once per boot was replaced. Cold
  reboot to have it written again. If the refusal survives the reboot, PCR 14
  was extended and ``/var/lib/lota/clock_state.dat`` rewritten to match (the
  evidence is identical): audit what can write ``/run/lota`` and
  ``/var/lib/lota``.
* ``This publisher's attestation key was created before each publisher got a
  key of its own``. The host was enrolled by a build that gave every publisher
  the same TPM key. A key cannot be rewritten in place, so the agent refuses
  to attest with it and the fix is one command per publisher:
  ``sudo lota-agent --reenroll --publisher <their ID>``. The attestation
  key is not part of the device ID, so the CA certifies the new key under the
  existing one and each verifier keeps the baseline it holds.
  Nothing has been spent: the refusal happens before the boot commitment, so
  the host comes up in the same boot once the enrollment is done.

A refused token request is written when the connection's answer changes,
not every round: as it first stands, when the reason changes, and when the
connection is answered again, with the number of rounds the refusal held.
Repeats are reported at shutdown as ``Token answer reports: repeated=``.

A journal quiet after a refusal means the refusal still stands; the client
gets the same error every round. A new connection writes its own line.

The unit does not restart into any refusal above that stops the agent from
starting: the agent exits 78 (``EX_CONFIG``) for a state only an operator can
clear, and ``RestartPreventExitStatus=78`` leaves the unit failed with the
reason in the journal. Every PCR 14 refusal is such a state -- the register
is not rewritable while the host is up, so the answer is the same on every
attempt -- and each attempt that was made anyway opened the TPM, provisioned
the AIK and bound the container socket before reaching it.

Counters printed by these messages come from ``TPM2_ReadClock`` and are the
values ``tpm2_readclock`` reports, so they can be checked against the machine.
That is also where the agent takes the counters it records for itself, the
ones that tell a restart within a boot from a hardware reset. Counters carried
by a quote will not match them, and are not meant to: a TPM offsets ``clock``,
``resetCount`` and ``restartCount`` in a signed attestation by an amount unique
to the signing key, so with per-publisher keys there is no single quoted
reading to compare against. Nothing binds either reading into PCR 14 -- the
boot commitment names the agent binary alone -- so the counters are diagnostic
here, not evidence.

Threat model implications of the dev path
=========================================

``scripts/lota-dev-bringup.sh`` lays down a self-signed operator key on disk in
``/etc/lota``. That key is the trust root for every BPF object the agent loads
on this host. An attacker with root can re-sign a tampered BPF object with the
same key and the agent will accept the load.

Production deployments treat the signing key as a sealed infrastructure
artefact: kept off-host, rotated through the operator's PKI, and never present
in ``/etc/lota`` on a live machine. The bring-up script's key generation is
explicitly developer-only.
