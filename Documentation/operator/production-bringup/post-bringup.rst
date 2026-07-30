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
  (must be ``Y``), and ``grep -oE 'ima_appraise=\w+' /proc/cmdline`` (must
  report ``enforce`` or ``fix``).
* ``Agent binary is not protected against offline tampering``. On
  ext4/btrfs/f2fs re-run ``fsverity enable`` on ``/usr/bin/lota-agent``; the
  verity merkle root is bound to the inode, so re-installs invalidate the bit
  and the bring-up script re-enables on every run. On XFS/ZFS (no verity)
  re-sign the binary into its ``security.ima`` xattr and confirm
  ``ima_appraise=enforce``; the agent accepts the signed xattr as equivalent.
* ``BPF object signature verification failed``. The ``.sig`` is from a different
  key. Re-sign with the key that ``policy_pubkey`` points at, or update
  ``policy_pubkey`` to match the signing key.
* ``Failed to load AIK metadata: Key has been revoked``. The TPM has a
  persistent AIK but the operator wiped ``/var/lib/lota``. Either restore the
  metadata backup or evict the AIK handle and reboot so the agent re-provisions
  clean.
* ``PCR14 holds an unexpected value``. Cold reboot. PCR14 only resets on
  hardware reset; warm reboot keeps the value. On UEFI Secure Boot this also
  appears when the ``90lota`` initramfs lock did not run: shim leaves the MOK
  measurement in PCR14, and without the lock recording that baseline at
  ``/run/lota/pcr14_baseline`` the agent cannot anchor its derivation. Confirm
  the dracut module is installed and the initramfs was rebuilt (see
  :doc:`manual-reference`, section 5), then cold reboot.

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

Operational constraints
=======================

Agent restart requires reboot
-----------------------------

The agent's ``lota_task_kill`` LSM hook blocks ``SIGTERM`` and ``SIGKILL``
delivered from any other task -- including PID 1 -- because the hook treats the
agent itself as a protected target. This is the load-bearing surface that
prevents a local-root attacker from killing the agent out of band, dropping the
BPF coverage, and swapping a tampered binary into place before the next
attestation.

The trade-off is that ``systemctl restart lota-agent`` does **not** work the way
it does for other units. After the stop request, the old process keeps running,
refuses to release ``/run/lota/lota.sock`` and the BPF maps, and the next
``ExecStart=`` fails with ``-EPERM`` when libbpf tries to recreate the same map
names. The unit then loops on ``Restart=on-failure`` while the original PID
stays alive forever.

Two supported paths exist:

#. **Graceful via IPC.** ``ExecStop=/usr/bin/lota-agent --shutdown`` sends a
   privileged IPC command to the running agent; the handler sets
   ``g_agent.running = 0``, which exits the daemon loop cleanly. As long as the
   IPC socket is reachable and the agent is not wedged in a syscall, this is the
   canonical update path and does not require a reboot.
#. **Cold reboot.** If the IPC path is unreachable (agent hang, socket gone,
   kernel deadlock) the only remaining recovery is to reboot the host. There is
   no kill-bypass for PID 1 and there never will be: every grace window would be
   an attack surface for an init-domain compromise. Operators planning updates
   therefore schedule them alongside a regular maintenance reboot.

Continuous attestation
----------------------

``lota-agent.service`` only enforces locally (BPF LSM, PCR14 commitment); it
does not attest. A deployed host proves its state through a second unit,
``lota-attest.service``, which runs ``lota-agent --attest`` fire-and-forget and
renews the CA-issued AIK certificate before it expires. It is a separate unit
on purpose: the attestation loop is network-facing, so isolating it from the
enforcement daemon keeps that security core on a tight seccomp and capability
profile. The attest unit itself runs with no effective capabilities at all
(``SecureBits=noroot-locked`` with an empty ambient set), reaches the TPM only
through ``DeviceAllow``, and cannot load BPF or disable enforcement. A
compromise of the attest process at worst stops fresh attestations, which the
verifier sees as staleness and marks untrusted.

The unit arms a 60 s systemd watchdog: the attest loop pings it on a cadence
independent of ``attest_interval``, so a loop wedged on the TPM or a stalled
TLS socket misses the deadline and systemd restarts it.

The verifier, port, CA certificate and cadence come from
``/etc/lota/lota.conf`` (``server``, ``port``, ``ca_cert``, ``attest_interval``);
no attestation flags are hardcoded in the unit. Keep ``attest_interval``
non-zero -- a zero interval attests once and exits. A non-zero value has to fall
between the floor and the ceiling the agent prints in ``--help``; the agent
refuses to start on anything else, since an interval past the ceiling mints
tokens that sit outside every relying party's freshness window.

``ca_cert`` must point at a path the hardened unit can read. The service runs
with ``ProtectHome=yes`` and ``ProtectSystem=strict``, so a certificate left in
an operator home directory (the ``--ca-cert ~/tls.crt`` used for a manual
``--enroll``) is invisible to it. Copy the verifier CA certificate under
``/etc/lota`` (root-owned, the unit mounts it read-only) and point ``ca_cert``
there, for example::

   sudo install -m 0644 verifier-ca.crt /etc/lota/verifier-ca.crt
   # then in /etc/lota/lota.conf: ca_cert = /etc/lota/verifier-ca.crt

A host that answers to more than one publisher lists them as ``[profile "name"]``
sections instead. Each section names the attestation CA it enrolls against, the
trust anchor that CA is verified with, the verifier it reports to, and
optionally its own cadence; ``ca_port`` and ``verifier_port`` default to the
same ports as the top-level keys. A profile missing the CA, the anchor or the
verifier is refused at load, and every anchor has to satisfy the same
readability constraint as the top-level ``ca_cert`` above.

Every key below a section header belongs to that section, so the top-level keys
go above the first profile and nothing top-level may follow one.
``lota-agent --dump-config`` prints profiles last for the same reason, which is
also what makes its output loadable again. See :ghsrc:`configs/lota.conf.example`
for a worked pair of profiles.

The section name is a label for the operator. A profile is identified by its
trust anchor's public key, so a publisher moving their CA to another address
keeps the same profile, and two publishers sharing a hostname cannot collide.
Publisher policy stays with the publisher: a profile grants no publisher any
say over this host's enforcement.

First enrollment stays operator-driven. ``lota-attest.service`` carries
``ConditionPathExists=/var/lib/lota/enroll_state.dat`` and stays inactive until
the operator's first ``lota-agent --enroll`` records that state; afterwards the
loop renews the certificate automatically. Start it after the first enrollment
(or it activates on the next boot):

.. code-block:: sh

   sudo systemctl enable --now lota-attest.service

Installing the package enables nothing. ``lota-install`` enables the units it
brings up -- the agent socket, the enforcement daemon and the attestation
loop -- so a host that has not been through bring-up runs neither, and a
``dnf install`` on a machine nobody is sitting at cannot start enforcing on
its own.

VM testing caveats
------------------

The supported development environment is a KVM guest with a swTPM backend
attached over TIS. Two behaviours diverge from bare metal and the agent's
startup gates treat them as integrity violations unless the operator works
around them.

* **swTPM persists state across guest reboots.** The TPM resource manager runs
  as a host process backed by an NV state file. A ``sudo reboot`` inside the
  guest does **not** reset the TPM and even
  ``sudo virsh destroy <machine> && sudo virsh start <machine>`` from the
  host keeps the same ``resetCount`` unless the libvirt XML carries
  ``<backend ... persistent_state='no'/>`` or swTPM is started with
  ``--flags startup-clear``. The guest's PCR14 resets to all-zero on each
  Startup(CLEAR) but ``resetCount`` does not advance; the agent's witness records
  the old ``(resetCount, last_extend)`` tuple and the next start reports
  ``PCR14 cleared while resetCount=N unchanged since last extend``. Before each
  test run on a guest without that XML setting, wipe the witness and evict the
  persistent AIK:

  .. code-block:: sh

      sudo systemctl stop lota-agent.service lota-agent.socket
      sudo find /var/lib/lota -mindepth 1 -delete
      for h in 0x81010002 0x81010003 0x81010004 0x81010005; do
          sudo tpm2_evictcontrol -C o -c "$h" 2>/dev/null || true
      done

* **The repo is virtiofs-mounted read-only at** ``/mnt/<dir>``. ``sudo make
  install`` recurses into the ``all`` target through the
  ``install: check-version-tag all`` prerequisite, so ``make`` will try to write
  dependency files to ``build/`` in the current working directory and fail with
  ``EROFS`` on the virtiofs mount. Pass the build directory explicitly on the
  same invocation:

  .. code-block:: sh

      sudo make BUILD_DIR=/var/tmp/lota-build install

* ``sudo make install`` **does not load the SELinux module.** The install rule
  lands ``lota.pp`` under the source tree but does not call ``semodule -i``.
  After any change to :ghsrc:`selinux/lota.te`, rebuild the module on the host (the
  in-tree :ghsrc:`selinux/Makefile` writes to ``tmp/`` in the cwd, which the
  read-only virtiofs blocks), then load the package inside the guest:

  .. code-block:: sh

      # [host]
      cd selinux && make && sha256sum lota.pp
      # [guest]
      sudo semodule -i /mnt/<dir>/selinux/lota.pp

  Verify the rule landed with ``sesearch -A -s lota_agent_t ...`` before
  retrying the agent. The stock policy ``dontaudit``\ s many reads that the
  agent legitimately needs (e.g. kallsyms, securityfs), so denials may be
  silent: run ``sudo semodule -DB`` before reproducing to surface them, then
  ``sudo semodule -B`` to re-enable.

* ``/usr/bin/lota-agent`` **must carry** ``lota_agent_exec_t``. A fresh
  ``make install`` writes the file with the default ``bin_t`` label on systems
  where the in-tree ``lota.fc`` has not been loaded yet; without the executable
  type, ``init_t`` does not transition to ``lota_agent_t`` at exec and the daemon
  runs with no TPM, BPF, or ``/etc/lota`` access. Restore the label after
  install:

  .. code-block:: sh

      sudo restorecon -v /usr/bin/lota-agent
      ls -lZ /usr/bin/lota-agent
      # expect: system_u:object_r:lota_agent_exec_t:s0
