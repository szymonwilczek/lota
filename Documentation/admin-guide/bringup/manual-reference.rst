.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
Manual steps
============

The steps below meet the startup checks in :doc:`gate-matrix` by hand. On a
packaged host ``lota-install`` runs most of them and asks first
(:doc:`../lota-install`).

Enforcement key
===============

The agent package installs ``/usr/lib/lota/lota_lsm.bpf.o``, its signature
``lota_lsm.bpf.o.sig`` and the key that verifies it,
``/usr/lib/lota/enforcement.pub``, and an upgrade replaces the three
together. A packaged host needs nothing from this section.

A fleet that signs the object with its own key keeps the private half on a
signing host and installs the public half on each agent host:

.. code-block:: sh

   # on the signing host, once
   lota-agent --gen-signing-key ./enforcement
   # for each object
   lota-agent --sign-policy ./lota_lsm.bpf.o --signing-key ./enforcement.key

   # on each agent host
   sudo install -m 0644 enforcement.pub /etc/lota/policy.pub
   sudo install -m 0644 lota_lsm.bpf.o lota_lsm.bpf.o.sig /usr/lib/lota/
   lota-agent --verify-policy /usr/lib/lota/lota_lsm.bpf.o

The daemon takes the key from ``--policy-pubkey``, then ``policy_pubkey`` in
``lota.conf``, then ``/etc/lota/policy.pub``, then
``/usr/lib/lota/enforcement.pub``, the first it can read
(:doc:`../../agent/command-line`). No package owns
``/etc/lota/policy.pub``, so the key stays across upgrades, and the object
each upgrade installs has to be signed with it again.

In a build tree, ``make sign-bpf`` signs the object with ``SIGNING_KEY``,
``/etc/lota/policy.key`` by default, and copies ``SIGNING_PUBKEY``, the same
path ending in ``.pub``, to ``build/lota-enforcement.pub``, which ``make
install`` installs as ``/usr/lib/lota/enforcement.pub``.

``scripts/lota-dev-bringup.sh`` generates the key on the agent host
itself (:doc:`gate-matrix`). That key is readable by root on the host it
protects, so it is a development setup.

SELinux and the TPM device
==========================

``make install`` copies the policy module to
``/usr/share/lota/selinux/lota.pp`` and the udev rule to
``/usr/lib/udev/rules.d/99-lota-tpm.rules``; it loads neither:

.. code-block:: sh

   sudo semodule -i /usr/share/lota/selinux/lota.pp
   sudo udevadm control --reload-rules
   sudo udevadm trigger --action=add /dev/tpmrm0 /dev/tpm0
   sudo restorecon -R /usr/bin/lota-agent /etc/lota /var/lib/lota
   ls -Z /dev/tpmrm0 /dev/tpm0

The udev rule sets the label on an ``add`` event only; a ``trigger``
without ``--action=add`` sends ``change``, leaves ``tpm_device_t`` in place
and still exits 0. The daemon looks for ``lota_tpm_device_t`` in the
label.

Initramfs lock
==============

The dracut module ``90lota`` puts ``lota-pcr14-lock`` into the initramfs,
which extends PCR 14 before the agent starts (:doc:`../../agent/lifecycle`).
Every installed kernel needs it, since each one can be booted:

.. code-block:: sh

   sudo dracut -f --regenerate-all
   lsinitrd -f usr/lib/lota/lota-pcr14-lock \
       /boot/initramfs-$(uname -r).img | cmp - /usr/lib/lota/lota-pcr14-lock

A kernel installed later gets the helper from the module. An upgrade of the
helper reaches an existing image only when the image is built again. PCR 14
resets only at a cold boot, so the host needs one before the first start.

Kernel command line
===================

On a kernel that does not reach the floor on its own
(:doc:`../platform-support`):

.. code-block:: sh

   sudo grubby --update-kernel=ALL --args="lockdown=integrity module.sig_enforce=1"
   sudo reboot

IMA appraisal policy
====================

The daemon starts without IMA appraisal of executables; each token then
reports ``KERNEL_APPRAISAL`` clear, and a verifier policy with
``require_ima_appraisal`` refuses the host. The flag is set when both hold
(:ghsrc:`src/agent/bpf_loader.c`):

* The appraisal mode blocks. Under Secure Boot the kernel keeps its
  built-in mode, which blocks, and for ``off``, ``log`` or ``fix`` logs
  ``ima: Secure boot enabled: ignoring ima_appraise=... option``.
  Otherwise the last ``ima_appraise=`` on the command line before ``--``
  decides: ``off``, ``log`` and ``fix`` block nothing, and any other value
  or none leaves the default, ``enforce``.
* ``/sys/kernel/security/ima/policy`` has an ``appraise`` rule whose
  first ``func=`` is ``BPRM_CHECK``, or which has no ``func=``. Rules on
  ``FILE_CHECK``, ``MMAP_CHECK`` or ``CREDS_CHECK`` do not count, and an
  earlier ``dont_appraise`` rule is not read. The file reads only with
  ``CAP_SYS_ADMIN`` on a kernel built with ``CONFIG_IMA_READ_POLICY``; when
  it does not read, the flag stays clear.

LOTA ships no signatures and no production policy. A rule cannot name a
path, so a rule that appraises the agent appraises every executable it
matches, and a blocking mode refuses each one without a valid signature or
hash. The signatures come with the rules, from one of:

* packages carrying IMA signatures, with the distribution's IMA
  certificate on the ``.ima`` keyring; ``getfattr -m security.ima -d
  /usr/bin/lota-agent`` shows whether a file has one;
* an image pipeline that signs the executables (``evmctl ima_sign``) and
  puts its certificate on the ``.ima`` keyring.

With ``appraise func=POLICY_CHECK appraise_type=imasig`` loaded, which the
arch policy of a Secure Boot kernel can carry, the kernel takes only the
path of a signed policy file: rules written to
``/sys/kernel/security/ima/policy`` directly fail with ``Permission
denied``.

:ghsrc:`configs/ima/lota-ima-policy` is the policy
``scripts/lota-dev-bringup.sh`` loads on a host whose mode does not block.
It appraises every ``BPRM_CHECK`` and executable ``MMAP_CHECK`` outside the
pseudo file systems and tmpfs, with signatures required; under ``enforce``
on a host without signatures it refuses every exec.

Clearing the agent's state
==========================

Clearing the state destroys the host's attestation identity: the next start
creates a new AIK, and certificates for the old one stop matching. Stop
every unit that runs the agent first; ``lota-attest.service`` rewrites the
state each round.

.. code-block:: sh

   sudo systemctl stop lota-agent.service lota-agent.socket lota-attest.service
   # the host AIK at aik_handle, default 0x81010002
   sudo tpm2_evictcontrol -C o -c 0x81010002
   sudo find /var/lib/lota -mindepth 1 -maxdepth 1 \
       \( -name 'aik*' -o -name 'clock*' -o -name 'boot_commit*' \
          -o -name 'snapshot*' \) -delete
   sudo lota-agent --seal-evict-primary
   # each publisher's key and profile, as --list-publishers shows them
   sudo lota-agent --forget-publisher ID
   sudo reboot

The key and its record go together: a start that finds the AIK in the TPM
and no record refuses with exit status 78 (:doc:`../../agent/tpm`). The
stop spends PCR 14 for this boot, so the next start needs the reboot.
``scripts/lota-dev-bringup.sh --reset`` deletes the same files and evicts
the same keys, the AIK only when ``tpm2-tools`` is installed. It refuses
while the agent runs, leaves the publishers, and does not reboot
(:doc:`gate-matrix`).
