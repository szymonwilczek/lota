.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============================
Manual reference: host gates
============================

This is the manual equivalent of the developer bring-up script: the host-side
gates an operator provisions before the agent will start. Attestation CA
enrollment and sealed keys are covered in their own documents
(:doc:`ca-enrollment <ca-enrollment>`,
:doc:`sealed-keys <sealed-keys>`).

1. Operator key + signed BPF object
===================================

.. code-block:: sh

    sudo install -d -m 0700 /etc/lota
    sudo /usr/bin/lota-agent --gen-signing-key /etc/lota/policy
    sudo chmod 0600 /etc/lota/policy.key
    sudo chmod 0644 /etc/lota/policy.pub
    sudo /usr/bin/lota-agent --sign-policy /usr/lib/lota/lota_lsm.bpf.o \
        --signing-key /etc/lota/policy.key

Add ``policy_pubkey = /etc/lota/policy.pub`` to ``/etc/lota/lota.conf`` (or copy
:ghsrc:`configs/lota.conf.example` and edit). The agent reads this file by default;
pass ``--config /path`` if the operator policy lives elsewhere.

The ``make sign-bpf SIGNING_KEY=/etc/lota/policy.key`` target wires the sign
call into the build system for CI / packaging.

.. note::

   The agent package ships ``lota_lsm.bpf.o`` **unsigned** on purpose, so each
   operator signs it with their own key. **Upgrading the package replaces the
   object and invalidates the previous signature** -- re-run the
   ``--sign-policy`` step above after every ``lota-agent`` package upgrade, then
   re-run ``lota-install`` to confirm the operator-trust stage. ``lota-install``
   only verifies the signature; it never signs on the host (a locally generated
   key would let local malware re-sign a tampered object).

2. Kernel-enforced immutability of the agent binary
===================================================

The agent refuses to start unless the kernel will reject a modified read of
``/usr/bin/lota-agent``, so a binary swapped while the host is offline is
caught at the next boot. Two mechanisms satisfy this, and the agent accepts
**either** (``agent_self_immutability_enforced()``):

**fs-verity** -- ext4, btrfs, f2fs and recent XFS:

.. code-block:: sh

    # ext4 needs the feature enabled at mkfs time
    # or via `sudo tune2fs -O verity /dev/sdX` on an unmounted device.
    # btrfs / f2fs ship verity in 5.15+.
    sudo fsverity enable /usr/bin/lota-agent
    sudo fsverity measure /usr/bin/lota-agent

If ``fsverity enable`` returns ``EOPNOTSUPP``, the filesystem has no verity
support. Production lays this down at install time via dracut + an
fs-verity-enabled rootfs.

**Signed IMA xattr** -- any filesystem with a ``security`` xattr namespace,
including XFS and ZFS where fs-verity is unavailable. Under
``ima_appraise=enforce`` (see section 3) the kernel refuses to exec or read a
file whose content does not match the hash signed in its ``security.ima``
xattr by a key on the ``.ima`` keyring, which is the same offline-swap
guarantee:

.. code-block:: sh

    # sign the binary; load the matching cert onto the .ima keyring
    sudo evmctl ima_sign --key /etc/keys/ima.key /usr/bin/lota-agent
    getfattr -m security.ima -d /usr/bin/lota-agent   # verify present

Bare (unsigned) digest does **not** count -- attacker who swaps the binary
offline can recompute it. The agent and the installer accept only a
signature-type ``security.ima`` xattr.

3. IMA appraisal policy
=======================

The agent parses ``/proc/cmdline`` and refuses to start unless
``ima_appraise=enforce`` (block on integrity failure) or ``ima_appraise=fix``
(block on signature failure, write missing xattrs) is present.
``ima_appraise=log`` and the default ``off`` are non-blocking and do not satisfy
the kernel-floor. The check does not read
``/sys/kernel/security/ima/policy`` because that file is write-only on kernels
built without ``CONFIG_IMA_READ_POLICY`` (Fedora 44's default).

.. code-block:: sh

    sudo grubby --update-kernel=ALL --args="ima=on ima_appraise=enforce"
    sudo reboot

The cmdline only sets the appraisal mode; the kernel still needs a loaded IMA
policy with ``appraise`` rules for anything to be checked. **The appraisal
content -- the signatures on disk and the rule set -- is distribution or
operator-supplied. LOTA ships neither an xattr-signing pipeline nor a production
appraisal policy**, and the kernel-floor check in the agent pins only the mode.
On a verity-capable rootfs LOTA's own binary is integrity-bound through
fs-verity and the PCR14 boot commitment independently of IMA appraisal; on a
filesystem without verity (XFS, ZFS) the signed ``security.ima`` route from
section 2 is what binds the agent binary instead. Two supported routes for the
appraisal content:

#. **Distribution signatures.** On Fedora/RHEL, packages can carry IMA file
   signatures applied at install time (``rpm-plugin-ima``, with the
   distribution's IMA certificate loaded onto the ``.ima`` keyring) and the
   built-in ``ima_policy=appraise_tcb`` cmdline policy appraises the TCB ranges
   against them. Verify the signatures actually exist
   (``getfattr -m security.ima -d /usr/bin/lota-agent``) before enabling
   ``enforce``.
#. **Operator image pipeline.** Deployments that build their own images sign
   executables at image-build time (``evmctl ima_sign --key <operator key>``
   over the executable closure) and load the matching certificate onto the
   ``.ima`` keyring (on a Secure Boot host, via a MOK-enrolled certificate). The
   policy and key lifecycle are owned by the image pipeline, not by LOTA.

Sequencing either route: ``ima_appraise=enforce`` with ``appraise`` rules loaded
blocks every execution the rules match that lacks a valid signature -- on a
rootfs without signatures that bricks the host at the next boot. Stage with
``ima_appraise=fix`` for one boot (the kernel writes missing xattrs as it walks
matched files) before switching to ``enforce``.

The shipped :ghsrc:`configs/ima/lota-ima-policy` is the **developer baseline** that
``scripts/lota-dev-bringup.sh`` loads on a dev host running ``ima_appraise=log``:
it measures every exec/mmap for the IMA log and its ``appraise_type=imasig``
rules verify signatures where they exist. IMA rules cannot match by path, so it
is not a "LOTA-only" policy -- do not load it under ``enforce`` on a host without
signatures.

4. SELinux label on /dev/tpm
============================

The udev rule from :ghsrc:`configs/udev/99-lota-tpm.rules` lays this down on
device-add. After ``make install``:

.. code-block:: sh

    sudo udevadm control --reload-rules
    sudo udevadm trigger /dev/tpmrm0 /dev/tpm0
    ls -lZ /dev/tpm0 /dev/tpmrm0                # expect lota_tpm_device_t

5. AIK + PCR14 reset
====================

The initramfs helper first pins PCR14 with a counter-stable LOTA lock, then the
agent binds PCR14 against ``(self_hash, resetCount, restartCount)`` once per
boot. The counters are obtained through a TPM2_Quote with an empty PCR selection
so the value extended into PCR14 matches the clockInfo carried by the later
attestation quote even on TPM 2.0 simulators (swtpm) whose ``Esys_ReadClock``
and ``Quote.clockInfo`` disagree.

PCR14 is not pristine on every platform. On UEFI Secure Boot, shim measures
the MOK state (``MokList``, ``SbatLevel``, ``MokListRT``) into PCR14 before the
initramfs runs, so the register is already non-zero when the lock helper
extends it. The helper therefore folds whatever PCR14 holds -- the *baseline*
-- into the chain instead of requiring ``0^32``, and records it at
``/run/lota/pcr14_baseline`` (raw 32 bytes, on the ``/run`` tmpfs that survives
the initramfs handoff). The agent reads that file so its derivations anchor on
the same baseline, and the verifier reconstructs the baseline independently by
replaying the signed TPM event log -- the LOTA extends happen after
ExitBootServices and never enter that log, so the log's PCR14 events are exactly
the firmware/shim baseline. A UEFI host that boots without shim measures nothing
into PCR14, so its baseline is legitimately ``0^32`` and the chain anchors on
zero. Because the verifier derives the baseline from the signed log, a forged
``/run`` handoff cannot move trust: it only makes the host fail closed.

Both halves of that chain are mandatory, and both refuse a non-UEFI host before
touching the TPM: the initramfs helper exits non-zero (which aborts the boot
transition, its unit is ordered before ``initrd-root-fs.target``) and the agent
returns ``ENOTSUP`` from its self-measurement, each naming the absent
``/sys/firmware/efi``. Legacy BIOS/CSM is unsupported -- see
:doc:`../platform-support`. If PCR14 still holds the bare baseline when the
agent runs, the initramfs lock did not run: install the ``90lota`` dracut
module, ``dracut -f --add lota``, and cold reboot. The agent refuses to extend
a commitment onto an unlocked register, because the verifier validates only the
lock-then-commit chain.

A MOK change (enrolling a key with ``mokutil``, a shim/SBAT update) shifts the
baseline and therefore the final PCR14, so an enrolled host reports an
``INTEGRITY_MISMATCH`` against its pinned baseline until an operator re-anchors
it -- the same review gate a firmware change goes through, since enrolling a MOK
key is a security-relevant boot-chain change. The agent therefore provisions its AIK before
``self_measure()`` runs; attestations issued before ``--enroll`` fall back to
the unauthenticated clock and must be rebound on the next start. A re-install
that changes either the initramfs helper or the agent binary without rebuilding
initramfs and cold-rebooting reports a PCR14 derivation mismatch or
``PCR14 holds a boot commitment from a different agent binary``. Wipe the
witness file and the persistent AIK, then reboot:

.. code-block:: sh

    sudo systemctl stop lota-agent.service lota-agent.socket
    sudo find /var/lib/lota -mindepth 1 -maxdepth 1 \
        \( -name 'aik*' -o -name 'clock*' -o -name 'boot_commit*' \
           -o -name 'snapshot*' \) -delete
    for h in 0x81010002 0x81010003 0x81010004 0x81010005; do
        sudo tpm2_evictcontrol -C o -c "$h" 2>/dev/null || true
    done
    sudo reboot

After reboot the agent's first start provisions a fresh AIK and extends PCR14
cleanly. Subsequent starts that follow a clean shutdown reuse the witness so the
gate is silent.
