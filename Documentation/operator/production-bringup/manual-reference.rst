.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============================
Manual reference: host gates
============================

This is the manual equivalent of the developer bring-up script: the host-side
gates an operator provisions before the agent will start. Attestation CA
enrollment and sealed keys are covered in their own documents
(:doc:`ca-enrollment`,
:doc:`sealed-keys`).

1. Operator key + signed BPF object
===================================

**A packaged host has this gate already.** The agent package installs
``lota_lsm.bpf.o``, its detached ``.sig`` and the key that signed it at
``/usr/lib/lota/enforcement.pub``, and an upgrade replaces all three together,
so the object on disk and the signature over it never disagree. Nothing below
is needed to start the agent; the rest of this section is the road a fleet
takes when it wants enforcement signed by its own key instead of the
packager's.

The signing key is generated and kept on the fleet's signing host -- never on
the host that runs the agent -- and only the public half travels:

.. code-block:: sh

    # on the signing host, once per fleet
    lota-agent --gen-signing-key ./enforcement        # enforcement.key + .pub
    lota-agent --sign-policy ./lota_lsm.bpf.o \
        --signing-key ./enforcement.key           # writes lota_lsm.bpf.o.sig

    # on each agent host: the public half, the object and the signature
    sudo install -d -m 0700 /etc/lota
    sudo install -m 0644 enforcement.pub /etc/lota/policy.pub
    sudo install -m 0644 lota_lsm.bpf.o /usr/lib/lota/lota_lsm.bpf.o
    sudo install -m 0644 lota_lsm.bpf.o.sig /usr/lib/lota/lota_lsm.bpf.o.sig

A key at ``/etc/lota/policy.pub`` is used without being named: the agent
prefers it over the key the package shipped, and no package owns that path, so
it survives every upgrade -- which also means putting a key there moves the
host off the packaged trust root, and the object must be re-signed with that
key after every agent upgrade that replaces it. ``policy_pubkey`` in
``/etc/lota/lota.conf`` (copy :ghsrc:`configs/lota.conf.example` and edit) is
only needed to name a key somewhere else. The agent reads that file by default;
pass ``--config /path`` if the operator policy lives elsewhere.

The ``make sign-bpf SIGNING_KEY=/path/to/enforcement.key`` target wires the
sign call into the build system for CI / packaging.

.. note::

   ``lota-install`` only verifies the signature; it never signs on the host,
   and it generates no key there either -- a signing key on the machine it
   protects lets local malware re-sign a tampered object, which is the whole
   reason the fleet key stays off it. The developer bring-up script
   :ghsrc:`scripts/lota-dev-bringup.sh` does generate one on the host: that is
   a development convenience and not a production path.

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

Verity is enabled once per inode and cannot be enabled twice, so on a binary
that already carries it ``enable`` exits non-zero with
``FS_IOC_ENABLE_VERITY failed on '/usr/bin/lota-agent': File exists``. That is
the armed state, not a failure; ``measure`` printing a digest is the check.
A re-install replaces the inode and the bit with it, which is why bring-up
runs ``enable`` on every pass.

If ``fsverity enable`` returns ``EOPNOTSUPP``, the filesystem has no verity
support. Production lays this down at install time via dracut + an
fs-verity-enabled rootfs.

The hash algorithm is the operator's choice: LOTA reads whichever digest the
kernel reports, SHA-256 (the ``fsverity enable`` default, and what the RPM
fs-verity plugin and composefs produce) or SHA-512
(``--hash-alg=sha512``). An allowlist entry matches only under the algorithm
it was captured with, so re-capture the digest after changing it -- and note
that the algorithm is fixed when verity is enabled, so changing it on an
existing file means writing a fresh copy of that file.

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
the kernel-floor.

Appraisal applies only to the ``func=`` rules the loaded policy contains, so a host
booted ``ima_appraise=enforce`` whose policy carries no ``appraise func=BPRM_CHECK``
rule appraises no executable at all.
The agent reads ``/sys/kernel/security/ima/policy`` as well and refuses to
start when the scope is empty, naming the rule it did not find. Where the
kernel was built without ``CONFIG_IMA_READ_POLICY`` that file cannot be read;
there the mode decides on its own and the agent logs, at startup, that the
scope went unverified.

.. code-block:: sh

    sudo grubby --update-kernel=ALL --args="ima=on ima_appraise=enforce"
    sudo reboot

**On a Secure Boot host the kernel discards that parameter.**
``default_appraise_setup()`` refuses to be told the mode where
``arch_ima_get_secureboot()`` is true, logging ``ima: Secure boot enabled:
ignoring ima_appraise=... option``, and leaves its built-in default, which
blocks. Since LOTA requires Secure Boot, that is the mode every supported host
appraises in: setting ``ima_appraise=fix`` there stages nothing, and the agent's
startup gate reads the loaded policy rather than the parameter for exactly that
reason. The staging advice below applies to a host booted without Secure Boot,
where the parameter is honoured.

The cmdline only sets the appraisal mode; the kernel still needs a loaded IMA
policy with ``appraise`` rules for anything to be checked. **The appraisal
content -- the signatures on disk and the rule set -- is distribution or
operator-supplied. LOTA ships neither an xattr-signing pipeline nor a production
appraisal policy**; what the agent checks is that the rule set in force reaches
executables at all, not where the signatures behind it came from.
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

A host whose loaded policy carries ``appraise func=POLICY_CHECK
appraise_type=imasig`` -- the arch policy a Secure Boot machine boots with --
appraises the policy buffer itself, so writing any unsigned rule set to
``/sys/kernel/security/ima/policy`` fails with ``Permission denied``: on such a
host the rule set has to be signed by a key on the ``.ima`` keyring. The
kernel's built-in ``ima_policy=appraise_tcb`` needs no policy write, but it is
not a way around the missing signatures either -- it appraises every root-owned
file, and on a Secure Boot host that runs in ``enforce`` (see below), so a
machine whose executables carry none stops booting.

``lota-install`` therefore reports the missing scope; it never widens one. A
rule set is loaded here by whoever owns the signatures.

**A host that appraises nothing still runs the agent**, as long as the agent
binary carries fs-verity: the kernel refuses a modified read of it and PCR 14
commits the running build, so the agent's own footing does not rest on IMA.
What is missing is coverage of everything else the machine executes, and that
travels rather than blocking -- ``LOTA_FLAG_KERNEL_APPRAISAL`` is clear in the
status word, the TPM-signed token and the attestation report, and a verifier
policy asks for it with ``require_ima_appraisal: true``. On a filesystem
without verity, where the binary's only claim is a signed ``security.ima``
xattr, appraisal is what makes that claim real and the agent refuses to start
without it.

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

The **type** is the check: ``lota_tpm_device_t`` is what the agent's gate looks
for. The SELinux user in front of it follows from how the file arrived --
``system_u`` on a device the policy labelled, ``unconfined_u`` on a file an
unconfined session installed -- and neither the gate nor ``restorecon`` treats
it as wrong.

5. AIK + PCR14 reset
====================

The initramfs helper first pins PCR14 with the LOTA lock, then the agent binds
PCR14 against its own ``self_hash`` once per boot. The TPM's clock counters
take no part in either digest: a TPM obfuscates them per signing key, so a
commitment that folded them in could only ever be rederived by one
publisher's AIK, and they are in every token the agent hands out anyway.

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
asks the same question during bring-up, before ``Initializing TPM``, so a slow,
absent or locked-out chip cannot delay the refusal. Self-measurement checks
again and returns ``ENOTSUP``. Every refusal names the absent
``/sys/firmware/efi``. Legacy BIOS/CSM is unsupported -- see
:doc:`../platform-support`. When the lock did not run this boot the agent says
so and names the fix: install the ``90lota`` dracut module, rebuild the
initramfs (``dracut -f --add lota`` for the booted kernel, or
``dracut -f --regenerate-all`` for every installed one) and cold reboot. It
recognises that case by the absence of the handoff file above, not by the
register's value -- on a shim host PCR14 holds the MOK measurement whether or
not the lock ran, so the value alone cannot tell a machine that needs its
initramfs rebuilt from one that was tampered with. The agent refuses to extend
a commitment onto an unlocked register either way, because the verifier
validates only the lock-then-commit chain.

The lock belongs in **every** installed kernel's initramfs, not only the
running one. The kernel command-line floor is armed on every boot entry, so a
kernel that can be selected from the boot menu without the lock boots a host
with no commitment; ``lota-install`` regenerates them all and reports the stage
unsatisfied while any installed kernel is missing the helper. A kernel
installed later picks the helper up from the packaged dracut module without
further action.

A MOK change (enrolling a key with ``mokutil``, a shim/SBAT update) shifts the
baseline and therefore the final PCR14, so an enrolled host reports an
``INTEGRITY_MISMATCH`` against its pinned baseline until an operator re-anchors
it -- the same review gate a firmware change goes through, since enrolling a MOK
key is a security-relevant boot-chain change. The agent therefore provisions its AIK before
``self_measure()`` runs; attestations issued before ``--enroll`` fall back to
the unauthenticated clock and must be rebound on the next start. A re-install
that changes either the initramfs helper or the agent binary without rebuilding
initramfs and cold-rebooting reports a PCR14 derivation mismatch or
``This is not the lota-agent build PCR 14 committed to when the host booted``.
Wipe the witness file and the persistent AIK, then reboot. **Stop every unit
that runs an agent, not only the daemon**: ``lota-attest.service`` runs
``lota-agent --attest`` and keeps the TPM clock witness current, so a wipe that
leaves it running deletes a file the next attestation round rewrites seconds
later.

.. code-block:: sh

    sudo systemctl stop lota-agent.service lota-agent.socket \
        lota-attest.service
    sudo find /var/lib/lota -mindepth 1 -maxdepth 1 \
        \( -name 'aik*' -o -name 'clock*' -o -name 'boot_commit*' \
           -o -name 'snapshot*' \) -delete
    # host that enrolled with publisher keeps that publisher's AIK in its profile;
    # wiping the key means wiping the enrollment with it
    sudo rm -rf /var/lib/lota/profiles
    # LOTA's handles only: AIK, seal primary, eight per-profile AIKs
    for h in 0x81010002 0x81010003 \
             0x81010010 0x81010011 0x81010012 0x81010013 \
             0x81010014 0x81010015 0x81010016 0x81010017; do
        sudo tpm2_evictcontrol -C o -c "$h" 2>/dev/null || true
    done
    sudo reboot

After reboot the agent's first start provisions a fresh AIK and extends PCR14
cleanly. Subsequent starts that follow a clean shutdown reuse the witness so the
gate is silent.
