.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================================
Startup gate matrix and automated bring-up
==========================================

Startup gate matrix
===================

The agent's startup chain refuses to load BPF / attach LSM programs unless
every entry below is satisfied. Source references are ``file::line`` into the
current tree.

.. list-table::
   :header-rows: 1
   :widths: 28 32 40

   * - Gate
     - Check site
     - Operator action
   * - ``lockdown=integrity`` (or confidentiality)
     - ``src/agent/bpf_loader.c::kernel_lockdown_restrictive()``
     - Boot under Secure Boot or pass ``lockdown=integrity`` on the kernel
       cmdline.
   * - ``module.sig_enforce=1``
     - ``src/agent/bpf_loader.c::kernel_module_sig_enforced()``
     - Fedora 44 ships this by default. On distros that do not, add
       ``module.sig_enforce=1`` to the cmdline.
   * - IMA appraisal in an enforcing mode
     - ``src/agent/bpf_loader.c::kernel_ima_appraise_enforcing()``
     - Add ``ima_appraise=enforce`` (or ``fix``) to the kernel cmdline. ``log``
       and the default ``off`` do not satisfy the gate.
   * - ``/dev/tpm{rm,}0`` carries ``lota_tpm_device_t``
     - ``src/agent/bpf_loader.c::tpm_device_selinux_label_ok()``
     - Install the udev rule under :ghsrc:`configs/udev/99-lota-tpm.rules` (handled by
       ``make install``) and run
       ``udevadm trigger --action=add /dev/tpmrm0 /dev/tpm0``.
   * - Kernel-enforced immutability of ``/usr/bin/lota-agent``
     - ``src/agent/bpf_loader.c::agent_self_immutability_enforced()``
     - fs-verity OR a signed ``security.ima`` xattr. On ext4/btrfs/f2fs run
       ``fsverity enable /usr/bin/lota-agent`` (or let bring-up do it); on
       XFS/ZFS sign the binary (``evmctl ima_sign``) under
       ``ima_appraise=enforce``.
   * - BPF object Ed25519 signature
     - ``src/agent/bpf_loader.c::verify_bpf_object_signature()``
     - Ships signed: the agent package carries ``lota_lsm.bpf.o``, its
       ``.sig`` and the public key at ``/usr/lib/lota/enforcement.pub``, all
       replaced together on upgrade. A fleet that signs enforcement itself
       re-signs the object and puts its key at ``/etc/lota/policy.pub``, which
       the agent prefers over the packaged one.
   * - BPF object built for this agent
     - ``src/agent/bpf_loader.c::bpf_loader_check_object_integrity_layout()``
     - The agent reads the object's ``integrity_cfg`` map into a struct whose
       size is compiled in, and the kernel copies the map's own value size on
       every access, so the two have to come from the same release. A fleet
       that keeps its own signed object re-builds and re-signs it from the
       release it is upgrading the agent to; the refusal names both layouts
       and happens before PCR 14 is extended, so a mismatch costs a failed
       start.
   * - AIK persistent handle + metadata in sync
     - ``src/agent/tpm.c::tpm_aik_load_metadata()``
     - Evict any stale persistent handle (``tpm2_evictcontrol``) before first
       start so the AIK metadata is initialised cleanly.
   * - PCR14 fresh after boot
     - ``src/agent/tpm.c::tpm_extend_boot_commitment()``
     - Cold reboot before the first agent start; PCR14 only resets on hardware
       reset.

Every gate maps to a ``lota_err()`` line in the journal when it fails, so
``journalctl -u lota-agent`` is the canonical debugging surface.

If the BPF library refuses to open the object, attach a program or set up the
event ring, the agent stops without recording enforcement as loaded. The
journal holds the library's message above the agent's line naming the call; a
refusal that leaves ``errno`` unset is reported as a fixed error, never as a
load.

A kernel floor gate (lockdown, module signatures, appraisal scope) is a state
of the host, so the agent exits with a status listed in
``RestartPreventExitStatus`` and ``lota-agent.service`` stays ``failed``, with
the line naming the missing gate last in the journal. Fix the host (often a
firmware setting) before restarting the unit.

The refusal names the lever this host has. With Secure Boot off, that is
Secure Boot itself, a firmware setting; ``lota-install --status`` prints the
route to this machine's setup screen. With Secure Boot on and a gate still
unmet, the kernel was built or booted without that state, and the refusal
names the command-line parameter that raises it. A host refused on the floor
is not told to correct its policy: the only edit that would let it start drops
the requirement.

What the mode decides
=====================

The strict flags (``strict_mmap``, ``strict_exec``, ``block_ptrace``,
``strict_modules``, ``block_anon_exec`` and their command-line forms) apply in
``mode = enforce`` only. In ``monitor`` and ``maintenance`` each gate returns
early: the agent starts, reports the flag as on and blocks nothing.

``lota-agent --dump-config`` lists the keys the mode leaves inert::

   mode = monitor
   # mode = monitor leaves inert: strict_mmap, block_ptrace, block_anon_exec
   # each of those gates returns early outside enforce mode, so the
   # key records a protection this host is not applying

and the agent logs the same list at startup, beside its ``Mode:`` line. A host
meant to enforce that shows either is in the wrong mode.

Automated developer bring-up
============================

``scripts/lota-dev-bringup.sh`` runs the steps above in a fixed order:

.. code-block:: sh

    sudo make install                                           # land agent + BPF + units + SELinux module
    sudo scripts/lota-dev-bringup.sh                            # gate the host
    sudo reboot                                                 # PCR14 baseline rebind
    sudo systemctl start lota-agent.socket lota-agent.service
    sudo systemctl status lota-agent.service --no-pager

Every step checks for the artefact it would produce and prints whether it ran
or skipped, so a re-run on a host that is already gated changes nothing. What
a run writes it keeps: nothing here rolls back, and a run that fails part-way
leaves what it had already done for the next run to pick up from.

Clearing the agent state under ``/var/lib/lota`` and the persistent handles in
the TPM is the one step that is not repeatable, because it destroys the host's
attestation identity -- the agent provisions a fresh key on the next start, and
anything holding a certificate for the old one is talking about a key that no
longer exists. It happens only under ``--reset``, and ``--reset`` refuses while an agent is
running -- either because ``lota-agent.service`` is active, or because the pid
file under ``/run/lota`` names a process that is still alive, which is the
state a host is left in when the agent refuses the stop. Read the script
before running it.
