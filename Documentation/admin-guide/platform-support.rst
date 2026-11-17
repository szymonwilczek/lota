.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

================
Platform support
================

The verifier and the attestation CA are Go services with no tie to the host
they run on; they ship as RPMs and as container images
(:doc:`container-images`). The agent drives the TPM, loads a BPF LSM object
and adds a dracut module to the initramfs, so it runs only where the
firmware, the kernel and the packaging meet the requirements below.

Minimal requirements
====================

.. list-table::
   :header-rows: 1
   :widths: 30 30 40

   * - Requirement
     - Minimum
     - Command to check
   * - Firmware
     - UEFI with Secure Boot on
     - ``mokutil --sb-state``
   * - TPM
     - TPM 2.0
     - ``ls /dev/tpmrm0``
   * - Kernel
     - 6.19
     - ``uname -r``
   * - Kernel lockdown
     - ``integrity``
     - ``cat /sys/kernel/security/lockdown``
   * - Module signatures
     - enforced
     - ``cat /sys/module/module/parameters/sig_enforce``
   * - Active LSMs
     - ``bpf`` in the list
     - ``cat /sys/kernel/security/lsm``
   * - Initramfs generator
     - dracut
     - ``dracut --version``

``lota-install`` checks the firmware and the TPM before it changes anything
(:doc:`lota-install`). The agent checks lockdown, module signatures and the
boot path every time it starts (:doc:`../agent/index`).

Distributions
=============

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Distribution
     - Tier
     - What runs there
   * - Fedora
     - Supported
     - CI builds the code and runs the unit tests on Fedora 43 and 44,
       builds the packages on Fedora 44, and loads the enforcement object
       through the kernel's BPF verifier on the Fedora kernel in a virtual
       machine (:ghsrc:`scripts/veristat-gate.sh`).
   * - RHEL, Rocky Linux, AlmaLinux
     - Unsupported
     - Their kernels are below the floor in `Kernel`_; CI does not build
       there.
   * - Debian, Ubuntu
     - Unsupported
     - They build the initramfs with ``initramfs-tools``; the dracut module
       ``90lota`` does not apply.
   * - Arch, SteamOS, image-based A/B systems
     - Unsupported
     - No packaging.

Kernel
======

Version
-------

The ``file_mprotect`` program hands the file of the mapping,
``vma->vm_file``, to ``bpf_get_fsverity_digest()``
(:ghsrc:`src/bpf/lota_lsm.bpf.c`). The BPF verifier accepts that only when
it trusts the pointer, and the kernel marks ``vm_file`` trusted from 6.19.
``bpf_get_fsverity_digest()`` itself first appeared in 6.8. When one
program of the object is refused, none of them loads, and the daemon start
ends with ``Failed to load BPF program``.

To check another kernel, boot it in a virtual machine and run
``scripts/veristat-gate.sh`` on the object as root.

Lockdown and module signatures
------------------------------

The daemon refuses to start with exit status 78 unless
``/sys/kernel/security/lockdown`` shows ``[integrity]`` or
``[confidentiality]`` and ``/sys/module/module/parameters/sig_enforce``
reads ``Y`` (:ghsrc:`src/agent/bpf_loader.c`). Under Secure Boot a kernel
with ``CONFIG_IMA_ARCH_POLICY`` enforces module signatures on its own; a
kernel that does not lock itself down under Secure Boot needs
``lockdown=integrity`` on the command line, and ``module.sig_enforce=1``
works the same for signatures. With Secure Boot on, the refusal names the
missing parameter; with it off, it points to the firmware setting.

Exec appraisal
--------------

When IMA does not appraise executables the daemon starts and logs ``Exec
appraisal is not established on this host``; every token then reports
``KERNEL_APPRAISAL`` clear (:doc:`lota-install`).

BPF LSM
-------

The kernel needs ``CONFIG_BPF_LSM`` and ``bpf`` in its active LSM list,
which the ``lsm=`` parameter sets when the built-in list lacks it, and BTF
at ``/sys/kernel/btf/vmlinux``.

Firmware and boot
=================

UEFI with Secure Boot
  The supported path. The verifier proves Secure Boot from the event log
  and can pin the first boot baseline on that proof (:doc:`../verifier/index`).
  The value PCR 14 holds before the initramfs lock, which shim's Machine
  Owner Key list goes into, is part of the commitment.

UEFI with Secure Boot off
  ``lota-install`` stops at its first stage with the steps to turn Secure
  Boot on. Setup mode and disabled shim validation stop it the same way. A
  host brought up by hand still needs the kernel floor above, and the
  verifier pins its first boot baseline only on a policy that pins PCR 0, 1
  and 7, a baseline already in its store, an operator re-anchor, or
  ``--allow-tofu-boot-baseline``. A policy with ``require_secureboot``
  refuses it.

Legacy BIOS or CSM
  Unsupported, since BIOS measures no EFI variable into the event log.
  ``lota-install`` stops at its first stage, the initramfs helper
  ``lota-pcr14-lock`` exits 13, the daemon logs ``This host cannot attest:
  it did not boot via UEFI.``, and the verifier answers ``pcr_fail``.

Registers a policy can pin
==========================

``lota-agent --export-policy`` writes PCR 0, 1, 4, 7 and 11
(:ghsrc:`src/agent/policy.c`). It leaves out:

PCR 8 and 9
  GRUB measures its commands into PCR 8 and the files it reads, ``grubenv``
  among them, into PCR 9, and it rewrites ``grubenv`` at boot. Two boots of
  one kernel can differ in both. The verifier checks the command line
  against the PCR 8 events and the kernel image against ``kernel_hashes``
  (:ghsrc:`policies/README.rst`).

PCR 14
  The verifier holds it per client, as the baseline of each host.

Independent of the policy, the verifier pins PCR 0, 1 and 7 and PCR 14 per
client. The kernel image goes into neither, so a kernel upgrade moves no
baseline; a policy that pins PCR 4 or lists kernel hashes needs the new
values. A change to the Machine Owner Keys moves PCR 14 and leaves PCR 7
as it was; the verifier re-pins it when the event log shows only that change
and the tenant allows self-service re-anchor (:doc:`../verifier/index`).
