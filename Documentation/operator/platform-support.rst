.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

================
Platform support
================

LOTA has two halves with different platform coupling. The **verifier** and
**attestation CA** are distro-independent Go services: they run from the native
RPMs or the distroless container images on any Linux the container or binary
targets, and platform support does not constrain them. The **agent** is coupled
to the host: it drives the TPM, loads a BPF LSM program, and installs an
initramfs module, so its support is defined per distribution family, firmware
and TPM. The tables below describe the agent.

Support tiers
=============

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Tier
     - Meaning
   * - Supported
     - The full bring-up and attestation path runs on the platform, and it is
       the reference environment the packaging and documentation describe.
   * - Experimental
     - The packages build and install from the same nfpm configs and dracut
       module as the supported platform, and the packaging is exercised there
       in CI. Parts of the bring-up path may be verified on the platform, but
       it is not the reference environment and a capability the supported
       platform has may be missing -- the row says which.
   * - Unsupported
     - The platform needs packaging or a boot-integration model LOTA does not
       carry. The agent has no path there.

Distributions
=============

.. list-table::
   :header-rows: 1
   :widths: 26 30 16 28

   * - Distribution family
     - Packaging
     - Tier
     - Notes
   * - Fedora
     - RPM + dracut ``90lota``
     - Supported
     - The reference agent platform. Fedora 44 ships ``module.sig_enforce=1``
       and the kernel lockdown the startup gates require.
   * - RHEL / Rocky / AlmaLinux (el9+)
     - RPM + dracut ``90lota`` (same nfpm configs)
     - Experimental
     - The RPM/dracut family the agent targets beyond Fedora. The RPMs build
       and install on el9 and el10 userspaces, and on el10 the agent enrolls,
       commits the boot state to PCR 14 and passes its TPM attestation. On el9
       the agent's ``fsverity-utils`` dependency is served by EPEL rather than
       the distribution, so that repository has to be enabled first. The
       BPF LSM does not arm on the el-family kernels, however -- see the
       Kernel section below -- so runtime enforcement stays a Fedora-class
       capability there.
   * - Debian / Ubuntu
     - separate ``initramfs-tools`` packaging
     - Unsupported
     - A different initramfs generator than dracut; the ``90lota`` module does
       not apply.
   * - Arch / SteamOS / immutable (A/B) distributions
     - none
     - Unsupported
     - A different update and root-filesystem model than the packaged
       bring-up assumes.

Kernel
======

The agent's BPF LSM enforcement needs a kernel new enough for its
``file_mprotect`` gate. That gate reads the mapped file through
``vm_area_struct::vm_file`` and hands it to the fs-verity digest kfunc, which
the verifier only accepts when the pointer is trusted. The kernel began marking
that field access trusted around **6.18**; measured with ``veristat`` against
live kernels, 6.17 rejects the program and 6.19 accepts it. The RHEL-family
kernels are below that floor -- el9 ships 5.14 (which additionally lacks the
fs-verity kfunc entirely) and el10 ships 6.12, where 12 of the 13 programs
verify and only ``file_mprotect`` is rejected. Because one rejected program
fails the whole object, the LSM does not load. The agent still enrolls,
commits PCR 14 and completes its TPM attestation on those kernels; only the
runtime BPF-LSM layer is unavailable. Lowering that layer to make the object
load on an older kernel is not offered: runtime enforcement requires a
Fedora-class kernel, not a reduced program set.

Firmware and boot
=================

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Boot path
     - Behaviour
   * - UEFI + Secure Boot
     - The reference target. shim measures the MOK state into PCR 14 before the
       initramfs, and the boot commitment is baseline-aware over it (see
       :doc:`production-bringup/ca-enrollment`). The verifier replays the TPM
       event log and establishes Secure Boot from the log rather than the
       self-report. A boot chain without shim (own PK/KEK/db, a directly signed
       systemd-boot or UKI) measures nothing into PCR 14; the boot commitment
       then chains onto a zero baseline, which is supported.
   * - UEFI without Secure Boot
     - The agent runs, but the firmware root of trust is weaker. Pass
       ``lockdown=integrity`` on the kernel command line so the BPF-load gate is
       satisfied (see :doc:`production-bringup/gate-matrix`).
   * - Legacy BIOS / CSM
     - **Unsupported.** BIOS measures neither the firmware and Secure Boot
       state the verifier pins nor an EFI variable the event log can carry, so
       a BIOS host cannot produce the evidence an attestation is built from.
       The installer refuses such a host, the initramfs helper refuses to lock
       PCR 14 on it, the agent refuses to form a boot commitment, and the
       verifier rejects the report. Switch the firmware out of legacy/CSM mode
       and reinstall.

TPM
===

The agent requires a **TPM 2.0**. Production hosts use a hardware TPM --
a discrete TPM (dTPM) or a firmware TPM (fTPM / Intel PTT). The documented
development environment is a KVM guest with a swTPM backend over TIS; its two
divergences from hardware (persistent state across guest reboots, and a quote
clock quirk) and the operator workarounds are covered under
:doc:`production-bringup/post-bringup`.

Runtime measurement coverage
============================

Every token folds a kernel-anchored measurement of the live code of each
protected process, and that measurement can cover an object only when the
kernel holds an fs-verity digest for it. What a platform provides therefore
decides how much of a process's code the measurement can account for.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Platform
     - Coverage
   * - A title's own binaries
     - Full, on any verity-capable filesystem. Whoever ships the title
       enables it, with ``lota-install --verity-manifest`` or the
       equivalent in their own packaging. The agent refuses a token when a
       protected process's own executable carries no digest.
   * - Distribution libraries on a package-managed host
     - **None, today.** Fedora ships ``libc``, ``libcurl`` and the rest
       without fs-verity, so those objects are absent from the fold and the
       token reports partial coverage
       (``LOTA_FLAG_IMAGE_FULLY_MEASURED`` clear). Enabling verity on them
       by hand lasts until the next update of the owning package, which
       replaces the inode and the digest with it. Whether partial coverage
       is acceptable is the relying party's policy.
   * - Image-based and composed filesystems
     - Not consumed yet. An image-based host (composefs, an OSTree
       deployment, a dm-verity root) already carries per-file or
       whole-image integrity, and consuming that as measurement evidence
       would give full coverage without per-file enablement. LOTA does not
       read those sources today; a protected process on such a host reports
       coverage over whatever fs-verity digests are present.

A relying party that requires full coverage asks for
``LOTA_FLAG_IMAGE_FULLY_MEASURED`` and, on a package-managed host, will not
get it. That is a statement about the platform, not about the machine
concealing anything: an unmeasurable object is reported as unmeasured and is
never folded in as though it had been measured.
