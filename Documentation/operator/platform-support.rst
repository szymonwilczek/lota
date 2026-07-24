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
       commits the boot state to PCR 14 and passes its TPM attestation. The
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
       self-report.
   * - UEFI without Secure Boot
     - The agent runs, but the firmware root of trust is weaker. Pass
       ``lockdown=integrity`` on the kernel command line so the BPF-load gate is
       satisfied (see :doc:`production-bringup/gate-matrix`).
   * - Legacy BIOS
     - The agent runs with a reduced PCR set: without shim there is no PCR 14
       MOK baseline and no Secure Boot event-log evidence, so the boot
       commitment starts from a zero baseline.

TPM
===

The agent requires a **TPM 2.0**. Production hosts use a hardware TPM --
a discrete TPM (dTPM) or a firmware TPM (fTPM / Intel PTT). The documented
development environment is a KVM guest with a swTPM backend over TIS; its two
divergences from hardware (persistent state across guest reboots, and a quote
clock quirk) and the operator workarounds are covered under
:doc:`production-bringup/post-bringup`.
