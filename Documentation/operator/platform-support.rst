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
       module as the supported platform. The bring-up path is shared, not
       separately exercised on the platform.
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
       and install on an el9 userspace (the ``Packages`` workflow's Rocky 9
       job).
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
