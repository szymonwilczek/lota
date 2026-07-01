.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=============
RPM packages
=============

LOTA ships as native RPMs so a host does not have to reproduce the build
toolchain. The packages are built with `nfpm <https://nfpm.goreleaser.com>`_
from the configs under ``packaging/nfpm`` and target the RPM/dracut family
(Fedora first, then RHEL/Rocky/Alma). Debian/Ubuntu use a different initramfs
generator and are handled separately.

The packages
============

.. list-table::
   :header-rows: 1
   :widths: 20 55 25

   * - Package
     - Contents
     - License
   * - lota-agent
     - agent, BPF LSM object, PCR14 initramfs helper, 90lota dracut module,
       systemd/dbus/udev integration, lota-install
     - MIT AND GPL-2.0-only
   * - lota-verifier
     - the verifier service binary
     - MIT
   * - lota-attest-ca
     - the attestation CA service binary
     - MIT
   * - lota-sdk-devel
     - SDK headers and shared libraries, Proton/Steam helpers
     - MIT

Only ``lota-agent`` is host-coupled (TPM, BPF, initramfs); the verifier and CA
can equally run as container images on a cluster. ``lota-sdk-devel`` is the
integrator surface for building on top of LOTA.

Building
========

::

   make packages

builds every RPM under ``build/packages`` (``PKG_DIR``), each named from the
project version. The target depends on a full build so the configs find the
binaries and libraries they reference. ``rpmlint`` then runs over the built
RPMs when it is installed, reporting any packaging warnings.

Installing
==========

Once the packages are served from a signed dnf repository::

   sudo dnf install lota-agent

The agent **fails closed** and is not started by the package: a fresh install
only places files and refreshes systemd. Complete the host bring-up with::

   sudo lota-install

which signs the BPF object with the host's signing key, installs the 90lota
module into the initramfs and arms the PCR14 boot commitment. The package ships
the BPF object **unsigned** on purpose -- each adopter signs it with their own
key during bring-up, and the agent refuses to load an unsigned object.

Package upgrades deliberately do not rewrite the boot path; re-run the
documented bring-up after an agent upgrade (the agent binary is measured, so a
new binary needs the initramfs and PCR14 commitment refreshed).
