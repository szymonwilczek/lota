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
   * - lota-sdk
     - versioned SDK runtime libraries (gaming, anti-cheat, server, Proton hook)
     - MIT
   * - lota-sdk-devel
     - SDK headers, linker symlinks and Proton/Steam helpers (needs lota-sdk)
     - MIT

Only ``lota-agent`` is host-coupled (TPM, BPF, initramfs); the verifier and CA
can equally run as container images on a cluster. ``lota-sdk`` carries the
versioned shared libraries and ``lota-sdk-devel`` the headers and linker
symlinks to build against them -- together the integrator surface for building
on top of LOTA.

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

On RHEL-family hosts, enable EPEL before that command. The agent requires
``fsverity-utils`` to measure the objects a title maps, and el9 serves that
package from EPEL rather than from baseos, appstream or crb::

   sudo dnf install epel-release

The agent **fails closed** and is not started by the package. The post-install
hook runs ``lota-install --unattended``, which does the host-local half of
bring-up: it verifies the shipped BPF object against the public key beside it,
records that key in ``/etc/lota/lota.conf``, restores fs-verity on the binary
the package just wrote, and loads the SELinux fence. Each of those is
reversible and none of them changes how the machine boots.

What it deliberately leaves alone is the boot path -- the 90lota initramfs
module and the kernel integrity floor on the command line -- and it says so
before exiting. Finish with::

   sudo lota-install

The hook's failure is never the transaction's failure: the package installs
either way and the run reports what is left. A host that wants the boot-path
stages unattended as well opts in **before** installing, by creating
``/etc/lota/auto-bringup`` or setting ``LOTA_AUTO_BRINGUP=1``; that is the
image-build and managed-fleet case, where whoever builds the image is the
person making that decision.

The BPF object ships **signed** by whoever built the package, with the public
key at ``/etc/lota/policy.pub`` (a config file, so a fleet that re-signs with
its own key keeps its copy across upgrades). The agent refuses to load an
unsigned object, and nothing signs one on the player's machine.

Package upgrades follow the same rule and do not rewrite the boot path. An
agent upgrade still needs the initramfs and the PCR 14 commitment refreshed,
since the binary is measured; ``sudo lota-install`` after the upgrade does
that.
