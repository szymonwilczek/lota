.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

============
RPM packages
============

``make packages`` builds five RPMs with `nfpm <https://nfpm.goreleaser.com>`_
from the configurations in :ghsrc:`packaging/nfpm`.
:ghsrc:`packaging/rpm/lota.spec` builds packages of the same names that
install the same files, for COPR (:doc:`copr`). Their dependencies differ.
The nfpm configurations name the libraries by hand: ``lota-agent`` requires
``tpm2-tss``, ``libbpf``, ``openssl-libs``, ``libseccomp`` and ``systemd``
beside the requirements in the table, ``lota-sdk`` requires
``openssl-libs``, ``lota-attest-ca`` requires ``glibc`` 2.34 or newer, and
``lota-verifier`` requires nothing. The spec leaves the libraries to the requirements rpmbuild
generates from the binaries and requires ``systemd`` for the agent's
scriptlets through ``%{?systemd_requires}``. Both require
``pkgconfig(libcrypto)`` for ``lota-sdk-devel``.

The packages
============

.. list-table::
   :header-rows: 1
   :widths: 20 55 25

   * - Package
     - Contents
     - License
   * - ``lota-agent``
     - ``lota-agent``, ``lota-install``, ``lota-protect``,
       ``lota-proton-hook`` and ``lota-steam-setup``; the signed enforcement
       object and its key; ``lota-pcr14-lock`` and the dracut module
       ``90lota``; the systemd units, the sysusers fragment, the D-Bus
       policy, the udev rule, the SELinux module and the IMA policy example.
       Requires ``lota-sdk`` of the same version and ``dracut``.
     - MIT AND GPL-2.0-only
   * - ``lota-verifier``
     - ``lota-verifier``.
     - MIT
   * - ``lota-attest-ca``
     - ``lota-attest-ca``.
     - MIT
   * - ``lota-sdk``
     - The versioned shared libraries of the gaming, server and anti-cheat
       SDKs and the Wine hook, and a 32-bit Wine hook in ``/usr/lib``.
     - MIT
   * - ``lota-sdk-devel``
     - The headers in ``/usr/include/lota``, the unversioned ``.so`` links
       and the pkg-config files. Requires ``lota-sdk`` of the same version.
     - MIT

The verifier and the CA also run as container images
(:doc:`container-images`).

Building
========

.. code-block:: sh

   make sign-bpf SIGNING_KEY=release.key
   make packages SIGNING_KEY=release.key

``make packages`` builds from ``./build`` and refuses another
``BUILD_DIR``. It refuses without ``build/lota_lsm.bpf.o.sig`` or a readable
``SIGNING_PUBKEY``, by default the path of ``SIGNING_KEY`` ending in
``.pub``, since the package ships the object with its signature and the key
that verifies it (:doc:`bringup/manual-reference`). It writes the RPMs to
``build/packages`` (``PKG_DIR``) and ends with ``make package-lint``, which
runs ``rpmlint`` with :ghsrc:`packaging/nfpm/lota.rpmlintrc` and fails on an
error that file does not filter. Without ``rpmlint`` the lint is skipped.

Installing
==========

.. code-block:: sh

   sudo dnf install lota-agent

After the files are in place the post-install script creates the ``lota``
group, reloads the SELinux module when one is loaded, relabels
``/etc/lota`` with ``restorecon -R``, and runs ``lota-install
--unattended``, whose exit status it ignores. That run leaves the initramfs
lock and the kernel integrity floor to ``sudo lota-install``, unless
``/etc/lota/auto-bringup`` exists or ``LOTA_AUTO_BRINGUP=1`` is set, and it
starts the units only when no stage is left ("Package installs" in
:doc:`lota-install`).

An upgrade runs the same script and leaves the running units alone; the new
agent takes effect at the next cold boot (:doc:`agent-update`).

State
=====

``lota-agent`` owns ``/etc/lota`` (0755), ``/var/lib/lota`` and
``/var/lib/lota/profiles`` (0700); ``lota-verifier`` owns ``/var/lib/lota``
(0700) as well. No package owns the files in them: ``lota.conf``,
``/etc/lota/policy.pub``, the AIK records and authorization files, the clock
state and the publisher profiles. They stay on removal and reinstall, as do
the TPM's persistent objects. "Clearing the agent's state" in
:doc:`bringup/manual-reference` removes them.

Removing ``lota-agent`` stops and disables ``lota-agent.service``,
``lota-agent.socket`` and ``lota-attest.service``. The stop extends PCR 14,
so the host attests again only after a reboot with the package installed.
