.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===============
COPR repository
===============

Alongside the self-hosted dnf repository of nfpm-built binary packages, LOTA is
published through `COPR <https://copr.fedorainfracloud.org>`_. COPR rebuilds the
subpackages -- ``lota-agent``, ``lota-verifier``, ``lota-attest-ca``,
``lota-sdk`` and ``lota-sdk-devel`` -- from source in a clean chroot for each
target Fedora and EPEL release, validating the build across releases, and
hosts a signed dnf repository operators enable directly.

Installing
==========

::

   sudo dnf copr enable szymon-wilczek/lota
   sudo dnf install lota-agent

The agent still fails closed and is not started by the package. Complete the
host bring-up with ``lota-install`` as for any other install path; see
:doc:`production-bringup/index`.

Rebuilding from the source RPM
==============================

The COPR packages are built from ``packaging/rpm/lota.spec``, and the same
source RPM rebuilds anywhere. ``make srpm`` archives the current commit, fills
the spec's version and newest changelog entry from ``VERSION`` and builds the
source RPM; the spec in the tree carries placeholders and is not built with
``rpmbuild`` directly.

Three properties of the spec matter to a rebuild:

* **The builder signs the enforcement object.** ``lota-agent`` ships a BPF LSM
  object it refuses to load unsigned, and the public half of the key that
  verifies it ships beside it, so whoever builds the package is who signs it.
  The spec takes the key as a define and refuses before compiling anything
  without one::

     rpmbuild --rebuild --define "lota_signing_key /path/to/enforcement.key" \
         lota-<version>.src.rpm

  ``lota_signing_pubkey`` overrides where the public half is read from; by
  default it is the key's own path with a ``.pub`` suffix, which is where
  ``lota-agent --gen-signing-key`` writes it. Building the *source* RPM needs
  no key: ``make srpm`` compiles and signs nothing.
* **The build needs network access.** The Go services (verifier, attest-CA)
  are not vendored; ``%build`` fetches their modules read-only from the proxy.
* **No debuginfo subpackage.** ``debug_package`` is disabled because rpm's
  debuginfo extraction strips the binaries, but the agent binary is
  fsverity-measured and its hash is pinned, so it must ship exactly as built.

In a chroot build, rpmbuild's dependency generator derives the library
Requires from the binaries' sonames rather than listing them by hand as in the
nfpm path. The package contents are otherwise identical to the
nfpm packages.
