.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===============
COPR repository
===============

Alongside the self-hosted dnf repository of nfpm-built binary packages, LOTA is
intended to be published through `COPR
<https://copr.fedorainfracloud.org>`_. COPR would rebuild the subpackages --
``lota-agent``, ``lota-verifier``, ``lota-attest-ca``, ``lota-sdk`` and
``lota-sdk-devel`` -- from source in a clean chroot for each target Fedora and
EPEL release, which both validates the build across releases and hosts a signed
dnf repository operators can enable directly.

.. note::

   The COPR project is not published yet, so the commands below do not work
   today. The spec (``packaging/rpm/lota.spec``) and the ``.copr/Makefile``
   entry point are in the tree, so the project is ready to be created; until
   then, build from source with ``make srpm`` or use the self-hosted signed
   :doc:`dnf-repo`.

Installing (once the project is published)
==========================================

The COPR project will live under the ``szymon-wilczek`` COPR account (which is
distinct from the ``szymonwilczek`` GitHub handle)::

   sudo dnf copr enable szymon-wilczek/lota
   sudo dnf install lota-agent

The agent still fails closed and is not started by the package. Complete the
host bring-up with ``lota-install`` as for any other install path; see
:doc:`production-bringup/index`.

How it is built
===============

COPR invokes ``make -f .copr/Makefile srpm``, which delegates to the top-level
``make srpm`` target. That archives the current commit, fills the version and
the newest changelog entry of ``packaging/rpm/lota.spec`` from the ``VERSION``
file and builds a source RPM; COPR then rebuilds it in the chroot. The same
``make srpm`` runs locally for a quick check. The spec in the tree carries
placeholders and is not built with ``rpmbuild`` directly.

Three properties of the spec matter:

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
  no key -- ``make srpm`` compiles and signs nothing -- so the key is a property of
  the rebuild, and a COPR project has to carry one before it can produce
  packages.
* **External network must be enabled** on the COPR project. The Go services
  (verifier, attest-CA) are not vendored, so the workspace build fetches their
  modules read-only from the proxy during ``%build``.
* **No debuginfo subpackage.** ``debug_package`` is disabled because rpm's
  debuginfo extraction strips the binaries, but the agent binary is
  fsverity-measured and its hash is pinned, so it must ship exactly as built.

Because the chroot build runs rpmbuild's automatic dependency generator, the
library Requires are derived from the binaries' sonames rather than listed by
hand as in the nfpm path. The package contents are otherwise identical to the
nfpm packages; COPR is the from-source, multi-release mirror of the same
deliverables.
