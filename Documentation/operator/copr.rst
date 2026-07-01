.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===============
COPR repository
===============

Alongside the self-hosted dnf repository of nfpm-built binary packages, LOTA is
published through `COPR <https://copr.fedorainfracloud.org>`_. COPR rebuilds
the same four subpackages -- ``lota-agent``, ``lota-verifier``,
``lota-attest-ca`` and ``lota-sdk-devel`` -- from source in a clean chroot for
each target Fedora and EPEL release, which both validates the build across
releases and hosts a signed dnf repository operators can enable directly.

Installing
==========

::

   sudo dnf copr enable szymonwilczek/lota
   sudo dnf install lota-agent

The agent still fails closed and is not started by the package. Complete the
host bring-up with ``lota-install`` as for any other install path; see
:doc:`production-bringup/index`.

How it is built
===============

COPR invokes ``make -f .copr/Makefile srpm``, which delegates to the top-level
``make srpm`` target. That archives the current commit, drops it into
``packaging/rpm/lota.spec`` and builds a source RPM; COPR then rebuilds it in
the chroot. The same ``make srpm`` runs locally for a quick check.

Two properties of the spec matter:

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
