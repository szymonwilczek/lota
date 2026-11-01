.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================
Signed dnf repository
=====================

The project's dnf repository at ``https://lota.szymon-wilczek.me/rpm`` serves
each release's binary RPMs. Both the packages and the repository metadata are
GPG-signed, so a client verifies each package (``gpgcheck``) and the
repository index itself (``repo_gpgcheck``).

The Fedora :doc:`copr` repository is the from-source alternative.

Installing
==========

Point dnf at the repository and import the key::

   sudo dnf config-manager --add-repo https://lota.szymon-wilczek.me/rpm/lota.repo
   sudo rpm --import https://lota.szymon-wilczek.me/rpm/RPM-GPG-KEY-lota
   sudo dnf install lota-agent

With ``gpgcheck`` and ``repo_gpgcheck`` both on, dnf refuses any package or
metadata that the key did not sign. Complete the agent bring-up with
``lota-install`` as on any other install path.

Mirroring
=========

The repository is a plain directory tree: the RPMs, ``repodata/`` with its
detached ``repomd.xml.asc``, ``RPM-GPG-KEY-lota`` and ``lota.repo``, shipped
with each release as ``lota-dnf-repo-<version>.tar.gz``. The signatures hold
at any address, so a mirror serves the tree unchanged and rewrites only the
``baseurl`` and ``gpgkey`` lines of ``lota.repo``.
