.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================
Signed dnf repository
=====================

``https://lota.szymon-wilczek.me/rpm`` serves the nfpm packages of the
newest release (:doc:`packages`). The packages and the repository metadata
are signed with the project's GPG key, and :ghsrc:`packaging/repo/lota.repo.in`
sets ``gpgcheck=1`` and ``repo_gpgcheck=1``, so dnf refuses a package or an
index that key did not sign. :doc:`copr` builds the same packages from the
source RPM.

Installing
==========

On Fedora:

.. code-block:: sh

   sudo dnf config-manager addrepo \
       --from-repofile=https://lota.szymon-wilczek.me/rpm/lota.repo
   sudo dnf install lota-agent

dnf offers to import ``RPM-GPG-KEY-lota`` from the repository on first use;
``sudo rpm --import https://lota.szymon-wilczek.me/rpm/RPM-GPG-KEY-lota``
imports it beforehand. Bring-up ends with ``sudo lota-install``
(:doc:`lota-install`).

Building the repository
=======================

.. code-block:: sh

   make dnf-repo LOTA_RPM_GPG_NAME=KEY-ID

``make dnf-repo`` signs the RPMs in ``build/packages`` (``PKG_DIR``) with
``rpmsign --addsign``, copies them to ``build/dnf-repo`` (``REPO_DIR``),
runs ``createrepo_c``, signs ``repodata/repomd.xml`` into
``repomd.xml.asc``, exports the public key as ``RPM-GPG-KEY-lota``, and
writes ``lota.repo`` with ``LOTA_REPO_BASEURL`` as ``baseurl`` and
``gpgkey``. It refuses without ``LOTA_RPM_GPG_NAME`` and builds no
packages: ``make packages`` comes first.

The release workflow publishes the tree as ``lota-dnf-repo-VERSION.tar.gz``
beside the RPMs, and the documentation deploy unpacks the newest release's
tarball under ``/rpm``. ``SHA256SUMS-fedora``, attached to the same
release, hashes the files of each RPM
(:doc:`../security/reproducible-builds`).

Mirroring
=========

The tarball is the whole repository. The signatures do not depend on the
address, so a mirror serves the tree as it is and changes ``baseurl`` and
``gpgkey`` in ``lota.repo``, or builds it with its own
``LOTA_REPO_BASEURL``.
