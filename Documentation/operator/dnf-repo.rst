.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================
Signed dnf repository
=====================

Self-hosted channel serves the nfpm-built binary RPMs from a signed dnf
repository the project controls end to end. Both the packages and the
repository metadata are GPG-signed, so a client verifies each package
(``gpgcheck``) and the repository index itself (``repo_gpgcheck``).

This is the channel the project hosts directly; the Fedora COPR repository is
the from-source alternative.

The signing key
===============

Use a **dedicated RPM signing key**, separate from any commit-signing key, kept
offline and secret. Generate one once::

   gpg --quick-generate-key "LOTA Package Signing <packages@lota.example>" \
       ed25519 sign never

Only the public key is published (in the repository); the private key never
enters the tree and signs only at release time.

Publishing
==========

After building the packages with ``make packages``::

   make dnf-repo \
       LOTA_RPM_GPG_NAME="LOTA Package Signing" \
       LOTA_REPO_BASEURL="https://lota.example/rpm"

This signs every RPM in ``PKG_DIR``, runs ``createrepo_c`` into ``REPO_DIR``,
writes a detached signature over ``repomd.xml``, exports the public key as
``RPM-GPG-KEY-lota`` and renders ``lota.repo`` with the base URL. Serve the
``REPO_DIR`` tree unchanged at that URL over HTTPS. The signing key's passphrase
must be reachable through ``gpg-agent`` when the target runs.

Installing
==========

Point dnf at the repository and import the key::

   sudo dnf config-manager --add-repo https://lota.example/rpm/lota.repo
   sudo rpm --import https://lota.example/rpm/RPM-GPG-KEY-lota
   sudo dnf install lota-agent

With ``gpgcheck`` and ``repo_gpgcheck`` both on, dnf refuses any package or
metadata that the key did not sign. Complete the agent bring-up with
``lota-install`` as on any other install path.
