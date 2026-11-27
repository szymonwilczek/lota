.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===============
COPR repository
===============

`COPR <https://copr.fedorainfracloud.org>`_ builds the five packages of
:doc:`packages` from the source RPM in a clean chroot and serves them as a
dnf repository:

.. code-block:: sh

   sudo dnf copr enable szymon-wilczek/lota
   sudo dnf install lota-agent

The install runs the same scripts as any other (:doc:`packages`); bring-up
ends with ``sudo lota-install`` (:doc:`lota-install`).

The source RPM
==============

COPR runs ``make -f .copr/Makefile srpm outdir=DIR``, which runs ``make
srpm OUTDIR=DIR`` (:ghsrc:`.copr/Makefile`). ``make srpm``:

#. runs ``make check-package-manifests``, which fails when the spec and the
   nfpm configurations describe different packages
   (:ghsrc:`scripts/check-package-manifests.sh`, checks listed in
   :doc:`../dev-tools/testing`);
#. archives ``HEAD`` with ``git archive``;
#. fills the spec's ``@VERSION@`` and ``@CHANGELOG@`` from ``VERSION``, the
   version ``0.9.0-rc1`` becoming ``0.9.0~rc1``;
#. builds the source RPM with ``rpmbuild -bs`` into ``OUTDIR``,
   ``build/srpm`` by default.

:ghsrc:`packaging/rpm/lota.spec` carries the placeholders, so ``rpmbuild``
does not build it directly. The source RPM is built without a key and
compiles nothing.

Rebuilding
==========

.. code-block:: sh

   rpmbuild --rebuild --define "lota_signing_key /path/to/enforcement.key" \
       lota-VERSION.src.rpm

``%build`` refuses before compiling without ``lota_signing_key``, and signs
the enforcement object with ``make sign-bpf``. The public half is read from
the key's path ending in ``.pub``, or from ``lota_signing_pubkey``.

The Go modules of the verifier and the CA are not vendored: ``%build``
fetches them from the module proxy, so the chroot needs network access.

Debuginfo extraction and the strip steps are off, since each rewrites ELF
files: the verifier pins the SHA-256 of the agent binary and the object is
signed. ``%check`` verifies the packaged object against the packaged key
and compares the packaged ``lota-agent`` with the built one.

rpmbuild derives the library dependencies from the sonames of the binaries;
the nfpm configurations list them by hand.
