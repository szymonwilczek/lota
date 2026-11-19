.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===================
Reproducible builds
===================

A release is built so that a checkout of its tag, built again with the same
toolchain, gives the same bytes. The release workflow
(:ghsrc:`.github/workflows/release.yml`) hashes the artifacts into a
``SHA256SUMS`` manifest and signs the manifest with cosign, so a user can
check that the artifacts came from the tag and from that workflow.

The build
=========

.. code-block:: console

   $ make reproducible-build

builds ``make all`` with three variables exported
(:ghsrc:`Makefile`):

``SOURCE_DATE_EPOCH``
  ``REPRO_SOURCE_DATE_EPOCH`` when it is set, in a checkout or outside
  one; otherwise the commit time of ``HEAD``. Without either the target
  stops::

     reproducible-build: no commit time to read and REPRO_SOURCE_DATE_EPOCH is unset.

``TZ``
  ``UTC``.

``LC_ALL``
  ``C``.

It ends with::

   Reproducible build complete (SOURCE_DATE_EPOCH=..., TZ=UTC, LC_ALL=C)

The container image targets take the same ``SOURCE_DATE_EPOCH``
(:doc:`../admin-guide/container-images`).

Timestamps
----------

No source embeds the time of the build: nothing uses ``__DATE__`` or
``__TIME__``, and no code reads ``SOURCE_DATE_EPOCH``.

Absolute paths
--------------

C and BPF objects are compiled with ``-ffile-prefix-map=$(CURDIR)=.``, and
the Go binaries with ``-trimpath``, so the directory of the checkout leaves
no trace in the output.

Version control
---------------

``go build`` stamps each Go binary with the commit it was built from: the
revision, the commit time, and whether the tree had changes. ``go version
-m`` prints the stamp:

.. code-block:: console

   $ go version -m build/lota-verifier | grep vcs
           build   vcs=git
           build   vcs.revision=...
           build   vcs.time=...
           build   vcs.modified=false

A tree with an untracked or changed file is stamped ``vcs.modified=true``.
``build/`` is ignored by git, so a build into it leaves the stamp at
``false``; a ``BUILD_DIR`` outside ``.gitignore`` does not. A tree with no
git checkout, such as an extracted source archive, gets no stamp, and its Go
binaries differ from the release. ``make`` rebuilds a Go binary only when
its sources change, so a binary keeps the stamp of the build that wrote it;
a check starts from an empty ``build/``.

Version
-------

``lota-agent``, ``lota-install``, the four shared libraries and the 32-bit
hook carry the version from ``VERSION``. ``LOTA_VERSION_STRING`` on the
``make`` command line replaces it, and changes their bytes.
``lota-pcr14-lock``, the Go binaries and the BPF object carry no version.

Toolchain
=========

The output depends on the compiler, the linker, Go and libbpf, so a rebuild
uses the versions the release used. The release workflow builds on GitHub's
``ubuntu-24.04`` runner with the distribution's GCC, Clang and LLVM, libbpf
v1.4.6 built from source and the newest Go 1.26 release from the Go
project. A distribution's build of the same Go release is another toolchain:
``go version`` names its experiments after the version, such as
``X:nodwarf5``. The released files name the compiler and Go versions:

.. code-block:: console

   $ readelf -p .comment lota-agent
   $ go version lota-verifier

The BPF object carries no ``.comment``; its Clang is the one of the runner
image, which the workflow run log names.

On x86_64, ``make all`` builds the 32-bit half of the Wine hook when the
compiler links a ``-m32`` program. That needs a 32-bit C library and
``libatomic``: on Ubuntu ``gcc-multilib``, on Fedora ``glibc-devel.i686``
and ``libatomic.i686``. Without them the build ends with::

   note: the 32-bit half of the Wine hook needs a multilib toolchain (...); this tree cannot be installed as it is

and gives no ``build/lib32/liblota_wine_hook.so``, so the manifest's 32-bit
hook cannot be checked.

CI builds every pull request and every push to ``main`` and ``lota-next``
twice into ``build/``, from two paths and in two time zones, hashes the
files of the manifest in both and compares the hashes. A Go binary not
stamped ``vcs.modified=false`` fails the job
(:ghsrc:`.github/workflows/reproducible-builds.yml`, :doc:`../dev-tools/ci`).

Reproducing a release
=====================

Build the tag in a fresh clone, into ``build/``, and copy the files of the
manifest into ``build/release``:

.. code-block:: console

   $ git clone https://github.com/szymonwilczek/lota.git
   $ cd lota
   $ git checkout vVERSION
   $ make reproducible-build
   $ make release-stage

The release workflow runs ``make check-version-tag`` before the build. On a
commit with a tag, it stops when ``VERSION`` is not the tag without its
``v``::

   ERROR: VERSION (...) does not match current git tag ...

The manifest names twelve files: ``lota-agent``, ``lota-install``,
``lota-verifier``, ``lota-attest-ca``, ``lota-pcr14-lock``,
``liblotagaming.so``, ``liblotaserver.so``, ``liblota_wine_hook.so``,
``liblota_anticheat.so``, ``lota_lsm.bpf.o``, ``liblota_wine_hook-i386.so``
and ``VERSION``. The release workflow stages and hashes the same list,
``RELEASE_ARTIFACTS`` in the :ghsrc:`Makefile`. ``make release-stage``
empties ``build/release`` and copies each file there under its manifest
name: the 32-bit hook from ``build/lib32/liblota_wine_hook.so``, ``VERSION``
from the top of the tree. It stops when a file is missing, and on x86_64
when the compiler cannot link a ``-m32`` program. Check the hashes there:

.. code-block:: console

   $ cd build/release
   $ sha256sum -c /path/to/SHA256SUMS

``make release-manifest`` stages the files and writes their hashes to
``build/SHA256SUMS`` in the format of the release manifest.

Verifying the signature
=======================

The release workflow signs ``SHA256SUMS`` with cosign without a key, under
the workflow's GitHub identity. ``SHA256SUMS.cosign.bundle``, attached to
the release, carries the signing certificate and the proof of its entry in
the Rekor transparency log:

.. code-block:: console

   $ cosign verify-blob \
         --bundle SHA256SUMS.cosign.bundle \
         --certificate-identity-regexp \
           '^https://github\.com/szymonwilczek/lota/\.github/workflows/release\.yml@refs/tags/v' \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com \
         SHA256SUMS

A valid signature says that the release workflow, run for a ``v`` tag,
produced the manifest. Verify it before checking the artifacts against the
manifest.

Scope
=====

The manifest covers the twelve files above. Other jobs of the same
workflow attach the packages and the Helm chart to the release, and push
the container images to ``ghcr.io``:

Packages
  Built in a ``fedora:44`` container with ``make all``, not
  ``reproducible-build``, so their binaries are not the ones the manifest
  lists. The job signs the BPF object with the project's enforcement key
  (``make sign-bpf``) and the packages and repository with its GPG key
  (:doc:`../admin-guide/dnf-repo`).

Container images
  Built with ko and signed with cosign under the same identity, and not
  attached to the release (:doc:`../admin-guide/container-images`). The
  ``lota-attest-ca`` of the manifest is built without PKCS#11 and loads its
  signing key from a file only; the ``-hsm`` tag of the ``attestca`` image
  carries the PKCS#11 build (:doc:`ca-key`).

Helm chart
  Packaged, pushed to ``ghcr.io`` and attached to the release, unsigned
  (:doc:`../admin-guide/helm-chart`).

The release has no ``lota_lsm.bpf.o.sig``. The agent loads the BPF object
only with a signature its enforcement key verifies (:doc:`../bpf/index`), so
a deployment that installs the manifest's object signs it with its own key,
``make sign-bpf`` (:doc:`../admin-guide/packages`).
