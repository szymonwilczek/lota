.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

================
Container images
================

The two server-side services, the verifier and the attestation CA, ship as
OCI container images so the relying-party tier can be deployed without
reproducing the host build toolchain on every distribution. The on-host agent
is **not** containerised: it touches the TPM, the kernel BPF LSM and the
initramfs, and stays a native package.

The images are plain OCI artifacts. They are built with `ko
<https://ko.build>`_, not a Dockerfile, and the build pipeline does not need
the Docker daemon. An operator can run the published image with Podman or
Docker -- the artifact is the same either way.

What is in the image
====================

Both services build as pure-Go static binaries (``modernc.org/sqlite``,
``jackc/pgx`` -- no cgo), so the default image of each is the binary on the
**nonroot distroless static** base: no shell, no libc and no package manager,
which keeps the CVE surface that enterprise scanners report close to zero. The
service therefore runs as an unprivileged user, and any writable state must be
supplied through a mounted volume.

The attestation CA ships as two images. The default tag carries the pure-Go
build described above, whose only signing key is an on-disk PEM -- the
development fallback. A production CA holds its key in a PKCS#11 token, and
that path is a cgo build that dlopens the vendor's module, so it cannot live
on a base with no loader. It ships as the ``-hsm`` variant tag of the same
repository::

   ghcr.io/szymonwilczek/lota/attestca:<version>        pure-Go, static, on-disk key
   ghcr.io/szymonwilczek/lota/attestca:<version>-hsm    PKCS#11, cgo, key in a token

The HSM image sits on **nonroot distroless cc**, which carries glibc,
``libstdc++`` and ``libcrypto`` -- what a PKCS#11 module is usually linked
against -- and nothing else: still no shell and no package manager. The module
is the operator's own and is mounted read-only, together with any library of
its own the base does not carry. cgo has no cross-compiler in this build, so
the HSM image is ``linux/amd64`` only; the pure-Go image keeps both
architectures.

The module is loaded with ``dlopen``, so the base's glibc has to be at least
as new as the glibc the module was built against, and its own dependencies
have to be reachable -- mount them beside it and name the directory in
``LD_LIBRARY_PATH``. A module from a distribution newer than the base fails to
load with a version lookup error naming the symbol version it wanted; the
answer is a module built for an older glibc, not a flag.

Building
========

::

   make container-images

builds and publishes all three: the verifier, the pure-Go CA and the HSM CA.
``make container-image-attest-ca-hsm`` builds the last on its own. The
relevant knobs are make variables:

* ``KO_DOCKER_REPO`` -- destination registry prefix. With ``-B`` the images are
  named ``$KO_DOCKER_REPO/verifier`` and ``$KO_DOCKER_REPO/attestca``.
* ``KO_IMAGE_TAGS`` -- comma-separated tags (default ``<version>,latest``).
* ``KO_PLATFORMS`` -- target platforms (default ``linux/amd64,linux/arm64``).
* ``KO_HSM_PLATFORMS`` -- the same for the HSM image (default ``linux/amd64``;
  its cgo build has no cross-compiler here).
* ``KO_HSM_TAG_SUFFIX`` -- the variant tag the HSM image is published under
  (default ``-hsm``), appended to each tag in ``KO_IMAGE_TAGS``.

The build is reproducible: ``SOURCE_DATE_EPOCH`` is pinned to the HEAD commit
time, matching the rest of the reproducible-build posture
(:doc:`/security/reproducible-builds`). Each image carries an SPDX SBOM and
OCI ``version``/``source``/``licence`` labels.

To inspect an image locally with Podman, without pushing to a registry, point
ko at an OCI layout instead::

   cd src/verifier && ko build --oci-layout-path=/tmp/v .
   skopeo copy oci:/tmp/v containers-storage:localhost/lota-verifier

Running with Podman
===================

The verifier needs its state on a writable volume and exposes its listener
port. A minimal rootless Podman invocation::

   podman run --rm \
       -v lota-verifier-state:/var/lib/lota \
       -p 8443:8443 \
       ghcr.io/szymonwilczek/lota/verifier:latest \
       --aik-store /var/lib/lota/aik --nonce-db /var/lib/lota/nonce.db

Run the service under systemd with a Quadlet ``.container`` unit so it is
managed the same way as the host-native agent. The CA image follows the same
shape, with the CA signing material mounted read-only.

For more than one verifier instance, the images slot into the Postgres-backed
topology unchanged: point each container at the shared database with
``--pg-dsn`` (or ``LOTA_PG_DSN``). See :doc:`ha-deployment`.

Running the HSM image
=====================

Mount the module and the token store, pass the PIN through the environment so
it stays out of the process argument list, and point the CA at the token::

   podman run --rm \
       -v /opt/hsm:/hsm:ro,Z \
       -v lota-ca-material:/var/lib/lota:ro,Z \
       -e LOTA_CA_PKCS11_PIN \
       -e LD_LIBRARY_PATH=/hsm/lib \
       -p 8444:8444 \
       ghcr.io/szymonwilczek/lota/attestca:latest-hsm \
       -ca-cert /var/lib/lota/ca.crt \
       -ca-key-pkcs11-module /hsm/module.so \
       -ca-key-pkcs11-token lota-ca \
       -ca-key-pkcs11-label lota-ca-key \
       -tls-cert /var/lib/lota/tls.crt -tls-key /var/lib/lota/tls.key \
       -pseudonym-key /var/lib/lota/pseudonym.key \
       -ek-root-bundle /var/lib/lota/ek-roots

``/opt/hsm`` here holds the module, the libraries it needs that the base does
not carry, and the token store or client configuration it reads. On SELinux
the mount needs a label the container can read (``:Z`` above); without one the
CA stops on a permission-denied error reading its own material, before it ever
opens the token.

A module that reads its configuration from the environment needs that variable
passed too -- SoftHSM's ``SOFTHSM2_CONF`` is the example, and a networked HSM
client usually needs its own configuration file mounted and its appliance
reachable from the pod.

:doc:`production-bringup/ca-enrollment` covers the flags themselves and the
key ceremony.

Verifying provenance
====================

Release images are signed with cosign over their digest, alongside the
existing ``SHA256SUMS`` signing for the source artifacts. Verify before
running::

   cosign verify ghcr.io/szymonwilczek/lota/verifier:latest

Each published tag is signed, the HSM variant included::

   cosign verify ghcr.io/szymonwilczek/lota/attestca:latest-hsm

The attached SBOM lets a scanner enumerate the (deliberately minimal) image
contents.
