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

Both services are pure-Go static binaries (``modernc.org/sqlite``,
``jackc/pgx`` -- no cgo), so each image is the binary on the **nonroot
distroless static** base: no shell, no libc and no package manager, which
keeps the CVE surface that enterprise scanners report close to zero. The
service therefore runs as an unprivileged user, and any writable state must be
supplied through a mounted volume.

The attestation CA image carries the default pure-Go build. The pkcs11/HSM
signing path is an opt-in cgo build that needs a PKCS#11 module at runtime and
is deliberately excluded; HSM adopters run the CA on a host with their module.

Building
========

::

   make container-images

builds and publishes both images. The relevant knobs are make variables:

* ``KO_DOCKER_REPO`` -- destination registry prefix. With ``-B`` the images are
  named ``$KO_DOCKER_REPO/verifier`` and ``$KO_DOCKER_REPO/attestca``.
* ``KO_IMAGE_TAGS`` -- comma-separated tags (default ``<version>,latest``).
* ``KO_PLATFORMS`` -- target platforms (default ``linux/amd64,linux/arm64``).

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

Verifying provenance
====================

Release images are signed with cosign over their digest, alongside the
existing ``SHA256SUMS`` signing for the source artifacts. Verify before
running::

   cosign verify ghcr.io/szymonwilczek/lota/verifier:latest

The attached SBOM lets a scanner enumerate the (deliberately minimal) image
contents.
