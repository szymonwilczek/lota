.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

================
Container images
================

The verifier and the attestation CA ship as OCI images built with `ko
<https://ko.build>`_. The agent needs the host's TPM, BPF LSM and initramfs,
and ships only as a package (:doc:`packages`).

The images
==========

.. list-table::
   :header-rows: 1
   :widths: 45 30 25

   * - Image
     - Base
     - Platforms
   * - ``ghcr.io/szymonwilczek/lota/verifier:VERSION``
     - ``gcr.io/distroless/static:nonroot``
     - ``linux/amd64``, ``linux/arm64``
   * - ``ghcr.io/szymonwilczek/lota/attestca:VERSION``
     - ``gcr.io/distroless/cc-debian13:nonroot``
     - ``linux/amd64``

Each tag also exists as ``latest``. The configurations are
:ghsrc:`src/verifier/.ko.yaml` and :ghsrc:`src/attestca/.ko.yaml`. Both
images run as uid 65532, so the state they write lives on a mounted volume.
Under rootless Podman, ``--userns=keep-id:uid=65532,gid=65532`` runs that
uid as the user who starts Podman, and every mounted file must be readable
by that user.

The verifier is a static build with cgo off, on a base with no shell and no
libc.

The CA is built with cgo, on a base that carries glibc, and loads the
operator's PKCS#11 module with ``dlopen``. The module needs a glibc no newer
than the base's; a library of its own that the base lacks is mounted beside
it and named in ``LD_LIBRARY_PATH``.

Building
========

.. code-block:: sh

   make container-images

builds both images and pushes them to ``KO_DOCKER_REPO``
(``ghcr.io/szymonwilczek/lota``) as ``verifier`` and ``attestca``;
``make container-image-verifier`` and ``container-image-attest-ca`` build
one. The variables:

``KO_IMAGE_TAGS``
  Tags, comma-separated. Default ``VERSION,latest``.

``KO_PLATFORMS``
  Platforms of the verifier image. Default ``linux/amd64,linux/arm64``.

``KO_CA_PLATFORMS``
  Platforms of the CA image. Default ``linux/amd64``, since cgo does not
  cross-compile in this build.

``SOURCE_DATE_EPOCH`` is ``REPRO_SOURCE_DATE_EPOCH`` when it is set to a
non-empty value, otherwise the commit time of ``HEAD``
(:doc:`../security/reproducible-builds`). Each image carries an SPDX SBOM
and the ``org.opencontainers.image.version``, ``source`` and ``licenses``
labels.

``KO_DOCKER_REPO=ko.local`` loads the images into the local Docker daemon.
For Podman, ko writes an OCI layout that ``skopeo`` copies::

   cd src/verifier
   KO_DOCKER_REPO=example.invalid/lota ko build -B --push=false \
       --platform=linux/amd64 --oci-layout-path=/tmp/lota-verifier .
   skopeo copy oci:/tmp/lota-verifier containers-storage:localhost/lota-verifier

Running the verifier
====================

The verifier refuses to start without a TLS certificate and key, an
attestation-CA root and a policy (:doc:`../verifier/command-line`). With
them in ``/etc/lota-verifier`` on the host:

.. code-block:: sh

   podman run --rm \
       --userns=keep-id:uid=65532,gid=65532 \
       -v lota-verifier-state:/var/lib/lota \
       -v /etc/lota-verifier:/etc/lota-verifier:ro,Z \
       -p 8443:8443 \
       ghcr.io/szymonwilczek/lota/verifier:VERSION \
       --cert /etc/lota-verifier/tls.crt --key /etc/lota-verifier/tls.key \
       --aik-ca-cert /etc/lota-verifier/aik-ca.crt \
       --policy /etc/lota-verifier/policy.yaml

The state database defaults to ``/var/lib/lota/verifier-state.sqlite``.
Several instances share a Postgres database through ``--pg-dsn`` or
``LOTA_PG_DSN`` (:doc:`ha-deployment`).

Running the CA with a token
===========================

The CA reads the PIN from ``LOTA_CA_PKCS11_PIN`` only. With the token in
``/opt/hsm`` and the CA material in ``/etc/lota-ca`` on the host:

.. code-block:: sh

   podman run --rm \
       --userns=keep-id:uid=65532,gid=65532 \
       -v /opt/hsm:/hsm:ro,Z \
       -v /etc/lota-ca:/var/lib/lota:ro,Z \
       -e LOTA_CA_PKCS11_PIN \
       -e LD_LIBRARY_PATH=/hsm/lib \
       -p 8444:8444 \
       ghcr.io/szymonwilczek/lota/attestca:VERSION \
       -ca-cert /var/lib/lota/ca.crt \
       -ca-key-pkcs11-module /hsm/module.so \
       -ca-key-pkcs11-token lota-ca \
       -ca-key-pkcs11-label lota-ca-key \
       -tls-cert /var/lib/lota/tls.crt -tls-key /var/lib/lota/tls.key \
       -pseudonym-key /var/lib/lota/pseudonym.key \
       -ek-root-bundle /var/lib/lota/ek-roots

``/opt/hsm`` holds the module, the libraries it needs and the configuration
it reads; a module that takes its configuration from the environment, as
SoftHSM does from ``SOFTHSM2_CONF``, needs that variable passed as well.
``/var/lib/lota/ek-roots`` is a pinned EK root bundle, a directory with its
``ek-roots.manifest``. :doc:`bringup/ca-enrollment` covers the flags, the
bundle and the key.

Verifying an image
==================

The release workflow signs each version tag with cosign, without a key,
under the workflow's identity:

.. code-block:: sh

   cosign verify \
       --certificate-identity-regexp \
         '^https://github\.com/szymonwilczek/lota/\.github/workflows/release\.yml@refs/tags/v' \
       --certificate-oidc-issuer https://token.actions.githubusercontent.com \
       ghcr.io/szymonwilczek/lota/verifier:VERSION

The same command verifies ``attestca:VERSION``.
