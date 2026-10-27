.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=====================
Verifier Helm chart
=====================

For operators who run the relying-party tier on Kubernetes, the
``deploy/helm/lota-verifier`` chart installs the verifier in the
Postgres-backed HA topology: N stateless replicas behind a Service, all
sharing one database. It packages the same deployment described in
:doc:`ha-deployment`, expressed as Kubernetes objects.

Only the verifier is charted. The agent is host-native (TPM, BPF LSM,
initramfs) and is never deployed to a cluster; the attestation CA, with its
signing key and distinct lifecycle, is deployed separately.

What the chart deploys
======================

* A **Deployment** of ``replicaCount`` verifier replicas using the distroless
  verifier image. The containers run as the
  nonroot distroless user with a read-only root filesystem, no added
  capabilities and the ``RuntimeDefault`` seccomp profile; writable state uses
  an ``emptyDir`` because the durable enforcement state lives in Postgres.
* A **Service** exposing the TLS attestation port (and the HTTP monitoring API
  when ``httpApi.enabled`` is set).
* A **ServiceAccount** for the pods.
* Optionally a **Secret** holding the Postgres DSN, when one is supplied inline
  rather than referenced.

Required inputs
===============

The chart does not mint secrets, and it fails closed at render time: the
verifier refuses to start without a trusted AIK root or a PCR policy, and
replicas without a shared backend cannot enforce as one fleet, so the chart
rejects an install that would produce a crash-looping pod or a split-brained
one.

Provide this material before installing:

* **Postgres DSN (required for more than one replica).** Reference an existing
  Secret with ``postgres.existingSecret`` (recommended), or set
  ``postgres.dsn`` to have the chart create one. The DSN is passed to the
  verifier through the ``LOTA_PG_DSN`` environment variable, never on the
  command line, so the database password does not appear in the pod's argv.
  Left unset, the release is a single instance keeping its enforcement state
  in the pod's ``emptyDir``: a supported shape, and not HA -- bans and
  baselines go with the pod. ``replicaCount`` above 1 without the backend is
  refused at render time, because each replica would enforce state the others
  cannot see.
* **TLS keypair.** A ``kubernetes.io/tls`` Secret named by
  ``tls.existingSecret`` (keys ``tls.crt`` and ``tls.key``), mounted read-only
  for the attestation listener.
* **Attestation-CA root (required with the default** ``requireCert``\ **).**
  A Secret holding the Privacy CA PEM root(s), referenced by
  ``aikCA.existingSecret`` and mounted read-only; each ``aikCA.files`` entry is
  passed as one ``--aik-ca-cert``. This is the root the AIK certificate must
  chain to, distinct from the listener TLS material. Setting
  ``requireCert=false`` drops the requirement but disables AIK chain
  verification (INSECURE).
* **Monitoring-API key (required when** ``httpApi.enabled`` **is set).** Every
  bind inside a pod is non-loopback, and the verifier refuses a non-loopback
  monitoring API without a key. Reference a Secret with
  ``httpApi.auth.existingSecret`` and name the entries to read:
  ``httpApi.auth.readerKey`` for the read-only endpoints Prometheus scrapes
  (``reader-api-key`` by default) and ``httpApi.auth.adminKey`` for revocations
  and bans (unset by default). Each named entry reaches the verifier as
  ``LOTA_READER_API_KEY`` or ``LOTA_ADMIN_API_KEY``, so no key appears in the
  pod's argv. Turning the API on without the Secret is refused at render time;
  see :doc:`monitoring-api` for what each tier may call.
* **PCR policy choice (required).** Either enable ``policy.enabled`` and point
  ``policy.existingConfigMap`` or ``policy.existingSecret`` at the policy file
  (set ``policy.pubKey`` when an Ed25519 ``policy.pub`` accompanies it), or set
  ``allowPermissivePolicy=true`` to accept the permissive built-in policy
  (INSECURE). The two are mutually exclusive.

Installing
==========

The chart in the tree carries an ``@VERSION@`` placeholder for
``appVersion`` and refuses to render as it is. ``make helm-package`` fills the
chart version and ``appVersion`` from the ``VERSION`` file and writes
``build/helm/lota-verifier-<version>.tgz``; a release publishes the same
package to ``oci://ghcr.io/szymonwilczek/charts/lota-verifier``.

::

   make helm-package
   helm install lota-verifier build/helm/lota-verifier-<version>.tgz \
       --set postgres.existingSecret=lota-pg \
       --set tls.existingSecret=lota-verifier-tls \
       --set aikCA.existingSecret=lota-aik-ca \
       --set policy.enabled=true \
       --set policy.existingSecret=lota-verifier-policy \
       --set replicaCount=3

   kubectl rollout status deploy/lota-verifier-lota-verifier

``--require-cert`` stays on by default; keep it on for production so reports
without a CA-issued AIK certificate are rejected, and supply the
``aikCA.existingSecret`` root it verifies against.

With the monitoring API, the same install carries the key Secret::

   kubectl create secret generic lota-api-keys \
       --from-literal=reader-api-key="$(openssl rand -hex 32)"

   helm install lota-verifier build/helm/lota-verifier-<version>.tgz \
       ... \
       --set httpApi.enabled=true \
       --set httpApi.auth.existingSecret=lota-api-keys

The Service then carries the ``http-api`` port beside ``attest``, and a
Prometheus scrape config points at it with the same key as its bearer
credential (:doc:`observability`).

Health probes
=============

With ``httpApi.enabled``, the readiness and liveness probes ask the monitoring
API for ``GET /health``, which needs no key and reports whether the attestation
listener is up. Without the API there is only the attestation port to ask, so
the probes open a connection there and close it; the verifier reads a peer that
never speaks as the health check it is, so those probes cost no challenge and
raise no error.

Validating without a cluster
============================

The chart is validated offline, with no Kubernetes cluster, through two make
targets:

* ``make helm-lint`` -- ``helm lint`` over the chart structure.
* ``make helm-template`` -- renders the packaged chart and pipes it through
  ``kubeconform`` for Kubernetes API schema validation.

Both run against the local chart and fit CI without a cluster. A full
``helm install`` smoke test additionally needs a local cluster (for example
k3s); it confirms the pods schedule and become Ready but is not required to
validate the chart.
