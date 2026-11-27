.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

===================
Verifier Helm chart
===================

:ghsrc:`deploy/helm/lota-verifier` deploys the verifier on Kubernetes: a
Deployment of ``replicaCount`` pods from the verifier image
(:doc:`container-images`), a Service, a ServiceAccount, and a Secret for
the Postgres DSN when ``postgres.dsn`` is set. Several replicas share one
Postgres database (:doc:`ha-deployment`). The chart deploys no CA and no
agent.

Installing
==========

``make helm-package`` sets the chart's version and ``appVersion`` from
``VERSION`` and writes ``build/helm/lota-verifier-VERSION.tgz``
(``HELM_PACKAGE_DIR``). The chart directory itself carries ``@VERSION@`` as
``appVersion`` and refuses to render. A release pushes the package to
``oci://ghcr.io/szymonwilczek/charts/lota-verifier`` and attaches it to the
release.

.. code-block:: sh

   helm install lota-verifier oci://ghcr.io/szymonwilczek/charts/lota-verifier \
       --version VERSION \
       --set postgres.existingSecret=lota-pg \
       --set tls.existingSecret=lota-verifier-tls \
       --set aikCA.existingSecret=lota-aik-ca \
       --set policy.enabled=true \
       --set policy.existingSecret=lota-verifier-policy

   kubectl rollout status deploy/lota-verifier-lota-verifier

Objects are named ``RELEASE-lota-verifier``. The image tag defaults to
``appVersion``.

Values
======

The chart creates no keys. It refuses to render without the inputs the
entries below call required:

``aikCA.existingSecret``
  A Secret with the attestation-CA roots; each name in ``aikCA.files``
  (default ``ca.crt``) becomes one ``--aik-ca-cert``. Required while
  ``requireCert`` is true, the default.

``policy.enabled``, ``policy.existingSecret`` or ``policy.existingConfigMap``
  The policy, under the key ``policy.yaml``, passed as ``--policy``. With
  ``policy.pubKey``, the key ``policy.pub`` is passed as
  ``--policy-pubkey``. The other choice is ``allowPermissivePolicy=true``,
  the built-in policy with no measurements. The chart refuses a render
  with neither of the two, or with both, and ``policy.enabled`` with no
  source or with both sources.

``postgres.existingSecret`` or ``postgres.dsn``
  The DSN, under ``postgres.dsnKey`` (default ``dsn``), reaches the verifier
  as ``LOTA_PG_DSN``. Without it, ``replicaCount`` must be 1 and the state
  lives in the pod's ``emptyDir``. The default ``replicaCount`` is 3.

``tls.existingSecret``
  A ``kubernetes.io/tls`` Secret, default ``lota-verifier-tls``, for the
  attestation listener on ``service.port`` (8443).

``httpApi.enabled``
  Starts the monitoring API on ``httpApi.port`` (8080) and adds it to the
  Service. A bind in a pod is not on loopback, so the API needs
  ``httpApi.auth.existingSecret``: its ``readerKey`` entry (default
  ``reader-api-key``) becomes ``LOTA_READER_API_KEY`` and its ``adminKey``
  entry, when named, ``LOTA_ADMIN_API_KEY``
  (:doc:`../verifier/monitoring-api`). A Secret with neither entry named is
  refused.

``extraArgs``
  Further verifier flags (:doc:`../verifier/command-line`).

``shutdownDrain``
  Passed as ``--shutdown-drain``.

The pods run as UID and GID 65532 with ``RuntimeDefault`` seccomp, a
read-only root filesystem, no privilege escalation and every capability
dropped; ``/var/lib/lota`` and ``/tmp`` are ``emptyDir`` volumes.

Probes
======

With ``httpApi.enabled`` the readiness and liveness probes request
``/health`` from the monitoring API over HTTPS. Without it they open a TCP
connection to the attestation port and close it; the verifier does not
count a peer that hangs up before the protocol as a connection error.
``probes.enabled=false`` removes both.

Checking the chart
==================

``make helm-lint`` runs ``helm lint``. ``make helm-template`` packages the
chart and pipes ``helm template`` through ``kubeconform -strict``. ``make
check-helm-chart``, which ``make helm-package`` runs first, checks what the
chart deploys: the image tag, the names, the inputs it refuses without, and
the Secrets a pod references. None of them needs a cluster.
