.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========
Operator
========

Production operation starts with the bring-up document. The agent
intentionally fails closed when required gates are missing.

* :doc:`Platform support <../admin-guide/platform-support>` -- which distributions, firmware
  and TPM the agent targets, and at what support tier.
* :doc:`Production bring-up <../admin-guide/bringup/index>` -- the full manual
  reference for fleet hosts, CA, and verifier.
* :doc:`Guided install (lota-install) <../admin-guide/lota-install>` -- the guided,
  reboot-resumable single-machine path.
* :doc:`Verifier deployment topologies <../admin-guide/ha-deployment>` -- single node versus
  N instances behind a load balancer.
* :doc:`Sizing guide <../admin-guide/sizing>` -- agents per verifier, verifiers per
  Postgres, enrollment bursts and failover behaviour, from measured runs.
* :doc:`Multi-tenancy <../admin-guide/multi-tenancy>` -- serve several isolated tenants from
  one verifier with per-tenant bans, policies, and scoped API keys.
* :doc:`Observability <../admin-guide/observability>` -- Prometheus scraping, the reference
  Grafana dashboard, alert rules, and per-alert runbooks.
* :doc:`Protocol versions <../admin-guide/protocol-versions>` -- how the attestation,
  enrollment and schema surfaces are versioned, and which agent, verifier and CA
  releases interoperate.
* :doc:`Agent updates and the reboot requirement <../admin-guide/agent-update>` -- why an
  agent update needs a cold reboot and a pre-pinned hash.
* :doc:`RPM packages <../admin-guide/packages>` -- the native packages and how to install
  and bring up the agent.
* :doc:`Container images <../admin-guide/container-images>` -- distroless OCI images for the
  verifier and attestation CA, built with ko.
* :doc:`Verifier Helm chart <../admin-guide/helm-chart>` -- install the HA verifier on
  Kubernetes.
* :doc:`COPR repository <../admin-guide/copr>` -- install the packages from the Fedora COPR
  build service.
* :doc:`Signed dnf repository <../admin-guide/dnf-repo>` -- sign the packages and serve them
  from a dnf repository.
* :doc:`Fleet CLI (lota-fleet) <../admin-guide/fleet-cli>` -- drive the verifier's
  monitoring API: revocations, bans, re-anchor, client removal, logs.
* :doc:`Monitoring API reference <../verifier/monitoring-api>` -- the REST endpoint
  contract the fleet CLI and custom tooling consume.

Related deployment material lives next to the code:

* PCR policy templates: :ghsrc:`policies/README.rst`
* SELinux policy: :ghsrc:`selinux/README.rst`
* EK root bundles: :ghsrc:`configs/ek-roots/README.rst`
* Example configuration: :ghsrc:`configs/lota.conf.example`

.. toctree::
   :hidden:

   ../admin-guide/platform-support
   ../admin-guide/bringup/index
   ../admin-guide/lota-install
   ../admin-guide/ha-deployment
   ../admin-guide/sizing
   ../admin-guide/multi-tenancy
   ../admin-guide/observability
   ../admin-guide/protocol-versions
   ../admin-guide/agent-update
   ../admin-guide/packages
   ../admin-guide/container-images
   ../admin-guide/helm-chart
   ../admin-guide/copr
   ../admin-guide/dnf-repo
   ../admin-guide/fleet-cli
   ../verifier/monitoring-api
   ../agent/tpm
