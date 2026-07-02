.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========
Operator
========

Production operation starts with the bring-up document. The agent
intentionally fails closed when required gates are missing.

* :doc:`Production bring-up <production-bringup/index>` -- the full manual
  reference for fleet hosts, CA, and verifier.
* :doc:`Player install (lota-install) <player-install>` -- the guided,
  reboot-resumable single-machine path.
* :doc:`Verifier deployment topologies <ha-deployment>` -- single node versus
  N instances behind a load balancer.
* :doc:`Multi-tenancy <multi-tenancy>` -- serve several isolated tenants from
  one verifier with per-tenant bans, policies, and scoped API keys.
* :doc:`RPM packages <packages>` -- the native packages and how to install
  and bring up the agent.
* :doc:`Container images <container-images>` -- distroless OCI images for the
  verifier and attestation CA, built with ko.
* :doc:`Verifier Helm chart <helm-chart>` -- install the HA verifier on
  Kubernetes.
* :doc:`COPR repository <copr>` -- install the packages from the Fedora COPR
  build service.
* :doc:`Signed dnf repository <dnf-repo>` -- sign the packages and serve them
  from a dnf repository.
* :doc:`Fleet CLI (lota-fleet) <fleet-cli>` -- drive the verifier's
  monitoring API: revocations, bans, re-anchor, client removal, logs.

Related deployment material lives next to the code:

* PCR policy templates: :ghsrc:`policies/README.rst`
* SELinux policy: :ghsrc:`selinux/README.rst`
* EK root bundles: :ghsrc:`configs/ek-roots/README.rst`
* Example configuration: :ghsrc:`configs/lota.conf.example`

.. toctree::
   :hidden:

   production-bringup/index
   player-install
   ha-deployment
   multi-tenancy
   packages
   container-images
   helm-chart
   copr
   dnf-repo
   fleet-cli
