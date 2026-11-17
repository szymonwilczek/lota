.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

========
Operator
========

These pages describe how to install and run LOTA: the platforms the agent
supports, the host requirements it checks at startup, the packages and
images, and the verifier tier with its fleet tooling. How each part works
is described in :doc:`../agent/index`, :doc:`../bpf/index` and
:doc:`../verifier/index`.

Installing a host
=================

* :doc:`Platform support <platform-support>` -- distributions, kernel,
  firmware and the PCRs a policy can pin.
* :doc:`Guided install (lota-install) <lota-install>` -- bring-up of one
  machine, stage by stage.
* :doc:`Production bring-up <bringup/index>` -- the host requirements by
  hand, attestation CA enrollment and sealed keys.
* :doc:`Agent updates <agent-update>` -- rolling a new agent build across a
  fleet.

Packages and images
===================

* :doc:`RPM packages <packages>` -- the packages, their install scripts and
  the state they own.
* :doc:`COPR repository <copr>` -- the packages built from the source RPM.
* :doc:`Signed dnf repository <dnf-repo>` -- the signed repository of
  release packages.
* :doc:`Container images <container-images>` -- the verifier and
  attestation CA images.
* :doc:`Verifier Helm chart <helm-chart>` -- the verifier on Kubernetes.

Running the verifier tier
=========================

* :doc:`Verifier topologies <ha-deployment>` -- where the verifier keeps
  its state and how many instances each store allows.
* :doc:`Sizing <sizing>` -- hosts per verifier, verifiers per Postgres and
  the cost of a first-boot burst.
* :doc:`Multi-tenancy <multi-tenancy>` -- tenants on one verifier.
* :doc:`Observability <observability>` -- metrics, dashboard, alerts and
  their runbooks.
* :doc:`Protocol versions <protocol-versions>` -- which agent, verifier and
  CA releases interoperate.
* :doc:`Fleet CLI (lota-fleet) <fleet-cli>` -- revocations, bans,
  re-anchor and logs through the monitoring API.

Next to the code
================

* :ghsrc:`policies/README.rst` -- PCR policy templates.
* :ghsrc:`selinux/README.rst` -- the SELinux policy module.
* :ghsrc:`configs/ek-roots/README.rst` -- EK root bundles.
* :ghsrc:`configs/lota.conf.example` -- an annotated ``lota.conf``; the
  keys are described in :doc:`../agent/configuration`.

.. toctree::
   :hidden:

   platform-support
   lota-install
   bringup/index
   agent-update
   packages
   copr
   dnf-repo
   container-images
   helm-chart
   ha-deployment
   sizing
   multi-tenancy
   observability
   protocol-versions
   fleet-cli
