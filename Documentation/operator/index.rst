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

Related deployment material lives next to the code:

* PCR policy templates: ``policies/README.rst``
* SELinux policy: ``selinux/README.rst``
* EK root bundles: ``configs/ek-roots/README.rst``
* Example configuration: ``configs/lota.conf.example``

.. toctree::
   :hidden:

   production-bringup/index
   player-install
   ha-deployment
