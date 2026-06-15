========
Operator
========

Production operation starts with the bring-up document. The agent
intentionally fails closed when required gates are missing.

* `Production bring-up <production-bringup/index.rst>`_ -- the full manual
  reference for fleet hosts, CA, and verifier.
* `Player install (lota-install) <player-install.rst>`_ -- the guided,
  reboot-resumable single-machine path.
* `Verifier deployment topologies <ha-deployment.rst>`_ -- single node versus
  N instances behind a load balancer.

Related deployment material lives next to the code:

* PCR policy templates: ``policies/README.rst``
* SELinux policy: ``selinux/README.rst``
* EK root bundles: ``configs/ek-roots/README.rst``
* Example configuration: ``configs/lota.conf.example``
