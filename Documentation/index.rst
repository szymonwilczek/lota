.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==================
LOTA Documentation
==================

Linux Open Trusted Attestation (LOTA) is a Linux attestation and
runtime-integrity framework. This tree holds the project's narrative
documentation, organised by the role of the reader.

Component documentation (examples, policies, SELinux, Syzkaller, EK roots,
benchmarks) lives next to the code it describes, as a ``README.rst`` in the
relevant directory.

Who are you?
============

New contributor or automated assistant
--------------------------------------

Development happens on ``lota-next``. Open pull requests there, not against
``main``.

* :doc:`Contribution rules <contributor/contributing>`
* :doc:`Development and testing policy <contributor/development/index>`
* :doc:`Branch and release flow <contributor/branching>`
* :doc:`Code of Conduct <contributor/code-of-conduct>`

Operator
--------

Production operation starts with the bring-up document. The agent
intentionally fails closed when required gates are missing.

* :doc:`Production bring-up <operator/production-bringup/index>`
* :doc:`Player install (lota-install) <operator/player-install>`
* :doc:`Verifier deployment topologies (HA) <operator/ha-deployment>`
* PCR policy templates: :ghsrc:`policies/README.rst`
* SELinux policy: :ghsrc:`selinux/README.rst`
* EK root bundles: :ghsrc:`configs/ek-roots/README.rst`

Security reviewer or academic reviewer
--------------------------------------

Start with the threat model and the reporting policy. Do not file public
issues for exploitable vulnerabilities.

* :doc:`Threat model <security/threat-model>`
* :doc:`Security reporting <security/reporting>`
* :doc:`Reproducible release verification <security/reproducible-builds>`
* :doc:`Attestation CA signing key <security/ca-key>`
* :doc:`Production bring-up <operator/production-bringup/index>`
* :doc:`Performance evaluation <performance/evaluation>`

TPM or attestation engineer
---------------------------

The hardware trust contract centres on EK root validation, credential
activation, AIK certificates, TPM quotes, PCR policy, and PCR14 boot
commitment.

* :doc:`Threat model <security/threat-model>`
* :doc:`Attestation CA signing key <security/ca-key>`
* :doc:`Production bring-up <operator/production-bringup/index>`
* Enrollment example: :ghsrc:`examples/enrollment/README.rst`
* EK root bundles: :ghsrc:`configs/ek-roots/README.rst`
* PCR policy documentation: :ghsrc:`policies/README.rst`

Kernel or BPF engineer
----------------------

The kernel-facing surface lives in the BPF LSM object, loader, runtime
measurement path, initramfs PCR14 lock, SELinux policy, and the Syzkaller
harness.

* :doc:`Production bring-up <operator/production-bringup/index>`
* :doc:`Kernel test policy <contributor/development/index>`
* SELinux policy: :ghsrc:`selinux/README.rst`
* Syzkaller harness: :ghsrc:`syzkaller/README.rst`
* Runtime remeasurement example: :ghsrc:`examples/runtime_remeasure/README.rst`

Game or anti-cheat integrator
-----------------------------

LOTA exposes trust decisions and token verification material. Gameplay policy
remains outside this repository.

* Example index: :ghsrc:`examples/README.rst`
* Reference server: :ghsrc:`examples/demo_server/README.rst`
* Anti-cheat heartbeat producer: :ghsrc:`examples/demo_anticheat/README.rst`
* Proton and Wine titles: :ghsrc:`examples/cs2/README.rst`
* Demo game client: :ghsrc:`examples/demo_game/README.rst`
* End-to-end demo: :ghsrc:`examples/demo/README.rst`
* mTLS example: :ghsrc:`examples/mtls/README.rst`
* Runtime remeasurement: :ghsrc:`examples/runtime_remeasure/README.rst`

Distribution maintainer
-----------------------

Packaging must preserve the security contract. Release artifacts are
reproducible and verified against signed manifests.

* :doc:`Reproducible builds <security/reproducible-builds>`
* :doc:`Release and branch flow <contributor/branching>`
* :doc:`Production install gates <operator/production-bringup/index>`
* SELinux policy: :ghsrc:`selinux/README.rst`

.. toctree::
   :hidden:

   contributor/index
   operator/index
   security/index
   performance/index
