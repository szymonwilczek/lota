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
* PCR policy templates: `policies/README.rst <https://github.com/szymonwilczek/lota/blob/main/policies/README.rst>`__
* SELinux policy: `selinux/README.rst <https://github.com/szymonwilczek/lota/blob/main/selinux/README.rst>`__
* EK root bundles: `configs/ek-roots/README.rst <https://github.com/szymonwilczek/lota/blob/main/configs/ek-roots/README.rst>`__

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
* Enrollment example: `examples/enrollment/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/enrollment/README.rst>`__
* EK root bundles: `configs/ek-roots/README.rst <https://github.com/szymonwilczek/lota/blob/main/configs/ek-roots/README.rst>`__
* PCR policy documentation: `policies/README.rst <https://github.com/szymonwilczek/lota/blob/main/policies/README.rst>`__

Kernel or BPF engineer
----------------------

The kernel-facing surface lives in the BPF LSM object, loader, runtime
measurement path, initramfs PCR14 lock, SELinux policy, and the Syzkaller
harness.

* :doc:`Production bring-up <operator/production-bringup/index>`
* :doc:`Kernel test policy <contributor/development/index>`
* SELinux policy: `selinux/README.rst <https://github.com/szymonwilczek/lota/blob/main/selinux/README.rst>`__
* Syzkaller harness: `syzkaller/README.rst <https://github.com/szymonwilczek/lota/blob/main/syzkaller/README.rst>`__
* Runtime remeasurement example: `examples/runtime_remeasure/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/runtime_remeasure/README.rst>`__

Game or anti-cheat integrator
-----------------------------

LOTA exposes trust decisions and token verification material. Gameplay policy
remains outside this repository.

* Example index: `examples/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/README.rst>`__
* Reference server: `examples/demo_server/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/demo_server/README.rst>`__
* Anti-cheat heartbeat producer: `examples/demo_anticheat/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/demo_anticheat/README.rst>`__
* Demo game client: `examples/demo_game/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/demo_game/README.rst>`__
* End-to-end demo: `examples/demo/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/demo/README.rst>`__
* mTLS example: `examples/mtls/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/mtls/README.rst>`__
* Runtime remeasurement: `examples/runtime_remeasure/README.rst <https://github.com/szymonwilczek/lota/blob/main/examples/runtime_remeasure/README.rst>`__

Distribution maintainer
-----------------------

Packaging must preserve the security contract. Release artifacts are
reproducible and verified against signed manifests.

* :doc:`Reproducible builds <security/reproducible-builds>`
* :doc:`Release and branch flow <contributor/branching>`
* :doc:`Production install gates <operator/production-bringup/index>`
* SELinux policy: `selinux/README.rst <https://github.com/szymonwilczek/lota/blob/main/selinux/README.rst>`__

.. toctree::
   :hidden:

   contributor/index
   operator/index
   security/index
   performance/index
