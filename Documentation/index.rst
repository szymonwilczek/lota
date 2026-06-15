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

* `Contribution rules <contributor/contributing.rst>`_
* `Development and testing policy <contributor/development/index.rst>`_
* `Branch and release flow <contributor/branching.rst>`_
* `Code of Conduct <contributor/code-of-conduct.rst>`_

Operator
--------

Production operation starts with the bring-up document. The agent
intentionally fails closed when required gates are missing.

* `Production bring-up <operator/production-bringup/index.rst>`_
* `Player install (lota-install) <operator/player-install.rst>`_
* `Verifier deployment topologies (HA) <operator/ha-deployment.rst>`_
* PCR policy templates: ``policies/README.rst``
* SELinux policy: ``selinux/README.rst``
* EK root bundles: ``configs/ek-roots/README.rst``

Security reviewer or academic reviewer
--------------------------------------

Start with the threat model and the reporting policy. Do not file public
issues for exploitable vulnerabilities.

* `Threat model <security/threat-model.rst>`_
* `Security reporting <security/reporting.rst>`_
* `Reproducible release verification <security/reproducible-builds.rst>`_
* `Attestation CA signing key <security/ca-key.rst>`_
* `Production bring-up <operator/production-bringup/index.rst>`_
* `Performance evaluation <performance/evaluation.rst>`_

TPM or attestation engineer
---------------------------

The hardware trust contract centres on EK root validation, credential
activation, AIK certificates, TPM quotes, PCR policy, and PCR14 boot
commitment.

* `Threat model <security/threat-model.rst>`_
* `Attestation CA signing key <security/ca-key.rst>`_
* `Production bring-up <operator/production-bringup/index.rst>`_
* Enrollment example: ``examples/enrollment/README.rst``
* EK root bundles: ``configs/ek-roots/README.rst``
* PCR policy documentation: ``policies/README.rst``

Kernel or BPF engineer
----------------------

The kernel-facing surface lives in the BPF LSM object, loader, runtime
measurement path, initramfs PCR14 lock, SELinux policy, and the Syzkaller
harness.

* `Production bring-up <operator/production-bringup/index.rst>`_
* `Kernel test policy <contributor/development/index.rst>`_
* SELinux policy: ``selinux/README.rst``
* Syzkaller harness: ``syzkaller/README.rst``
* Runtime remeasurement example: ``examples/runtime_remeasure/README.rst``

Game or anti-cheat integrator
-----------------------------

LOTA exposes trust decisions and token verification material. Gameplay policy
remains outside this repository.

* Example index: ``examples/README.rst``
* Reference server: ``examples/demo_server/README.rst``
* Anti-cheat heartbeat producer: ``examples/demo_anticheat/README.rst``
* Demo game client: ``examples/demo_game/README.rst``
* End-to-end demo: ``examples/demo/README.rst``
* mTLS example: ``examples/mtls/README.rst``
* Runtime remeasurement: ``examples/runtime_remeasure/README.rst``

Distribution maintainer
-----------------------

Packaging must preserve the security contract. Release artifacts are
reproducible and verified against signed manifests.

* `Reproducible builds <security/reproducible-builds.rst>`_
* `Release and branch flow <contributor/branching.rst>`_
* `Production install gates <operator/production-bringup/index.rst>`_
* SELinux policy: ``selinux/README.rst``
