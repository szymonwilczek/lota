.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==============================
Linux Open Trusted Attestation
==============================

Linux Open Trusted Attestation, or LOTA, is a Linux attestation and
runtime-integrity framework.

It lets a remote verifier or game server decide whether a host was enrolled
through a manufacturer-backed TPM, booted into an approved firmware and Secure
Boot state, runs the expected LOTA agent image, and enforces the configured
runtime gates through BPF LSM.

LOTA is **not** a behavioral anti-cheat engine. It does **not** scan gameplay
state, input, memory signatures, or network behavior. It provides a
hardware-backed trust substrate that game, anti-cheat, fleet, or relying-party
policy can build on top of.

Trust chain overview
====================

The production trust chain is::

    TPM 2.0 EK certificate -> Attestation CA (1) -> LOTA agent (2) -> Verifier / SDK consumer (3)

    (1) Attestation CA
      - verifies EK roots
      - runs TPM2 credential activation
      - issues an AIK certificate

    (2) LOTA agent
      - owns TPM interaction
      - measures boot and runtime state
      - loads signed BPF LSM policy

    (3) Verifier or SDK consumer
      - checks AIK certificate trust
      - verifies TPM quote freshness
      - enforces PCR, boot, runtime, and token policy

The verifier trusts a CA-issued AIK certificate, not an agent-asserted public
key. Firmware and Secure Boot state are pinned through PCR 0, PCR 1, and PCR 7.
LOTA's own boot commitment is bound through PCR14. Runtime protection is
enforced by the agent and BPF LSM hooks, with fs-verity, SELinux, lockdown,
module signing, and signed BPF objects forming the production floor.

For the complete security boundary, read
`Documentation/security/threat-model.rst
<Documentation/security/threat-model.rst>`_.

Quick start
===========

* Build the tree:
  ``env GOCACHE=/tmp/lota-gocache make BUILD_DIR=/tmp/lota-build all``
* Run unit tests:
  ``env GOCACHE=/tmp/lota-gocache make BUILD_DIR=/tmp/lota-build test-unit``
* Build optional examples: ``make examples``
* Bring up a production host: see
  `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_
* Run the end-to-end demo material: see
  `examples/README.rst <examples/README.rst>`_
* Report a vulnerability: see `SECURITY.md <SECURITY.md>`_
* Contribute a patch: see `CONTRIBUTING.rst <CONTRIBUTING.rst>`_

Build inputs include a C toolchain, clang/LLVM for BPF, libbpf, TPM2-TSS,
OpenSSL, systemd, libseccomp, D-Bus headers, and Go for the verifier and
attestation CA.

The authoritative build and test policy is in
`Documentation/contributor/development/index.rst
<Documentation/contributor/development/index.rst>`_.

Essential documentation
=======================

All users should know where these documents live:

* Threat model: `Documentation/security/threat-model.rst
  <Documentation/security/threat-model.rst>`_
* Production bring-up: `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_
* Development and testing policy:
  `Documentation/contributor/development/index.rst
  <Documentation/contributor/development/index.rst>`_
* Branch and release flow: `Documentation/contributor/branching.rst
  <Documentation/contributor/branching.rst>`_
* Reproducible builds: `Documentation/security/reproducible-builds.rst
  <Documentation/security/reproducible-builds.rst>`_
* Performance evaluation: `Documentation/performance/evaluation.rst
  <Documentation/performance/evaluation.rst>`_
* PCR policies: `policies/README.rst <policies/README.rst>`_
* SELinux policy: `selinux/README.rst <selinux/README.rst>`_
* EK root bundle material: `configs/ek-roots/README.rst
  <configs/ek-roots/README.rst>`_
* Security reporting: `SECURITY.md <SECURITY.md>`_
* Code of Conduct: `CODE_OF_CONDUCT.rst <CODE_OF_CONDUCT.rst>`_

The full documentation tree, organised by reader role, lives under
`Documentation/ <Documentation/index.rst>`_.

Repository map
==============

* ``src/agent/`` - privileged host agent, TPM interaction, BPF loading, IPC,
  reporting, enrollment, and runtime measurement.
* ``src/bpf/`` - BPF LSM enforcement programs.
* ``src/initramfs/`` - PCR14 initramfs lock helper and dracut integration.
* ``src/attestca/`` - attestation CA and TPM credential-activation service.
* ``src/verifier/`` - verifier, policy engine, stores, API server, nonce
  handling, revocation, and report validation.
* ``src/sdk/`` and ``include/`` - C SDK, server SDK, token formats, and public
  integration headers.
* ``policies/``, ``configs/``, ``systemd/``, ``selinux/``, and ``dbus/`` -
  production deployment policy and service material.
* ``examples/`` - enrollment, demo server, anti-cheat heartbeat, game UI,
  sealed-key, mTLS, runtime remeasurement, and blocking scenarios.
* ``benchmarks/`` and ``syzkaller/`` - performance and kernel-surface validation
  material.

Who are you?
============

* Operator - deploying the agent and verifier on real hosts.
* Game or anti-cheat integrator - consuming trust verdicts and SDK tokens.
* Security reviewer - auditing the trust model and reporting vulnerabilities.
* TPM or attestation engineer - reviewing enrollment, EK roots, AIKs, and PCRs.
* Kernel or BPF engineer - reviewing runtime gates and LSM portability.
* Distribution maintainer - packaging, signing, and reproducing releases.
* New contributor - preparing patches against ``lota-next``.
* Academic reviewer - evaluating design, threat model, and measurements.
* Automated coding assistant - following project contribution rules.

The role-specific documentation index lives at
`Documentation/index.rst <Documentation/index.rst>`_.

For specific users
==================

Operator
--------

Production operation starts with the bring-up document. The agent intentionally
fails closed when required gates are missing.

* Production checklist: `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_
* PCR policy templates: `policies/README.rst <policies/README.rst>`_
* SELinux policy: `selinux/README.rst <selinux/README.rst>`_
* EK root bundles: `configs/ek-roots/README.rst <configs/ek-roots/README.rst>`_
* Example configuration: `configs/lota.conf.example
  <configs/lota.conf.example>`_
* Re-enrollment flow: `examples/enrollment/README.rst
  <examples/enrollment/README.rst>`_

Game or anti-cheat integrator
-----------------------------

LOTA exposes trust decisions and token verification material. Gameplay policy
remains outside this repository.

* Example index: `examples/README.rst <examples/README.rst>`_
* Reference server: `examples/demo_server/README.rst
  <examples/demo_server/README.rst>`_
* Anti-cheat heartbeat producer: `examples/demo_anticheat/README.rst
  <examples/demo_anticheat/README.rst>`_
* Demo game client: `examples/demo_game/README.rst
  <examples/demo_game/README.rst>`_
* End-to-end demo: `examples/demo/README.rst <examples/demo/README.rst>`_
* mTLS example: `examples/mtls/README.rst <examples/mtls/README.rst>`_
* Runtime remeasurement: `examples/runtime_remeasure/README.rst
  <examples/runtime_remeasure/README.rst>`_

Security reviewer
-----------------

Start with the threat model and the security reporting policy. Do not file
public issues for exploitable vulnerabilities.

* Threat model: `Documentation/security/threat-model.rst
  <Documentation/security/threat-model.rst>`_
* Security reporting: `SECURITY.md <SECURITY.md>`_
* Reproducible release verification:
  `Documentation/security/reproducible-builds.rst
  <Documentation/security/reproducible-builds.rst>`_
* Production bring-up: `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_
* Development tests and fuzzing:
  `Documentation/contributor/development/index.rst
  <Documentation/contributor/development/index.rst>`_
* Performance baseline: `Documentation/performance/evaluation.rst
  <Documentation/performance/evaluation.rst>`_

TPM or attestation engineer
---------------------------

The hardware trust contract is centered on EK root validation, credential
activation, AIK certificates, TPM quotes, PCR policy, and PCR14 boot
commitment.

* Threat model: `Documentation/security/threat-model.rst
  <Documentation/security/threat-model.rst>`_
* Enrollment example: `examples/enrollment/README.rst
  <examples/enrollment/README.rst>`_
* EK root bundles: `configs/ek-roots/README.rst <configs/ek-roots/README.rst>`_
* PCR policy documentation: `policies/README.rst <policies/README.rst>`_
* Production bring-up: `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_

Kernel or BPF engineer
----------------------

The kernel-facing surface lives in the BPF LSM object, loader, runtime
measurement path, initramfs PCR14 lock, SELinux policy, and Syzkaller harness.

* BPF and production gates: `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_
* SELinux policy: `selinux/README.rst <selinux/README.rst>`_
* Kernel test policy: `Documentation/contributor/development/index.rst
  <Documentation/contributor/development/index.rst>`_
* Syzkaller harness: `syzkaller/README.rst <syzkaller/README.rst>`_
* Runtime remeasurement example: `examples/runtime_remeasure/README.rst
  <examples/runtime_remeasure/README.rst>`_

Distribution maintainer
-----------------------

Packaging must preserve the security contract. Release artifacts are intended
to be reproducible and verified against signed manifests.

* Reproducible builds: `Documentation/security/reproducible-builds.rst
  <Documentation/security/reproducible-builds.rst>`_
* Release and branch flow: `Documentation/contributor/branching.rst
  <Documentation/contributor/branching.rst>`_
* Production install gates:
  `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_
* systemd units: `systemd/ <systemd/>`_
* udev rules: `configs/udev/99-lota-tpm.rules
  <configs/udev/99-lota-tpm.rules>`_
* IMA policy: `configs/ima/lota-ima-policy <configs/ima/lota-ima-policy>`_
* SELinux policy: `selinux/README.rst <selinux/README.rst>`_

New contributor
---------------

Development happens on ``lota-next``. Open pull requests there, not against
``main``.

* Contribution rules: `CONTRIBUTING.rst <CONTRIBUTING.rst>`_
* Development and testing policy:
  `Documentation/contributor/development/index.rst
  <Documentation/contributor/development/index.rst>`_
* Branch model: `Documentation/contributor/branching.rst
  <Documentation/contributor/branching.rst>`_
* Local patch checks: ``scripts/check-patch``
* Commit-message normalizer: ``scripts/format-patch``
* Code of Conduct: `CODE_OF_CONDUCT.rst <CODE_OF_CONDUCT.rst>`_

Academic reviewer
-----------------

For thesis or architecture review, read the security model first, then the
production and measurement documents.

* Threat model: `Documentation/security/threat-model.rst
  <Documentation/security/threat-model.rst>`_
* Production bring-up: `Documentation/operator/production-bringup/index.rst
  <Documentation/operator/production-bringup/index.rst>`_
* Performance evaluation: `Documentation/performance/evaluation.rst
  <Documentation/performance/evaluation.rst>`_
* Reproducible builds: `Documentation/security/reproducible-builds.rst
  <Documentation/security/reproducible-builds.rst>`_
* Examples: `examples/README.rst <examples/README.rst>`_

Automated coding assistant
--------------------------

Automated tools must follow the same contribution rules as human contributors.
They must not weaken security checks, invent threat-model claims, remove DCO
trailers, or bypass documentation updates for changed behavior.

* Contribution rules: `CONTRIBUTING.rst <CONTRIBUTING.rst>`_
* Development policy: `Documentation/contributor/development/index.rst
  <Documentation/contributor/development/index.rst>`_
* Security reporting: `SECURITY.md <SECURITY.md>`_
* Local quality gate: ``scripts/check-patch``

Communication and support
=========================

* Security vulnerabilities: use GitHub Private Vulnerability Reporting for
  ``github.com/szymonwilczek/lota``; see `SECURITY.md <SECURITY.md>`_.
* General contribution process: see `CONTRIBUTING.rst <CONTRIBUTING.rst>`_.
* Conduct reports: see `CODE_OF_CONDUCT.rst <CODE_OF_CONDUCT.rst>`_.
* Release status and supported versions are documented in release notes and
  `Documentation/contributor/branching.rst
  <Documentation/contributor/branching.rst>`_.

Licensing
=========

Copyright (C) 2026 Szymon Wilczek.

LOTA is dual-licensed:

* The userspace components are licensed under the **MIT** license; the full
  text is in `LICENSE <LICENSE>`_. That includes the headers the agent and the
  BPF program share, because those carry LOTA's own definitions rather than
  anything derived from kernel source.
* Kernel-facing BPF programs are licensed **GPL-2.0-only**, as the kernel
  interface they attach to requires; the full text is in
  `LICENSE.GPL-2.0-only <LICENSE.GPL-2.0-only>`_.

Every source file carries an ``SPDX-License-Identifier`` naming the license
that applies to it, so the license of any individual file is unambiguous
regardless of which component it belongs to.
