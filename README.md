Linux Open Trusted Attestation
==============================

Linux Open Trusted Attestation, or LOTA, is a Linux attestation and
runtime-integrity framework.

It lets a remote verifier or game server decide
whether a host was enrolled through a manufacturer-backed TPM, booted into an
approved firmware and Secure Boot state, runs the expected LOTA agent image,
and enforces the configured runtime gates through BPF LSM.

LOTA is **not** a behavioral anti-cheat engine. It does **not** scan gameplay state,
input, memory signatures, or network behavior. It provides a hardware-backed
trust substrate that game, anti-cheat, fleet, or relying-party policy can build
on top of.

Trust Chain Overview
--------------------

The production trust chain is:

```text
TPM 2.0 EK certificate --> Attestation CA (1) --> LOTA agent (2) --> Verifier / SDK consumer (3)

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
```

The verifier trusts a CA-issued AIK certificate, not an agent-asserted public
key. Firmware and Secure Boot state are pinned through PCR 0, PCR 1, and PCR 7.
LOTA's own boot commitment is bound through PCR14. Runtime protection is
enforced by the agent and BPF LSM hooks, with fs-verity, SELinux, lockdown,
module signing, and signed BPF objects forming the production floor.

For the complete security boundary, read
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

Quick Start
-----------

* Build the tree:
  `env GOCACHE=/tmp/lota-gocache make BUILD_DIR=/tmp/lota-build all`
* Run unit tests:
  `env GOCACHE=/tmp/lota-gocache make BUILD_DIR=/tmp/lota-build test-unit`
* Build optional examples: `make examples`
* Bring up a production host: see
  [`docs/PRODUCTION_BRINGUP.md`](docs/PRODUCTION_BRINGUP.md)
* Run the end-to-end demo material: see
  [`examples/README.md`](examples/README.md)
* Report a vulnerability: see [`SECURITY.md`](SECURITY.md)
* Contribute a patch: see [`CONTRIBUTING.md`](CONTRIBUTING.md)

Build inputs include a C toolchain, clang/LLVM for BPF, libbpf, TPM2-TSS,
OpenSSL, systemd, libseccomp, D-Bus headers, and Go for the verifier and
attestation CA.

Authoritative build and test policy is in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

Essential Documentation
-----------------------

All users should know where these documents live:

* Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
* Production bring-up: [`docs/PRODUCTION_BRINGUP.md`](docs/PRODUCTION_BRINGUP.md)
* Development and testing policy: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
* Branch and release flow: [`docs/BRANCHING.md`](docs/BRANCHING.md)
* Reproducible builds: [`docs/BUILD-REPRODUCIBLE.md`](docs/BUILD-REPRODUCIBLE.md)
* Performance evaluation: [`docs/PERF.md`](docs/PERF.md)
* PCR policies: [`policies/README.md`](policies/README.md)
* SELinux policy: [`selinux/README.md`](selinux/README.md)
* EK root bundle material: [`configs/ek-roots/README.md`](configs/ek-roots/README.md)
* Security reporting: [`SECURITY.md`](SECURITY.md)
* Code of Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

Repository Map
--------------

* `src/agent/` - privileged host agent, TPM interaction, BPF loading, IPC,
  reporting, enrollment, and runtime measurement.
* `src/bpf/` - BPF LSM enforcement programs.
* `src/initramfs/` - PCR14 initramfs lock helper and dracut integration.
* `src/attestca/` - attestation CA and TPM credential-activation service.
* `src/verifier/` - verifier, policy engine, stores, API server, nonce
  handling, revocation, and report validation.
* `src/sdk/` and `include/` - C SDK, server SDK, token formats, and public
  integration headers.
* `policies/`, `configs/`, `systemd/`, `selinux/`, and `dbus/` - production
  deployment policy and service material.
* `examples/` - enrollment, demo server, anti-cheat heartbeat, game UI,
  sealed-key, mTLS, runtime remeasurement, and blocking scenarios.
* `benchmarks/` and `syzkaller/` - performance and kernel-surface validation
  material.

Who Are You?
============

* Operator - deploying the agent and verifier on real hosts.
* Game or anti-cheat integrator - consuming trust verdicts and SDK tokens.
* Security reviewer - auditing the trust model and reporting vulnerabilities.
* TPM or attestation engineer - reviewing enrollment, EK roots, AIKs, and PCRs.
* Kernel or BPF engineer - reviewing runtime gates and LSM portability.
* Distribution maintainer - packaging, signing, and reproducing releases.
* New contributor - preparing patches against `lota-next`.
* Academic reviewer - evaluating design, threat model, and measurements.
* Automated coding assistant - following project contribution rules.

For Specific Users
==================

Operator
--------

Production operation starts with the bring-up document. The agent intentionally
fails closed when required gates are missing.

* Production checklist: [`docs/PRODUCTION_BRINGUP.md`](docs/PRODUCTION_BRINGUP.md)
* PCR policy templates: [`policies/README.md`](policies/README.md)
* SELinux policy: [`selinux/README.md`](selinux/README.md)
* EK root bundles: [`configs/ek-roots/README.md`](configs/ek-roots/README.md)
* Example configuration: [`configs/lota.conf.example`](configs/lota.conf.example)
* Re-enrollment flow: [`examples/enrollment/README.md`](examples/enrollment/README.md)

Game or Anti-Cheat Integrator
-----------------------------

LOTA exposes trust decisions and token verification material. Gameplay policy
remains outside this repository.

* Example index: [`examples/README.md`](examples/README.md)
* Reference server: [`examples/demo_server/README.md`](examples/demo_server/README.md)
* Anti-cheat heartbeat producer:
  [`examples/demo_anticheat/README.md`](examples/demo_anticheat/README.md)
* Demo game client: [`examples/demo_game/README.md`](examples/demo_game/README.md)
* End-to-end demo: [`examples/demo/README.md`](examples/demo/README.md)
* mTLS example: [`examples/mtls/README.md`](examples/mtls/README.md)
* Runtime remeasurement:
  [`examples/runtime_remeasure/README.md`](examples/runtime_remeasure/README.md)

Security Reviewer
-----------------

Start with the threat model and the security reporting policy. Do not file
public issues for exploitable vulnerabilities.

* Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
* Security reporting: [`SECURITY.md`](SECURITY.md)
* Reproducible release verification:
  [`docs/BUILD-REPRODUCIBLE.md`](docs/BUILD-REPRODUCIBLE.md)
* Production bring-up: [`docs/PRODUCTION_BRINGUP.md`](docs/PRODUCTION_BRINGUP.md)
* Development tests and fuzzing: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
* Performance baseline: [`docs/PERF.md`](docs/PERF.md)

TPM or Attestation Engineer
---------------------------

The hardware trust contract is centered on EK root validation, credential
activation, AIK certificates, TPM quotes, PCR policy, and PCR14 boot
commitment.

* Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
* Enrollment example: [`examples/enrollment/README.md`](examples/enrollment/README.md)
* EK root bundles: [`configs/ek-roots/README.md`](configs/ek-roots/README.md)
* PCR policy documentation: [`policies/README.md`](policies/README.md)
* Production bring-up: [`docs/PRODUCTION_BRINGUP.md`](docs/PRODUCTION_BRINGUP.md)

Kernel or BPF Engineer
----------------------

The kernel-facing surface lives in the BPF LSM object, loader, runtime
measurement path, initramfs PCR14 lock, SELinux policy, and Syzkaller harness.

* BPF and production gates: [`docs/PRODUCTION_BRINGUP.md`](docs/PRODUCTION_BRINGUP.md)
* SELinux policy: [`selinux/README.md`](selinux/README.md)
* Kernel test policy: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
* Syzkaller harness: [`syzkaller/README.md`](syzkaller/README.md)
* Runtime remeasurement example:
  [`examples/runtime_remeasure/README.md`](examples/runtime_remeasure/README.md)

Distribution Maintainer
-----------------------

Packaging must preserve the security contract. Release artifacts are intended
to be reproducible and verified against signed manifests.

* Reproducible builds: [`docs/BUILD-REPRODUCIBLE.md`](docs/BUILD-REPRODUCIBLE.md)
* Release and branch flow: [`docs/BRANCHING.md`](docs/BRANCHING.md)
* Production install gates: [`docs/PRODUCTION_BRINGUP.md`](docs/PRODUCTION_BRINGUP.md)
* systemd units: [`systemd/`](systemd/)
* udev rules: [`configs/udev/99-lota-tpm.rules`](configs/udev/99-lota-tpm.rules)
* IMA policy: [`configs/ima/lota-ima-policy`](configs/ima/lota-ima-policy)
* SELinux policy: [`selinux/README.md`](selinux/README.md)

New Contributor
---------------

Development happens on `lota-next`. Open pull requests there, not against
`main`.

* Contribution rules: [`CONTRIBUTING.md`](CONTRIBUTING.md)
* Development and testing policy: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
* Branch model: [`docs/BRANCHING.md`](docs/BRANCHING.md)
* Local patch checks: `scripts/check-patch`
* Commit-message normalizer: `scripts/format-patch`
* Code of Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

Academic Reviewer
-----------------

For thesis or architecture review, read the security model first, then the
production and measurement documents.

* Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
* Production bring-up: [`docs/PRODUCTION_BRINGUP.md`](docs/PRODUCTION_BRINGUP.md)
* Performance evaluation: [`docs/PERF.md`](docs/PERF.md)
* Reproducible builds: [`docs/BUILD-REPRODUCIBLE.md`](docs/BUILD-REPRODUCIBLE.md)
* Examples: [`examples/README.md`](examples/README.md)

Automated Coding Assistant
--------------------------

Automated tools must follow the same contribution rules as human contributors.
They must not weaken security checks, invent threat-model claims, remove DCO
trailers, or bypass documentation updates for changed behavior.

* Contribution rules: [`CONTRIBUTING.md`](CONTRIBUTING.md)
* Development policy: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
* Security reporting: [`SECURITY.md`](SECURITY.md)
* Local quality gate: `scripts/check-patch`

Communication and Support
=========================

* Security vulnerabilities: use GitHub Private Vulnerability Reporting for
  `github.com/szymonwilczek/lota`; see [`SECURITY.md`](SECURITY.md).
* General contribution process: see [`CONTRIBUTING.md`](CONTRIBUTING.md).
* Conduct reports: see [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
* Release status and supported versions are documented in release notes and
  [`docs/BRANCHING.md`](docs/BRANCHING.md).

Licensing
=========

Source files carry SPDX license identifiers. The userspace components are
primarily MIT-licensed. Kernel-facing BPF and shared kernel-contract headers
use GPL-2.0-only where required by the Linux kernel interface.
