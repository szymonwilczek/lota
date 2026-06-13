# LOTA Threat Model

This document states what LOTA is designed to protect, what the current
implementation enforces, and what remains outside its boundary.

## Security Objectives

LOTA provides a hardware-backed attestation substrate for Linux hosts. It is NOT
a behavioral cheat detector.

The protected properties are:

- the attesting key is bound to a manufacturer-certified TPM through TPM 2.0
  credential activation,
- the verifier accepts only AIK certificates issued by the deployment's
  attestation CA,
- the TPM quote is fresh and bound to verifier-provided nonce material,
- firmware and Secure Boot state are pinned through PCR 0, PCR 1, and PCR 7,
- Secure Boot enablement and the kernel command line are enforced
  machine-independently from the quote-bound TPM event log,
- LOTA's boot commitment is bound through PCR14,
- the agent binary and runtime-protected executable image are measured and
  bound into attestation or token material,
- kernel-side enforcement gates executable mappings, ptrace, kernel module
  loading, and protected process mutation through BPF LSM programs,
- release artifacts can be rebuilt and checked against signed hashes.

An integrator can build game-specific or fleet-specific policy on top of these
properties. LOTA does not inspect gameplay behavior, memory signatures, network
patterns, or user input.

## Trust Boundaries

### Host

The host runs a TPM 2.0 device, Linux with BPF LSM support, SELinux enforcing
mode for the packaged policy, kernel lockdown, module signature enforcement,
IMA appraisal, fs-verity, and the LOTA agent.

The IMA appraisal requirement pins the kernel's appraisal *mode*
(`ima_appraise=enforce|fix` on the command line); the appraisal *content* -
file signatures and the rule set - is distribution- or operator-supplied
(see [`PRODUCTION_BRINGUP.md`](PRODUCTION_BRINGUP.md)). LOTA ships no
xattr-signing pipeline, and its own binaries are integrity-bound through
fs-verity and the PCR14 boot commitment independent of IMA.

The agent is privileged. It owns TPM interaction, BPF LSM loading, runtime
measurement, local IPC, D-Bus status, and attestation report construction.

### Attestation CA

The attestation CA verifies the EK certificate chain, runs credential
activation against the TPM, and issues a short-lived AIK certificate. Verifiers
trust the CA certificate, not an agent-asserted public key.

The CA key is a high-value fleet secret. It is loaded as a `crypto.Signer`, so
both an on-disk PKCS#8 PEM (the explicit dev-only fallback) and a PKCS#11 token
(HSM or SoftHSM, built with the `pkcs11` tag) are supported. Production
deployments hold the key in an HSM; the on-disk path is logged loudly and is
never the production default. See [`CA-KEY.md`](CA-KEY.md).

### Verifier

The verifier validates AIK certificates, TPM quotes, PCR policy, event logs,
boot commitments, runtime protection digests, token nonces, revocations, and
ban state.

The default store is SQLite for single-node deployments. A Postgres backend
(selected with `--pg-dsn`) holds the baseline, used-nonce, revocation, ban,
audit, attestation and session-token state in a shared database, so several
verifier instances behind a load balancer share enforcement state and any
instance validates a session token issued by any peer. See
[`HA_DEPLOYMENT.md`](HA_DEPLOYMENT.md) for the supported topologies.

### SDK Consumer

The game, anti-cheat service, or relying server consumes LOTA status and token
verification results. It remains responsible for gameplay policy and behavioral
detection.

## Active Threats

| Threat | LOTA control | Residual risk |
| ------ | ------------ | ------------- |
| Software-only fake attester | Enrollment requires TPM 2.0 credential activation. The CA issues an AIK certificate only after proving the AIK and EK live in the same TPM. | A verifier must run with the production CA trust root and certificate requirement enabled. |
| Replayed attestation | Verifier challenges are one-time nonces with expiry and used-nonce tracking. The TPM quote covers a binding nonce. | Clock and storage availability are operational dependencies for replay tracking. |
| Agent-asserted report metadata | The attestation binding nonce covers hardware identity, signed flags, kernel hash, agent hash, and IOMMU status before verification of `TPMS_ATTEST.extraData`. | Metadata outside that binding must not be promoted to security decisions without extending the binding. |
| Firmware or Secure Boot drift | Production policy pins PCR 0, PCR 1, and PCR 7 for homogeneous fleets. Diverse fleets enroll each device's PCR 0/1/7 on first use, but only when the event-log Secure Boot gate is active and the report proves Secure Boot enabled; the per-device row then anchors rollback/consistency and any later drift rejects. | Firmware updates require deliberate policy rotation. Raw pins do not scale to diverse single-machine populations; the event-log checks below cover those. On the diverse-fleet path, firmware tampering that keeps Secure Boot enabled and predates the device's first attestation is not caught at first use - firmware trust there rests on the Secure Boot and command-line gates, not on the PCR 0/1 values. The agent additionally reports the ESRT System Firmware version (telemetry) so a future self-service re-anchor can use it as a firmware anti-rollback signal; being firmware-reported it is meaningful only in combination with an unchanged PCR 7 keyset, not as an independent control. A re-anchor archives the superseded PCR 0/1/7 row rather than overwriting it, so a re-baseline is auditable after the fact; on an HA deployment the archive and the re-anchor bookkeeping live in the shared Postgres store so every verifier instance sees the same history. The re-anchor discriminator admits a drift only when it preserves the Secure Boot root of trust: PK/KEK/db byte-identical by event-log replay, dbx append-only (revocation can grow, never shrink), Secure Boot still enabled, and the firmware version not rolled back; anything touching PK/KEK/db escalates to the operator. |
| Secure Boot disabled to boot a tampered kernel | The verifier reads the firmware-measured `SecureBoot` variable from the event log (PCR 7) and accepts it only when the log replay reproduces the TPM-quoted PCR, so the value cannot be fabricated or stripped. The agent-reported Secure Boot flag is telemetry only. | Kernels signed for Secure Boot (including operator/MOK-signed) pass; the control rejects unsigned boots, not signed-but-malicious kernels. |
| Signed kernel sabotaged via command line (`init=`, `rd.break`, `lockdown=none`, ...) | The verifier checks the GRUB-measured kernel command line (PCR 8 event log, quote-bound) against a machine-independent parameter denylist; a non-zero quoted PCR 8 with no measured command line is rejected as a truncated log. | GRUB-only today: systemd-boot/UKI hosts measure the command line into PCR 12 and skip this check (Secure Boot enforcement still applies). Denylist coverage is enumerative, not semantic. |
| Agent binary drift | PCR14 boot commitment and agent hash policy bind the agent image. fs-verity protects the installed binary. | Replacing the agent binary requires cold reboot, fs-verity re-enable, policy update, and re-attestation. |
| Early PCR14 tamper | Initramfs PCR14 lock runs before normal userspace; udev and SELinux restrict TPM device access; systemd ordering starts the agent before login-capable targets. | PCR14 is OS-writable by the PC Client Profile. Userspace cannot make that race impossible on every platform. |
| Runtime image substitution | BPF LSM gates executable mmap and mprotect for protected processes against the fs-verity allow-list. The agent re-measures file-backed executable mappings from the kernel side. | Anonymous executable memory and JIT code are not measured as modules. The intended bound is W^X plus policy enforcement. |
| ptrace or process mutation | BPF LSM hooks protect the agent and protected PIDs, including `__ptrace_may_access` where available. | Hook availability and verifier behavior must be validated on the target kernel. |
| Kernel module or memory-only load | Kernel lockdown, module signature enforcement, and BPF LSM gates reject unsafe load paths. | A kernel vulnerability or disabled production gate is outside LOTA's software boundary. |
| DMA attack | The agent reports IOMMU state and production policy can require it. | Platform firmware and hardware must actually expose and enable the IOMMU. |
| EK certificate spoofing | The CA verifies EK certificate chains against pinned manufacturer roots, with bundled intermediates as path material for the common leaf-intermediate-root manufacturer shape. | A deployment must ship verified roots and the issuing intermediates for the supported TPM vendors or narrow supported hardware accordingly. |
| Revoked or factorable endorsement key | Enrollment checks the EK certificate against operator-loaded manufacturer CRLs (SIGHUP-refreshable); a revoked EK, or one whose issuer has only stale CRLs, is refused before credential activation. An EK whose RSA modulus carries the ROCA (CVE-2017-15361) fingerprint is rejected outright, independent of CRL coverage. | An issuer with no configured CRL is not CRL-checked; operators must load the feed for every manufacturer that publishes one. The intrinsic-weakness check covers only ROCA; other key-generation flaws need their manufacturer revocation feed. |
| Supply-chain artifact swap | Reproducible builds and cosign-signed `SHA256SUMS` bind released artifacts to the source tag and release workflow identity. | Consumers must verify the signed manifest and rebuild with the documented toolchain. |
| Remote MITM | Enrollment and verifier communication use TLS, with examples using explicit CA material rather than disabled verification. | Operators must provision and rotate TLS certificates correctly. |

## STRIDE Mapping

| STRIDE class | LOTA treatment |
| ------------ | -------------- |
| Spoofing | TPM credential activation, CA-issued AIK certificates, TLS server authentication, mTLS demo for SDK-server integration. |
| Tampering | PCR policy, PCR14 boot commitment, fs-verity, signed BPF objects, BPF LSM gates, SELinux confinement. |
| Repudiation | Verifier logs attestation decisions, nonce use, baseline changes, and AIK state. Release artifacts are signed through Sigstore. |
| Information disclosure | Verifiers receive CA-issued pseudonyms rather than EK certificates. Reports should not expose EK material after enrollment. |
| Denial of service | Rate limits and nonce limits bound challenge pressure. Local enforcement may intentionally fail closed when production gates are missing. |
| Elevation of privilege | LOTA reduces post-boot tamper paths through lockdown, module signing, BPF LSM, SELinux, and ptrace restrictions. It does not replace the kernel's own privilege boundary. |

## Explicit Non-Goals

- Detecting cheat behavior by scanning memory, input, game state, or network
  patterns.
- Supporting hosts that intentionally disable lockdown, module signature
  enforcement, SELinux enforcing mode, fs-verity, IMA appraisal, or TPM access
  control required by production policy.
- Proving the runtime integrity of the kernel. Measured boot binds the kernel
  *image* that was loaded (see "Root of trust" below); it cannot prove that a
  kernel which booted clean stays honest, because a kernel compromised at
  runtime (a 0-day, a signed-but-vulnerable driver, a DMA write) produces the
  same boot measurements and sits inside the TCB that produces the agent's
  measurements. A measurement produced by layer N cannot bootstrap trust in
  layer N.
- Measuring anonymous executable memory as a trusted module set.
- Making PCR14 immutable from userspace on platforms where the TPM profile
  leaves it OS-writable.
- Replacing operator key management, CA key ceremony, or release governance.

## Root of trust: static measured boot (SRTM), not DRTM

LOTA roots its boot measurements in the platform's Static Root of Trust for
Measurement (SRTM): the firmware measures itself, the Secure Boot policy, and
the boot chain into the TPM, and the boot chain measures the kernel image,
command line, and initrd before the kernel runs. LOTA pins PCR 0/1/7 (firmware,
platform config, Secure Boot) and PCR 14 (its own boot commitment) today; the
kernel-image PCRs from the same SRTM (PCR 4, and PCR 8/9 on GRUB or 11/12/13 on
systemd-boot/UKI) are available to deployments that also pin them. Because these
measurements are taken before the kernel executes and are extended into hardware
PCRs, a compromised kernel cannot forge them after the fact. The practical trust
anchor for "a trusted kernel booted" is PCR 7: it reflects the Secure Boot
signing chain and stays constant across kernel updates, so a fleet trusts the
distribution's signing key without maintaining a per-kernel hash.

Dynamic Root of Trust for Measurement (DRTM) - Intel TXT, AMD SKINIT, driven
on Linux by the TrenchBoot / Secure Launch project - would re-measure the
kernel from a CPU-rooted late launch into PCR 17-22, removing the firmware and
bootloader from the trusted computing base. LOTA does not adopt DRTM, for two
reasons that are structural, not temporary:

- It is not universal. DRTM requires specific hardware and firmware (Intel TXT
  with a chipset-signed SINIT ACM, or AMD SKINIT, plus IOMMU, plus firmware
  enablement that consumer boards frequently hide or omit) and bleeding-edge
  kernel and bootloader support. LOTA targets every machine with a TPM 2.0 and
  a recent Linux, including ordinary gaming hosts; a feature gated on
  server-class platform configuration cannot be part of that baseline.
- It cannot be validated without that hardware. DRTM relies on real CPU
  instructions and signed ACMs that swtpm and the usual emulators do not
  provide, so the path cannot be exercised in CI or on a developer workstation.

DRTM also does not remove the need for a reference value: it relocates the root
of trust but still produces a measurement that an operator must compare against
a pinned value or a signature, so it does not lower the maintenance burden it is
sometimes assumed to. Runtime kernel integrity therefore remains out of scope;
deployments that require it must add a layer below the kernel (DRTM, a measuring
hypervisor, or a confidential-computing TEE) outside LOTA.

## Validation Status

The software paths are covered by local build, unit, fuzz, and integration
tests as documented in [`docs/DEVELOPMENT.md`](DEVELOPMENT.md).

Hardware TPM validation remains required for release claims that depend on
physical TPM behavior. swtpm validation is useful for protocol and regression
coverage, but it is not a substitute for running the full enrollment,
attestation, and runtime protection path on target hardware.

## Operational Requirements

Production deployments must:

- install the agent, systemd units, SELinux policy, udev TPM labeling, IMA
  policy, and signed BPF object,
- enroll each host through the attestation CA (enrollment requires an RSA
  endorsement key, the TCG EK template H-1 that every TPM 2.0 ships, and an
  RSA AIK; an ECC EK is refused at the start of the ceremony),
- configure verifiers with the CA root and a production PCR policy,
- maintain EK root bundles for the supported TPM vendors,
- verify release manifests before shipping binaries,
- validate BPF LSM hook attachment on the target kernel and distribution,
- document operator recovery for AIK rotation, policy rotation, and legitimate
  binary updates.

See [`docs/PRODUCTION_BRINGUP.md`](PRODUCTION_BRINGUP.md),
[`policies/README.md`](../policies/README.md), and
[`selinux/README.md`](../selinux/README.md) for the deployment details.
