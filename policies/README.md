# LOTA PCR Policies

This directory contains PCR (Platform Configuration Register) policy templates
for the LOTA verifier.

## Policy Files

| File              | Purpose                                             |
| ----------------- | --------------------------------------------------- |
| `testing.yaml`    | Minimal policy for development/testing environments |
| `production.yaml` | Template for production deployments                 |
| `strict.yaml`     | High-security policy for competitive gaming         |

## Creating Custom Policies

### 1. Export Baseline from Target System

Run the LOTA agent on the target system to generate a complete policy:

```bash
# Export full policy YAML to file
sudo lota-agent --export-policy > my-policy.yaml

# Or redirect diagnostic output
sudo lota-agent --export-policy 2>/dev/null > my-policy.yaml
```

### 2. Customize Policy

The exported policy is ready to use as-is. Optionally edit to:

- Remove PCR values you don't want to enforce
- Adjust security requirements
- Change the policy name

```yaml
name: my-production
description: "My production environment policy"

pcrs:
  0: "abc123..." # From baseline export
  7: "def456..." # From baseline export

kernel_hashes:
  - "sha256_hash_of_vmlinuz"

agent_hashes:
  - "sha256_hash_of_lota_agent"

require_iommu: true
require_enforce: true
```

### 3. Deploy Policy

```bash
# Start verifier with custom policy
lota-verifier --policy /path/to/my-policy.yaml
```

## PCR Meanings (SHA-256 Bank)

| PCR   | Measured By | Description                               |
| ----- | ----------- | ----------------------------------------- |
| 0     | UEFI        | SRTM - firmware code measurements         |
| 1     | UEFI        | UEFI configuration data                   |
| 2     | UEFI        | Option ROM code                           |
| 3     | UEFI        | Option ROM configuration                  |
| 4     | UEFI        | Boot loader code (GRUB/systemd-boot)      |
| 5     | UEFI        | GPT/MBR partition table                   |
| 6     | UEFI        | Resume from S4/S5 state transitions       |
| 7     | UEFI        | Secure Boot state (policies/certificates) |
| 8     | OS          | Kernel command line (grub2 measured boot) |
| 9     | OS          | Linux IMA measurements (if enabled)       |
| 10    | OS          | IMA verified measurements                 |
| 11-13 | OS          | Application-defined                       |
| 14    | LOTA        | Agent self-measurement                    |
| 15    | OS          | Reserved                                  |
| 16-23 | Apps        | Application use                           |

## Security Requirements

| Requirement          | Description                         | Typical Default    |
| -------------------- | ----------------------------------- | ------------------ |
| `require_iommu`      | DMA protection via VT-d/AMD-Vi      | `true`             |
| `require_enforce`    | SELinux/AppArmor in enforce mode    | `true`             |
| `require_module_sig` | Kernel module signature enforcement | Distro-dependent   |
| `require_secureboot` | UEFI Secure Boot enabled            | Hardware-dependent |
| `require_lockdown`   | Kernel lockdown mode active         | `false` (optional) |

## Boot enrollment ceremony

The production verifier defaults to
`VerifierConfig.RequireBootEnrollment = true`. Under that default the
verifier rejects any client whose PCR 0, PCR 1, or PCR 7 cannot be
matched against a known-good baseline. Two paths satisfy that contract:

1. **Pinned policy (recommended).** The operator commits real PCR 0/1/7
   values into the YAML policy (production.yaml or strict.yaml) before
   the first attestation. New clients are accepted only when their
   live PCR 0/1/7 match those pins. This is the path the production
   template above is wired for.
2. **Out-of-band boot enrollment.** The operator runs
   `lota-agent --export-policy` on a single known-good host, signs the
   resulting policy, and ships it to the fleet; subsequent clients
   inherit the PCR 0/1/7 baseline from the signed policy without
   contacting the verifier first.

A short-lived `--allow-tofu-boot-baseline` switch on the verifier exists
for closed test fixtures. It explicitly weakens the contract above by
accepting whatever PCR 0/1/7 the first attestation reports; the verifier
emits a warning-level log line on every accept under that switch and the
operator must turn it back off before the deployment is considered
production.

PCR 14 (LOTA agent self-measurement) is not TOFU. It is derived
deterministically from the boot-commitment chain
(`tpm_boot_commitment_digest`) and the verifier rederives the same
value during signature verification; an agent rebuild that legitimately
changes the self-measurement is handled by updating the signed policy
rather than by trusting whatever value the next attestation happens to
report.

## Updating Policies

When software is updated:

1. Update `kernel_hashes` when kernel is upgraded
2. Update `agent_hashes` when LOTA agent is upgraded
3. PCR 0/7 typically only change with firmware updates
4. Clear TOFU baseline if agent binary changes legitimately

```bash
# Re-export policy after updates
sudo lota-agent --export-policy > updated-policy.yaml
```
