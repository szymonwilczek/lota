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

Run the LOTA agent on the target system to collect PCR values:

```bash
# Export PCR baseline to stdout
sudo lota-agent --export-baseline > my-baseline.yaml

# Or redirect diagnostic output
sudo lota-agent --export-baseline 2>/dev/null > my-baseline.yaml
```

### 2. Customize Policy

Copy the relevant values into a new policy file:

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

## TOFU (Trust On First Use)

PCR 14 (LOTA self-measurement) uses TOFU semantics:

- First attestation: PCR 14 value is stored as baseline
- Subsequent attestations: PCR 14 must match baseline

This allows deployment without pre-computing every agent hash while still
detecting tampering after initial enrollment.

## Updating Policies

When software is updated:

1. Update `kernel_hashes` when kernel is upgraded
2. Update `agent_hashes` when LOTA agent is upgraded
3. PCR 0/7 typically only change with firmware updates
4. Clear TOFU baseline if agent binary changes legitimately

```bash
# Re-export baseline after updates
sudo lota-agent --export-baseline > updated-baseline.yaml
```
