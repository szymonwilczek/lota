# LOTA - Linux Open Trusted Attestation

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-red.svg)](LICENSE)

Transparent system integrity framework that proves to remote servers (e.g., game servers) that a Linux system is untampered.

# Read before anything else in this repository
I am incredibly absorbed in creating this project and I hope that one day it will become the standard in the Linux gaming industry. Stallman said that maybe it is TiVoization, but any solution seems better to me than none at all. The project has a long way to go before it becomes functional in any way, but if it succeeds, welcome anti-cheats on Linux, which brings with it another cheer: welcome gaming on our beloved penguin! (Of course, if any game developer wants to implement such a solution, heh.)

All corporations using anti-cheat software have rejected gaming on Linux because they are unable to trust us. I will try to ensure that there are no grounds for this.

## Overview

LOTA establishes a cryptographic chain of trust from hardware (TPM 2.0) through the kernel (eBPF/LSM) to a user-space agent, and finally to a remote verifier.

```
┌──────────────┐     ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  TPM 2.0     │ ──▶│ eBPF LSM    │ ──▶│  LOTA Agent  │ ──▶│   Remote     │
│  Hardware    │     │ Kernel      │     │  User-space  │     │   Verifier   │
└──────────────┘     └─────────────┘     └──────────────┘     └──────────────┘
     PCRs                Binary            Attestation           Validation
                       Monitoring             Report
```

## Features

- **Hardware Root of Trust**: TPM 2.0 PCR measurements for Measured Boot
- **IOMMU Verification**: Ensures VT-d/AMD-Vi is enabled (DMA attack protection)
- **Binary Execution Monitoring**: eBPF LSM hooks track all program executions
- **Challenge-Response Protocol**: Nonce-based attestation prevents replay attacks
- **CO-RE Support**: BPF program works across different kernel versions

## Requirements

### Hardware
- TPM 2.0 chip
- Intel VT-d or AMD-Vi IOMMU

### Kernel
- Linux 5.7+ with:
  - `CONFIG_BPF_LSM=y`
  - `CONFIG_DEBUG_INFO_BTF=y`
  - LSM includes `bpf` (check `/sys/kernel/security/lsm`)

### Fedora Dependencies

```bash
# Install development packages
sudo dnf install -y \
    clang llvm \
    libbpf-devel \
    tpm2-tss-devel \
    openssl-devel \
    bpftool

# Verify kernel configuration
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
# Expected: CONFIG_BPF_LSM=y

cat /sys/kernel/security/lsm
# Expected: should contain "bpf"
```

## Security Model

| Attack Vector | Protection |
|--------------|------------|
| Binary tampering | eBPF monitors all execve() |
| Kernel rootkits | Measured Boot (PCR 0-7) |
| DMA attacks | IOMMU verification |
| Replay attacks | Nonce in TPM Quote |
| Boot parameter tampering | PCR 8/9 measurement |


## Status

⚠️ **Definetly** `Not` ready for production use yet.
