# LOTA - Linux Open Trusted Attestation

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-red.svg)](LICENSE)

Transparent system integrity framework that proves to remote servers (e.g., game servers) that a Linux system is untampered.

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

## Building

```bash
# Clone repository
git clone https://github.com/youruser/lota.git
cd lota

# Generate vmlinux.h (if not present)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

# Build
make

# Build outputs:
#   build/lota-agent       - User-space daemon
#   build/lota_lsm.bpf.o   - eBPF LSM program
```

## Usage

### Test IOMMU Verification
```bash
sudo ./build/lota-agent --test-iommu
```

### Test TPM Operations
```bash
sudo ./build/lota-agent --test-tpm
```

### Run Agent (Monitor Mode)
```bash
sudo ./build/lota-agent --bpf ./build/lota_lsm.bpf.o
```

## Security Model

| Attack Vector | Protection |
|--------------|------------|
| Binary tampering | eBPF monitors all execve() |
| Kernel rootkits | Measured Boot (PCR 0-7) |
| DMA attacks | IOMMU verification |
| Replay attacks | Nonce in TPM Quote |
| Boot parameter tampering | PCR 8/9 measurement |

## License

- User-space code: MIT License
- eBPF/kernel code: GPL-2.0 (required for BPF)

## Status

⚠️ **Definetly** `Not` ready for production use yet.
