# LOTA - Linux Open Trusted Attestation

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-red.svg)](LICENSE)

Transparent system integrity framework that proves to remote servers (e.g., game servers) that a Linux system is untampered.

# Read before anything else in this repository

I am incredibly absorbed in creating this project and I hope that one day it will become the standard in the Linux gaming industry. Stallman said that maybe it is TiVoization, but any solution seems better to me than none at all. In the end I really \*don't care\*\* about the politics around, just on the technology behind it. You want it? You have it (when it will be ready), you don't want it? Fine, then no gaming or some sort. It's just an option, not a required way to run a fully blown distro. Linux will always be fully open-source, so if you don't want to give up the tinkering with the kernel - just have 2 of those and pick it up through GRUB or your desired bootloader. It's that simple.

The project is in active development toward its first functional release. If it succeeds, it could enable anti-cheat solutions on Linux, unlocking a broader gaming ecosystem on the platform.

Anti-cheat vendors have historically declined to support Linux because they cannot establish the same trust guarantees available on locked-down platforms. LOTA provides the missing cryptographic trust chain to address this gap.

## Overview

LOTA establishes a cryptographic chain of trust from hardware (TPM 2.0) through the kernel (eBPF/LSM) to a user-space agent, and finally to a remote verifier.

TPM 2.0 (Hardware: PCRs) -> eBPF LSM Kernel (Binary Monitoring) -> LOTA Agent User-Space (Attestation Report) -> Remote Verifier (Validation)

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

## Security Model

| Attack Vector            | Protection                 |
| ------------------------ | -------------------------- |
| Binary tampering         | eBPF monitors all execve() |
| Kernel rootkits          | Measured Boot (PCR 0-7)    |
| DMA attacks              | IOMMU verification         |
| Replay attacks           | Nonce in TPM Quote         |
| Boot parameter tampering | PCR 8/9 measurement        |

## Status

⚠️ **Heavily** in `development`.

I don't even want to give up the setting up this project in the README right now (of course it can be done, I documented it inside the code), but it instantly reducing the number of people trying to get this to work on right now.
