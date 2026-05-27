# LOTA production bring-up

This document walks an operator through the full set of prerequisites
the `lota-agent` daemon enforces at startup. The agent is deliberately
strict: every gate documented below is a hard fail in production
because the corresponding bypass is part of the threat model (kernel
module load, ptrace, /proc/mem inspection, tampered BPF object,
PCR14 rebind, ...).

There is **no shortcut**. The full chain is documented here and automated
by `scripts/lota-dev-bringup.sh` for developer-host iteration.
Production hosts run the equivalent steps through their distro integrity
tooling (signed RPMs, kernel cmdline provisioned at install, IMA policy
from `/etc/sysconfig/integrity`, operator key in a sealed store).

## Startup gate matrix

The agent's startup chain refuses to load BPF / attach LSM programs
unless every entry below is satisfied. Source references are
file:line into the current tree.

| Gate                                          | Check site                                                                       | Operator action                                                                                                       |
|-----------------------------------------------|----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `lockdown=integrity` (or confidentiality)     | `src/agent/bpf_loader.c::kernel_lockdown_restrictive()`                          | Boot under Secure Boot or pass `lockdown=integrity` on the kernel cmdline.                                            |
| `module.sig_enforce=1`                        | `src/agent/bpf_loader.c::kernel_module_sig_enforced()`                           | Fedora 44 ships this by default. On distros that do not, add `module.sig_enforce=1` to the cmdline.                   |
| IMA appraisal policy active                   | `src/agent/bpf_loader.c::kernel_ima_appraisal_enabled()`                         | Boot with `ima=on ima_policy=appraise_tcb` OR write `configs/ima/lota-ima-policy` to `/sys/kernel/security/ima/policy` at boot. |
| `/dev/tpm{rm,}0` carries `lota_tpm_device_t`  | `src/agent/bpf_loader.c::tpm_device_selinux_label_ok()`                          | Install the udev rule under `configs/udev/99-lota-tpm.rules` (handled by `make install`) and run `udevadm trigger`.   |
| fs-verity on `/usr/bin/lota-agent`            | `src/agent/bpf_loader.c::agent_self_fsverity_enabled()`                          | Filesystem must have the verity feature enabled. Run `fsverity enable /usr/bin/lota-agent` (or let bring-up do it).   |
| BPF object Ed25519 signature                  | `src/agent/bpf_loader.c::verify_bpf_object_signature()`                          | Sign `lota_lsm.bpf.o` against the operator key, install the `.sig` next to the `.o`, point `policy_pubkey` at the PEM.|
| AIK persistent handle + metadata in sync      | `src/agent/tpm.c::tpm_aik_load_metadata()`                                       | Evict any stale persistent handle (`tpm2_evictcontrol`) before first start so the AIK metadata is initialised cleanly.|
| PCR14 fresh after boot                        | `src/agent/tpm.c::tpm_extend_boot_commitment()`                                  | Cold reboot before the first agent start; PCR14 only resets on hardware reset.                                        |

Every gate maps to a `lota_err()` line in the journal when it fails,
so `journalctl -u lota-agent` is the canonical debugging surface.

## Automated developer bring-up

`scripts/lota-dev-bringup.sh` runs the steps above in a fixed order:

```sh
sudo make install                                  # land agent + BPF + units
sudo scripts/lota-dev-bringup.sh                   # gate the host
sudo reboot                                        # PCR14 baseline rebind
sudo systemctl start lota-agent.socket lota-agent.service
sudo systemctl status lota-agent.service --no-pager
```

The script is idempotent and prints which step it ran or skipped so
re-runs after a partial failure are safe. Read it before running.

## Manual reference

### 1. Operator key + signed BPF object

```sh
sudo install -d -m 0700 /etc/lota
sudo /usr/bin/lota-agent --gen-signing-key /etc/lota/policy
sudo chmod 0600 /etc/lota/policy.key
sudo chmod 0644 /etc/lota/policy.pub
sudo /usr/bin/lota-agent --sign-policy /usr/lib/lota/lota_lsm.bpf.o \
    --signing-key /etc/lota/policy.key
```

Add `policy_pubkey = /etc/lota/policy.pub` to `/etc/lota/lota.conf`
(or copy `configs/lota.conf.example` and edit). The agent reads this
file by default; pass `--config /path` if the operator policy lives
elsewhere.

The `make sign-bpf SIGNING_KEY=/etc/lota/policy.key` target wires the
sign call into the build system for CI / packaging.

### 2. fs-verity on the agent binary

```sh
# Filesystem must support fs-verity. ext4 needs the feature enabled at
# mkfs time or via `sudo tune2fs -O verity /dev/sdX` on an unmounted
# device. btrfs / f2fs ship verity in 5.15+.
sudo fsverity enable /usr/bin/lota-agent
sudo fsverity measure /usr/bin/lota-agent
```

If `fsverity enable` returns `EOPNOTSUPP`, the filesystem feature is
off. Production lays this down at install time via dracut + fs-verity-enabled rootfs.

### 3. IMA appraisal policy

The agent's startup check accepts any IMA policy that contains an
`appraise` rule. On Fedora the simplest path is to boot with
`ima_policy=appraise` on the cmdline:

```sh
sudo grubby --update-kernel=ALL --args="ima=on ima_policy=appraise"
sudo reboot
```

For a runtime policy file (no reboot required) write the developer
baseline to `/sys/kernel/security/ima/policy`:

```sh
sudo cat configs/ima/lota-ima-policy >/sys/kernel/security/ima/policy
```

Production should ship its own IMA policy file with the matching
signature pipeline (`evmctl ima_sign`).

### 4. SELinux label on /dev/tpm

The udev rule from `configs/udev/99-lota-tpm.rules` lays this down on
device-add. After `make install`:

```sh
sudo udevadm control --reload-rules
sudo udevadm trigger /dev/tpmrm0 /dev/tpm0
ls -lZ /dev/tpm0 /dev/tpmrm0           # expect lota_tpm_device_t
```

### 5. AIK + PCR14 reset

The agent binds PCR14 against `(self_hash, resetCount, restartCount)`
once per boot. A re-install that changes the binary self-hash without
a cold reboot reports
`PCR14 holds a boot commitment from a different agent binary`. Wipe
the witness file and the persistent AIK, then reboot:

```sh
sudo systemctl stop lota-agent.service lota-agent.socket
sudo find /var/lib/lota -mindepth 1 -maxdepth 1 \
    \( -name 'aik*' -o -name 'clock*' -o -name 'boot_commit*' \
       -o -name 'snapshot*' \) -delete
for h in 0x81010002 0x81010003 0x81010004 0x81010005; do
    sudo tpm2_evictcontrol -C o -c "$h" 2>/dev/null || true
done
sudo reboot
```

After reboot the agent's first start provisions a fresh AIK and
extends PCR14 cleanly. Subsequent starts that follow a clean shutdown
reuse the witness so the gate is silent.

## What still fails after bring-up

The most common failures, with the gate that produced them:

- `Kernel anti-tamper prerequisites are not satisfied`. Check
  `cat /sys/kernel/security/lockdown` (must show `[integrity]` or
  `[confidentiality]`), `cat /sys/module/module/parameters/sig_enforce`
  (must be `Y`), and `cat /sys/kernel/security/ima/policy` (must
  contain `appraise`).
- `Agent binary is not fs-verity protected`. Re-run `fsverity enable`
  on `/usr/bin/lota-agent`. The verity merkle root is bound to the
  inode, so re-installs invalidate the bit; the bring-up script
  re-enables on every run.
- `BPF object signature verification failed`. The `.sig` is from a
  different key. Re-sign with the key that `policy_pubkey` points
  at, or update `policy_pubkey` to match the signing key.
- `Failed to load AIK metadata: Key has been revoked`. The TPM has
  a persistent AIK but the operator wiped `/var/lib/lota`. Either
  restore the metadata backup or evict the AIK handle and reboot so
  the agent re-provisions clean.
- `PCR14 holds an unexpected value`. Cold reboot. PCR14 only resets
  on hardware reset; warm reboot keeps the value.

## Threat model implications of the dev path

`scripts/lota-dev-bringup.sh` lays down a self-signed operator key
on disk in `/etc/lota`. That key is the trust root for every BPF
object the agent loads on this host. An attacker with root can
re-sign a tampered BPF object with the same key and the agent will
accept the load.

Production deployments treat the signing key as a sealed
infrastructure artefact: kept off-host, rotated through the
operator's PKI, and never present in `/etc/lota` on a live machine.
The bring-up script's key generation is explicitly developer-only.
