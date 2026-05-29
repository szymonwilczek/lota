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
| IMA appraisal in an enforcing mode            | `src/agent/bpf_loader.c::kernel_ima_appraise_enforcing()`                        | Add `ima_appraise=enforce` (or `fix`) to the kernel cmdline. `log` and the default `off` do not satisfy the gate. |
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

The agent parses `/proc/cmdline` and refuses to start unless
`ima_appraise=enforce` (block on integrity failure) or
`ima_appraise=fix` (block on signature failure, write missing
xattrs) is present. `ima_appraise=log` and the default `off` are
non-blocking and do not satisfy the kernel-floor. The check does
not read `/sys/kernel/security/ima/policy` because that file is
write-only on kernels built without `CONFIG_IMA_READ_POLICY`
(Fedora 44's default).

```sh
sudo grubby --update-kernel=ALL --args="ima=on ima_appraise=enforce"
sudo reboot
```

The cmdline only sets the appraisal mode; the kernel still needs a
loaded IMA policy with `appraise` rules for any path to be checked.
On Fedora the built-in `ima_policy=appraise_tcb` covers the TCB
ranges, but on a rootfs without IMA xattrs it bricks the host at
the next boot. Pre-populate xattrs with `ima_appraise=fix` for one
boot (the kernel writes missing signatures from `evmctl ima_sign`
output as it walks the matched paths) before switching to
`enforce`, or ship a narrow policy that only appraises the LOTA
binary closure (`/usr/bin/lota-agent`, `/usr/lib/lota/*.bpf.o`):

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
  (must be `Y`), and `grep -oE 'ima_appraise=\w+' /proc/cmdline`
  (must report `enforce` or `fix`).
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

## Operational constraints

### Agent restart requires reboot

The agent's `lota_task_kill` LSM hook blocks `SIGTERM` and `SIGKILL`
delivered from any other task -- including PID 1 -- because the
hook treats the agent itself as a protected target. This is the
load-bearing surface that prevents a local-root attacker from
killing the agent out of band, dropping the BPF coverage, and
swapping a tampered binary into place before the next attestation.

The trade-off is that `systemctl restart lota-agent` does **not**
work the way it does for other units. After the stop request, the
old process keeps running, refuses to release `/run/lota/lota.sock`
and the BPF maps, and the next `ExecStart=` fails with `-EPERM`
when libbpf tries to recreate the same map names. The unit then
loops on `Restart=on-failure` while the original PID stays alive
forever.

Two supported paths exist:

1. **Graceful via IPC.** `ExecStop=/usr/bin/lota-agent --shutdown`
   sends a privileged IPC command to the running agent; the
   handler sets `g_agent.running = 0`, which exits the daemon loop
   cleanly. As long as the IPC socket is reachable and the agent
   is not wedged in a syscall, this is the canonical update path
   and does not require a reboot.

2. **Cold reboot.** If the IPC path is unreachable (agent hang,
   socket gone, kernel deadlock) the only remaining recovery is
   to reboot the host. There is no kill-bypass for PID 1 and there
   never will be: every grace window would be an attack surface for
   an init-domain compromise. Operators planning updates therefore
   schedule them alongside a regular maintenance reboot.

### VM testing caveats

The supported development environment is a KVM guest with a swTPM
backend attached over TIS. Two behaviours diverge from bare metal
and the agent's startup gates treat them as integrity violations
unless the operator works around them.

- **swTPM persists state across guest reboots.** The TPM resource
  manager runs as a host process backed by an NV state file. A
  `sudo reboot` inside the guest does **not** reset the TPM and
  even `sudo virsh destroy fedora-lota && sudo virsh start
  fedora-lota` from the host keeps the same `resetCount` unless
  the libvirt XML carries `<backend ... persistent_state='no'/>`
  or swTPM is started with `--flags startup-clear`. The guest's
  PCR14 resets to all-zero on each Startup(CLEAR) but
  `resetCount` does not advance; the agent's witness records the
  old `(resetCount, last_extend)` tuple and the next start
  reports `PCR14 cleared while resetCount=N unchanged since last
  extend`. Before each test run on a guest without that XML
  setting, wipe the witness and evict the persistent AIK:

  ```sh
  sudo systemctl stop lota-agent.service lota-agent.socket
  sudo find /var/lib/lota -mindepth 1 -delete
  for h in 0x81010002 0x81010003 0x81010004 0x81010005; do
      sudo tpm2_evictcontrol -C o -c "$h" 2>/dev/null || true
  done
  ```

- **The repo is virtiofs-mounted read-only at `/mnt/lota`.**
  `sudo make install` recurses into the `all` target through the
  `install: check-version-tag all` prerequisite, so `make` will
  try to write dependency files to `build/` in the current working
  directory and fail with `EROFS` on the virtiofs mount. Pass the
  build directory explicitly on the same invocation:

  ```sh
  sudo make BUILD_DIR=/var/tmp/lota-build install
  ```

- **`sudo make install` does not load the SELinux module.** The
  install rule lands `lota.pp` under the source tree but does not
  call `semodule -i`. After any change to `selinux/lota.te`, rebuild
  the module on the host (the in-tree `selinux/Makefile` writes to
  `tmp/` in the cwd, which the read-only virtiofs blocks), then
  load the package inside the guest:

  ```sh
  # [host]
  cd selinux && make && sha256sum lota.pp
  # [guest]
  sudo semodule -i /mnt/lota/selinux/lota.pp
  ```

  Verify the rule landed with `sesearch -A -s lota_agent_t ...`
  before retrying the agent. The stock policy `dontaudit`s many
  reads that the agent legitimately needs (e.g. kallsyms,
  securityfs), so denials may be silent: run `sudo semodule -DB`
  before reproducing to surface them, then `sudo semodule -B` to
  re-enable.

- **`/usr/bin/lota-agent` must carry `lota_agent_exec_t`.** A
  fresh `make install` writes the file with the default `bin_t`
  label on systems where the in-tree `lota.fc` has not been loaded
  yet; without the executable type, `init_t` does not transition
  to `lota_agent_t` at exec and the daemon runs with no TPM, BPF,
  or `/etc/lota` access. Restore the label after install:

  ```sh
  sudo restorecon -v /usr/bin/lota-agent
  ls -lZ /usr/bin/lota-agent
  # expect: system_u:object_r:lota_agent_exec_t:s0
  ```
