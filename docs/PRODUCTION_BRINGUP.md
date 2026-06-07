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

The initramfs helper first pins PCR14 with a counter-stable LOTA lock,
then the agent binds PCR14 against `(self_hash, resetCount, restartCount)`
once per boot. The counters are obtained through a TPM2_Quote with an
empty PCR selection so the value extended into PCR14 matches the
clockInfo carried by the later attestation quote even on TPM 2.0
simulators (swtpm) whose `Esys_ReadClock` and `Quote.clockInfo` disagree.
The agent therefore provisions its AIK before `self_measure()` runs;
attestations issued before `--enroll` fall back to the unauthenticated
clock and must be rebound on the next start. A re-install that changes
either the initramfs helper or the agent binary without rebuilding
initramfs and cold-rebooting reports a PCR14 derivation mismatch or
`PCR14 holds a boot commitment from a different agent binary`. Wipe the
witness file and the persistent AIK, then reboot:

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

### 6. Attestation CA enrollment

The verifier authenticates an agent only through a certificate issued by
the attestation CA (`lota-attest-ca`), so each host enrolls once before it
can attest. Enrollment runs the TPM 2.0 credential-activation ceremony:
the CA verifies the EK certificate chains to a trusted manufacturer root,
proves the AIK and that EK share one TPM, and issues a short-lived AIK
certificate whose subject is the device pseudonym. The EK is presented
only to the CA; verifiers never see it.

Stand up the CA with your CA key, the trusted manufacturer EK roots and a
server TLS keypair (`examples/enrollment/gen-ca.sh` generates the CA
material). Production fleets span several TPM manufacturers, so trust a
pin-enforced multi-vendor bundle with `-ek-root-bundle`; the CA fails
closed if any pinned root is missing, mismatched, or unpinned (see
[`configs/ek-roots/README.md`](../configs/ek-roots/README.md) for how to
materialize one):

```sh
lota-attest-ca -listen :8444 \
    -ca-cert ca.crt -ca-key ca.key \
    -tls-cert tls.crt -tls-key tls.key \
    -pseudonym-key pseudonym.key \
    -ek-root-bundle /var/lib/lota/ek-roots
```

`-ek-root <file>` is still accepted and adds operator-supplied roots (for
example a swtpm CA in the enrollment demo) on top of the bundle; pass
either or both.

#### CA signing key

CA signing key is the anchor every issued AIK certificate chains to,
so the CA loads it as a `crypto.Signer` and checks the signer's public key
against the CA certificate at startup -- a key that does not match the
certificate is refused, whether it comes from a file or an external store.

The source is selectable: an on-disk PKCS#8 PEM (`-ca-key`) for development,
or an external key store that never exposes the private key for production.
The sections below cover the production options.

`-ca-key` is a **development-only fallback**. The key sits in the clear on
the host, so a host compromise yields the fleet's signing root. The CA logs
a loud warning at startup whenever it is used, and it is never the
production default: a production CA holds the key in an HSM (next section)
and keeps `-ca-key` for local bring-up and tests only.

The bundle ships empty: the supported set is every TPM whose EK
certificate chains to a root you can verify and pin, not a fixed vendor
list. Build it from the platforms you actually attest -- draft a sources
line from a host's EK certificate, verify each pin out of band against the
vendor's published value, then materialize the bundle:

```sh
# walk the EK cert's issuer chain to the self-signed root and draft a line
sudo tpm2_nvread 0x01c00002 -o ek.der
cp configs/ek-roots/sources.example sources
scripts/lota-ek-root-pin.sh ek.der >>sources

# after verifying each pin out of band, fetch and pin the roots
scripts/lota-ek-roots-update.sh sources /var/lib/lota/ek-roots
```

`lota-ek-root-pin.sh` prints a fingerprint over what the network returned;
it does not vouch for it, so confirm the pin against the vendor before the
line enters `sources`. See
[`configs/ek-roots/README.md`](../configs/ek-roots/README.md) for the full
flow.

Enroll the agent once per host (repeat before the certificate TTL
expires, default 24h):

```sh
sudo lota-agent --enroll --ca-server ca.example --ca-port 8444 \
    --ca-cert tls.crt
# stores /var/lib/lota/aik_cert.der, sent in every attestation report
# also records the CA endpoint for guided re-enrollment
```

The first enrollment records the CA endpoint, so a refresh -- before the
certificate TTL expires, or after the agent rotates the AIK -- is a single
guided command with no CA arguments and no manual CA steps:

```sh
sudo lota-agent --reenroll
```

Point every verifier at the CA root:

```sh
lota-verifier -aik-ca-cert ca.crt ...
```

A host that has not enrolled (no AIK certificate) is refused under the
production `--require-cert` default. See
[`examples/enrollment/README.md`](../examples/enrollment/README.md) for
the full end-to-end walk-through.

The agent rotates the AIK on its own schedule (`--aik-ttl`, default 30d).
It surfaces the rotation state over D-Bus so an operator -- or a fleet
monitor -- can see when a rotation is due and when a re-enrollment is
needed. `GetRotationStatus` returns the generation, the AIK creation time,
the next-rotation deadline, any open grace window, and whether the stored
certificate has been outdated by a rotation:

```sh
busctl call org.lota.Agent1 /org/lota/Agent1 org.lota.Agent1 \
    GetRotationStatus
# (tttttb) generation provisioned_at rotation_deadline ... reenroll_required

busctl get-property org.lota.Agent1 /org/lota/Agent1 org.lota.Agent1 \
    ReenrollRequired
```

When `ReenrollRequired` is true, the host rotated its AIK and the issued
certificate is stale; clear it with the guided `sudo lota-agent --reenroll`
above. The same properties emit `PropertiesChanged`, so a subscriber is
notified the moment a rotation happens rather than having to poll.

### 7. Sealed keys (offline local attestation)

Remote attestation proves state to a verifier over the network. Sealing
is the local counterpart: the TPM releases a secret only when the host
booted into the expected state, with no verifier round-trip. It is a
local boundary the TPM enforces - useful for single-player / offline DRM
and for at-rest key storage - but it does **not** replace remote
attestation for competitive multiplayer, where the attacker owns the box.

Seal a secret to the current boot state and recover it later:

```sh
# Seal: secret in on stdin, sealed blob out on stdout (root only).
printf '%s' "$PER_TITLE_KEY" | sudo lota-agent --seal > title.sealed

# Unseal: only succeeds when the host is in the sealed PCR state.
sudo lota-agent --unseal < title.sealed
```

The default PCR set is firmware/kernel PCRs 0-7 plus LOTA's PCR14
boot-commitment, so a firmware, kernel, or agent change makes the unseal
fail closed. Pick a different set with `--seal-pcrs MASK` (for example
`--seal-pcrs 0xC1` for PCRs 0, 6, 7) when you want the secret to survive
agent upgrades.

To harden the agent's own AIK userAuth at rest, enable sealing in
`lota.conf`:

```ini
seal_aik_auth = true          # keep a sealed copy, prefer it on load
seal_aik_auth_strict = true   # store ONLY sealed; no plaintext on disk
```

`strict` removes the plaintext sidecar, so a captured disk no longer
yields the AIK auth even to an attacker with the same TPM in a different
boot state. Leave both keys at their default `false` to keep the existing
plaintext-sidecar behaviour.

An already-enrolled host adopts sealing without re-enrolling:

```sh
# Set the keys in lota.conf, then seal the current auth in place:
sudo lota-agent --seal-aik-auth
```

The trade-off of `strict`: a legitimate firmware/kernel/agent change
makes the sealed auth unrecoverable. The agent will then **not** silently
rotate the enrolled AIK; it reports the PolicyPCR mismatch and waits for
an explicit recovery. Rotate and re-seal deliberately, then re-enroll:

```sh
sudo lota-agent --reprovision-aik
sudo lota-agent --enroll --ca-server ca.example --ca-port 8444 --ca-cert tls.crt
```

#### Anti-rollback: what sealing binds, and what it does not

LOTA sealing binds a secret to a boot/PCR **state**, and that is the
intended contract. A few consequences worth stating plainly:

- **Replaying a recurring good state is by design.** Rebooting into the
  same expected state releases the key every time. For offline DRM and
  at-rest storage that is the whole point, not a rollback hole.
- **A different (tampered) state fails closed.** A firmware, kernel, or
  agent change moves the bound PCRs and the unseal is denied.
- **What PCR binding does *not* cover:** revoking an *old* secret version
  while the host can still reproduce the PCR state it was sealed against -
  i.e. a key/version *downgrade*. PCR binding has no notion of "newer than".

LOTA core does not version or revoke sealed secrets, so it deliberately
ships no monotonic-counter machinery (NV counters are a scarce, global TPM
resource, and a compound PolicyPCR+PolicyNV path cannot be validated on the
target hardware until the hardware bring-up above). If your use case *does*
need downgrade protection, bind the secret to a TPM NV monotonic counter in
addition to the PCRs and bump the counter to revoke. A complete, tested
tpm2-tools recipe is in
[`examples/sealed-key/anti-rollback-recipe.sh`](../examples/sealed-key/anti-rollback-recipe.sh).

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
