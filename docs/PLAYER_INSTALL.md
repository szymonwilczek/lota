# LOTA player install (`lota-install`)

`lota-install` is the player-side path onto a LOTA-attested host: one
guided, reboot-resumable command instead of the operator checklist in
[`PRODUCTION_BRINGUP.md`](PRODUCTION_BRINGUP.md). It drives the same
hard requirements the agent enforces at startup, but it explains every
change before making it, asks for consent, and survives the reboot the
install inherently needs.

The three install surfaces and their audiences:

| Tool | Audience | Scope |
|------|----------|-------|
| `lota-install` | Player on a single machine | Guided stages, consent prompts, reboot resume |
| [`PRODUCTION_BRINGUP.md`](PRODUCTION_BRINGUP.md) | Operator bringing up fleet hosts, CA and verifier | Full manual reference |
| `scripts/lota-dev-bringup.sh` | Contributor iterating on a dev host | Generates a throwaway signing key. Never for production. |

## Running it

```sh
sudo lota-install \
    --ca-server ca.example --ca-port 8444 --ca-cert /path/to/ca-tls.crt \
    --verifier verifier.example
```

CA/verifier endpoints and the trust material paths come from the
operator's install instructions (see "What the operator must ship"
below).

`lota-install --status` prints a read-only report of every
stage without changing anything.

- `--yes` skips the per-stage prompts,
- `--plain` disables the TUI for logs and scripting.

On an interactive terminal `lota-install` is a full-screen application
(alternate screen, like lazygit): a stage list on the left, a details
pane explaining the selected stage, and an output pane streaming what
every command actually does. The initial system probe runs before the
screen takeover and its per-stage results stay in the scrollback.
Nothing scrolls away and the layout follows terminal resizes. Keys:

| Key | Action |
|-----|--------|
| `↑`/`↓` or `j`/`k` | select a stage |
| `Enter` | run the selected stage (centered dialog explains the change and asks first) |
| `a` | run every pending stage in order |
| `y` / `n` | answer the confirmation dialog |
| `r` | re-probe all stages |
| `PgUp`/`PgDn` | scroll the output pane |
| `q`, `Ctrl-C`, double `Ctrl-D` | quit (`Ctrl-C` first aborts a running command) |

The original scrollback is restored on exit and a one-line result
(complete / reboot required / re-run to continue) is printed to the
normal screen. Without a TTY, or with `--plain`, the same stages run
as a sequential prompted flow suitable for logs and scripts.

Exit codes: `0` complete, `1` failed or blocked on missing input, `2`
usage, `10` reboot required - reboot and re-run the same command, the
installer detects the finished stages from live system state and
continues at the first unmet one.

There is no state file to corrupt: every done-condition is probed from
the system itself (installed files, the fs-verity bit, the initramfs
content, `/proc/cmdline`, PCR 14 via sysfs, the certificate's validity
window), and the probes mirror the agent's own startup gates, so the
installer cannot report green on a host the agent would refuse.

## What the stages do

1. **Preflight** - TPM 2.0 device present, UEFI Secure Boot enabled,
   required tooling installed. Secure Boot off is a hard stop: the
   verifier proves it from the TPM event log and rejects hosts without
   it (MOK-signed custom kernels keep working).
2. **Package artifacts** - agent binary, BPF object, systemd units,
   udev rule and dracut module are installed. The installer does not
   build or download anything. Missing artifacts mean the LOTA package
   has not been installed yet.
3. **Operator trust material** - the BPF object's signature verifies
   against the operator's public key, and `/etc/lota/lota.conf` points
   the agent at that key.
   Fail-closed: the installer never generates a signing key on the player
   machine - a locally generated key would let local malware re-sign
   a tampered enforcement object.
4. **fs-verity** - enables the kernel-enforced immutability bit on the
   agent binary.
5. **Initramfs PCR14 lock** - regenerates the initramfs so the PCR14
   lock helper runs before any regular userspace. Requires a reboot.
6. **Kernel integrity floor** - appends `ima=on ima_appraise=fix`
   (plus `module.sig_enforce=1` / `lockdown=integrity` where the
   running kernel lacks them) to the boot entries via grubby. The
   floor pins the appraisal *mode*. Signature content stays
   distribution- or operator-supplied (see PRODUCTION_BRINGUP).
   Requires a reboot.
7. **SELinux fence** - loads the LOTA policy module if needed and
   re-triggers udev so `/dev/tpm*` carries the LOTA-only label.
8. **Reboot checkpoint** - stops with exit 10 until the boot-chain
   changes are live and PCR 14 carries this boot's initramfs lock.
   PCR 14 only resets on a hardware reset, so this cannot be skipped.
9. **Agent service** - enables and starts `lota-agent.service` and its
   socket.
10. **Enrollment** - the TPM proves itself to the operator's
    attestation CA (credential activation) and receives a short-lived
    AIK certificate. An expired certificate is refreshed with the
    recorded endpoint (`lota-agent --reenroll`), no flags needed.

Run ends with a self-check (integrity floor, fs-verity, service,
certificate, and - when `--verifier` is given - a full attestation
round-trip) and a plain-language summary of exactly what telemetry
leaves the machine.

## What the operator must ship

A player install needs four operator-provided inputs, all fail-closed:

- **BPF signing public key** (default `/etc/lota/policy.pub`,
  override with `--policy-pubkey`) and the matching **`.sig`** next to
  `/usr/lib/lota/lota_lsm.bpf.o`;
- **attestation CA endpoint** (`--ca-server`, `--ca-port`,
  `--ca-cert`);
- optionally the **verifier endpoint** (`--verifier`) for the final
  round-trip check;
- compiled **SELinux module** (`lota.pp`, default
  `/usr/share/lota/selinux/lota.pp`, override with
  `--selinux-module`) on SELinux-enforcing distributions.

Distro-native packaging (RPM/DEB whose post-install hooks drive the
same stage engine) is the planned follow-up. Until then the package
step is `sudo make install` from a release tree plus the operator's
bundle.

## Pausing and removing

- **Pause:** `sudo lota-agent --shutdown`. The agent deliberately
  cannot be killed (the kill-block is the anti-tamper surface), and
  the graceful shutdown poisons PCR 14 before unloading - so **resume
  requires a reboot**. That is the security contract, not a bug:
  same-boot re-attestation after a shutdown would let a tampered
  session pose as the original one.
- **Remove:** take the host off the kernel floor (drop the cmdline
  parameters) and disable the service. The agent then refuses to run
  and the host simply stops attesting. The design degrades gracefully:
  `disabled` means `fails attestation`, never `agent runs without its
  guarantees`.

## What leaves this machine

Shown by the installer at the end of every run, repeated here. Each
attestation report to the operator's verifier carries:
- TPM PCR values and a TPM-signed quote,
- Boot event log (which includes the kernel command line and therefore disk UUIDs),
- Agent and kernel image hashes,
- IOMMU status,
- Recent process-execution telemetry from the BPF layer (binary paths, hashes, PIDs, UIDs),
- Stable device identifier derived by hashing the TPM endorsement key's public name,
- AIK certificate whose subject is a CA-issued pseudonym.

During enrollment only, the attestation CA additionally receives the
TPM's EK certificate. No file contents, browsing data or account
identity are read or transmitted.
