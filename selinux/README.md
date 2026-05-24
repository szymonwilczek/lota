# LOTA SELinux Policy

SELinux policy for confining the LOTA agent.

## Types

| Type                | Description                     |
| ------------------- | ------------------------------- |
| `lota_agent_t`      | LOTA agent process domain       |
| `lota_agent_exec_t` | Agent binary executable         |
| `lota_var_t`        | Runtime data (AIK store, state) |
| `lota_etc_t`        | Configuration files             |
| `lota_bpf_t`        | eBPF object files               |
| `lota_log_t`        | Log files                       |
| `lota_port_t`       | Network port for attestation    |
| `lota_tpm_device_t` | `/dev/tpm[0-9]*` and `/dev/tpmrm[0-9]*` (relabelled by `configs/udev/99-lota-tpm.rules`) |

### `lota_tpm_device_t` - pre-agent PCR14 defence

TPM 2.0 PC Client Platform TPM Profile p3.3 keeps PCR14 in the
OS-Loader-writable range (PCR8–15, Locality 0, auth-free
`TPM2_PCR_Extend`). The TPM exposes **no on-chip mechanism** that
could gate the extend, so a local-root attacker with `/dev/tpmrm0`
access can extend PCR14 between cold boot and the agent's first
`tpm_extend_boot_commitment()` call. The defence has to live outside
the TPM. LOTA stacks four layers:

1. **udev** (`configs/udev/99-lota-tpm.rules`) sets `0600 root:root`
   on `/dev/tpm*` at device-add time and assigns the
   `lota_tpm_device_t` SELinux label.
2. **SELinux** (this module) is the only policy that allows `rw_chr_file_perms`
   on `lota_tpm_device_t`, and only to `lota_agent_t`. Stock refpolicy
   interfaces (`dev_rw_tpm()`, ...) bind to the generic `tpm_device_t`
   label and no longer apply once the udev rule has run — including
   for `unconfined_t`.
3. **systemd ordering** (`systemd/lota-agent.service` `Before=multi-user.target
   getty.target`) narrows the window in which any login-capable target
   could spawn a tool that races the agent's first extend.
4. **Persistent clock-state attribution** (`src/agent/tpm.c`,
   `/var/lib/lota/clock_state.dat`) detects every PCR14 mismatch
   post-hoc and attributes it to one of cold-boot tamper,
   mid-session tamper, or live binary upgrade so the operator
   receives an actionable journal entry.

**Operators MUST run SELinux in enforcing mode for the MAC layer to
bind.** A permissive system trusts every uid-0 process equally and
LOTA cannot offer protection against that operator decision; the
clock-state attribution layer still records the tamper but cannot
prevent it.

### Capabilities Granted

The agent requires elevated privileges for hardware attestation:

- **TPM Access**: Read PCRs, generate quotes, manage AIK
- **BPF Operations**: Load LSM programs for execution monitoring
- **System State**: Read kernel, firmware, and security status
- **Network**: Connect to verifier servers for attestation

## Installation

### Prerequisites

```bash
# Fedora/RHEL
sudo dnf install selinux-policy-devel policycoreutils-python-utils

# Verify SELinux is enforcing
getenforce  # should return "Enforcing"
```

### Build and Install

```bash
cd selinux/

# Build policy modules
make

# Install (requires root)
sudo make install

# Verify installation
sudo make verify
```

### Post-Installation

After installing the agent binary and BPF object:

```bash
# Apply correct labels
sudo restorecon -Rv /usr/bin/lota-agent
sudo restorecon -Rv /usr/lib/lota
sudo restorecon -Rv /etc/lota
sudo restorecon -Rv /var/lib/lota
```

## Configuration Tunables

Control policy behavior with SELinux booleans:

| Boolean                   | Default | Description                            |
| ------------------------- | ------- | -------------------------------------- |
| `lota_network_attest`     | on      | Allow network attestation to verifiers |
| `lota_bpf_load`           | on      | Allow loading eBPF LSM programs        |
| `lota_module_enforce`     | off     | Allow kernel module enforcement        |
| `lota_steam_attest`       | on      | Steam attestation integration          |
| `lota_wine_attest`        | on      | Wine/Proton attestation integration    |
| `lota_anticheat_extended` | on      | Extended anti-cheat access             |

### Modify Tunables

```bash
# Disable network attestation
sudo setsebool -P lota_network_attest off

# Enable module enforcement
sudo setsebool -P lota_module_enforce on

# Show current values
getsebool -a | grep lota
```

## Gaming Integration

### Steam

Steam and games launched through Steam can query LOTA attestation status:

```bash
# Verify Steam can access LOTA
sudo sesearch -A -s steam_t -t lota_var_t
```

### Proton/Wine

Windows games running via Proton have access to LOTA for anti-cheat verification:

```bash
# Check Wine access
sudo sesearch -A -s wine_t -t lota_agent_t
```

### Anti-Cheat Systems

EAC, BattlEye, and other anti-cheat systems running in Wine can:

1. Query current attestation status
2. Request fresh attestation
3. Verify system integrity

## File Contexts

### Standard Paths

| Path                  | Context             |
| --------------------- | ------------------- |
| `/usr/bin/lota-agent` | `lota_agent_exec_t` |
| `/usr/lib/lota/`      | `lota_bpf_t`        |
| `/etc/lota/`          | `lota_etc_t`        |
| `/var/lib/lota/`      | `lota_var_t`        |
| `/var/log/lota/`      | `lota_log_t`        |
| `/run/lota/`          | `lota_var_t`        |
| `/dev/tpm[0-9]*`      | `lota_tpm_device_t` |
| `/dev/tpmrm[0-9]*`    | `lota_tpm_device_t` |

### Custom Locations

To add custom file contexts:

```bash
# example: Agent in non-standard location
sudo semanage fcontext -a -t lota_agent_exec_t "/opt/lota/bin/lota-agent"
sudo restorecon -v /opt/lota/bin/lota-agent
```

## Troubleshooting

### View AVC Denials

```bash
# Recent denials
sudo ausearch -m avc -ts recent | grep lota

# Use make target
sudo make audit
```

### Generate Policy Suggestions

```bash
# From audit log
sudo make suggest

# Or manually
sudo ausearch -m avc | audit2allow -m lota_local
```

### Common Issues

#### "Permission denied" accessing TPM

```bash
# Check device labels
ls -Z /dev/tpm*

# Expected after install: lota_tpm_device_t. If the label is still
# tpm_device_t the LOTA udev rule never ran:
sudo install -m 644 ../configs/udev/99-lota-tpm.rules \
    /usr/lib/udev/rules.d/99-lota-tpm.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=tpm
ls -Z /dev/tpm*
```

#### "TPM device carries SELinux label ... expected lota_tpm_device_t"

The agent reads `security.selinux` on `/dev/tpmrm0` and `/dev/tpm0`
at the hardening gate. If the udev relabel did not run (broken
symlink in `/etc/udev/rules.d`, missing
`/usr/lib/udev/rules.d/99-lota-tpm.rules`, or a host kernel that
labelled the device before the rule was installed), any other root
SELinux domain (`tpm2-abrmd_t`, generic `init_t`, ...) still has
rw access to the TPM resource manager. That domain can flood the
chip and exhaust TPM sessions, the NV rate budget, or the DA
counter; LOTA stays fail-closed
(`LOTA_ERR_TPM_LOCKED` -> `LOTA_STATUS_TPM_LOCKOUT`), but
attestation availability drops. Re-run the udev install steps
above; the agent will start once the label is `lota_tpm_device_t`.

#### TPM DoS / DA lockout runbook

When `LOTA_STATUS_TPM_LOCKOUT` shows up on `lota-agent status` or
on the D-Bus `StatusChanged` signal:

```bash
# Confirm the TPM is currently in dictionary-attack lockout.
sudo tpm2_getcap properties-variable | grep -E "lockoutCounter|lockoutInterval"

# Identify other processes holding the TPM resource manager fd.
sudo lsof /dev/tpmrm0 /dev/tpm0

# Inspect recent denials from non-LOTA domains.
sudo ausearch -ts recent -m AVC -c tpm2-abrmd

# Reset the lockout (requires lockoutAuth, typically empty on
# stock distributions; otherwise consult the platform admin):
sudo tpm2_dictionarylockout --setup-parameters \
    --max-tries=32 --recovery-time=120 --lockout-recovery=120
sudo tpm2_dictionarylockout --clear-lockout
```

The agent re-publishes the status flag on the next attestation
cycle. If the lockout returns on a host where `ls -Z /dev/tpm*`
shows `lota_tpm_device_t`, the offender is inside the
`lota_agent_t` policy boundary; check `/var/log/lota` for repeated
`LOTA_ERR_TPM_LOCKED` retries before escalating to hardware.

#### BPF program loading fails

```bash
# Verify tunable is enabled
getsebool lota_bpf_load

# Check BPF capabilities
sudo sesearch -A -s lota_agent_t -c bpf
```

#### Steam cannot connect to LOTA

```bash
# Verify socket label
ls -Z /run/lota/lota.sock

# Check Steam access
sudo sesearch -A -s steam_t -t lota_var_t -c sock_file
```

#### Network attestation blocked

```bash
# Check tunable
getsebool lota_network_attest

# Verify port definition
sudo semanage port -l | grep lota
```

## Interface Reference

Other SELinux policies can use LOTA interfaces:

### For Gaming Applications

```sh
# Allow querying attestation status
lota_query_status(myapp_t)

# Full gaming client access
lota_gaming_client(myapp_t)
```

### For Anti-Cheat

```sh
# Extended anti-cheat access
lota_anticheat_client(myanticheat_t)
```

### For System Services

```sh
# Administrative access
lota_admin(myadmin_t, myadmin_r)
```

## Development

### Testing Changes

```bash
# Build without installing
make

# Check syntax
make check

# Reload after changes
sudo make reload
```

### Debugging in Permissive Mode

```bash
# Set LOTA domain to permissive (logs but allows)
sudo semanage permissive -a lota_agent_t

# Test functionality
lota-agent --test-tpm

# Review denials
sudo ausearch -m avc -ts recent | grep lota

# Return to enforcing
sudo semanage permissive -d lota_agent_t
```

## Contributing

When modifying the policy:

1. Test in permissive mode first
2. Use `audit2allow` to identify required permissions
3. Add minimal permissions with comments explaining why
4. Test with SELinux enforcing before submitting

## License

GPL-2.0-only
