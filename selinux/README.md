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

# Should show tpm_device_t
# If not, report bug in distribution policy (please!)
```

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
