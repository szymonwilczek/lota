#!/bin/sh
# SPDX-License-Identifier: MIT
# Post-install for lota-agent: refresh systemd, restore fs-verity.
# Bring-up (90lota initramfs, PCR14 arming) is
# deliberately left to lota-install, and BPF object signing to the operator,
# so a package install or upgrade never rewrites the boot path or signs
# trust material on its own.
set -e

# Create the 'lota' socket group from the shipped sysusers.d fragment.
# socket's SocketGroup=lota resolves only once this group exists.
systemd-sysusers /usr/lib/sysusers.d/lota-agent.conf >/dev/null 2>&1 || true

systemctl daemon-reload >/dev/null 2>&1 || true

# The agent enforces fs-verity (or an appraised signed IMA xattr) on itself
# at startup, so leaving this undone means the next boot has no agent at all
# - the machine stops attesting for reason nobody chose and no log the user
# reads.
#
# Restoring it is not the same kind of act as the bring-up steps left to
# lota-install: it grants no trust and signs nothing, it only makes the file
# the package just wrote immutable to the kernel.
# It is also idempotent, so first install pays nothing for it.
verity_state="unsupported"
if command -v fsverity >/dev/null 2>&1; then
	if fsverity measure /usr/bin/lota-agent >/dev/null 2>&1; then
		verity_state="already-enabled"
	elif fsverity enable /usr/bin/lota-agent >/dev/null 2>&1; then
		verity_state="enabled"
	fi
fi

cat <<EOF
lota-agent installed. Agent fails closed until host bring-up completes.

BPF enforcement object ships UNSIGNED, and a package upgrade replaces it,
so sign it with your operator key (lota-install verifies the signature, it
never signs on this host):

  sudo lota-agent --sign-policy /usr/lib/lota/lota_lsm.bpf.o \\
      --signing-key /etc/lota/policy.key

Then run \`lota-install\` (or the documented operator bring-up) to install the
90lota dracut module, arm the PCR14 boot commitment and enable fs-verity. The
agent refuses to load an unsigned BPF object, so it is not started
automatically.
EOF

if [ "$verity_state" = "unsupported" ]; then
	cat <<'EOF'

fs-verity could not be enabled on /usr/bin/lota-agent. On a filesystem that
supports it the agent refuses to start without it, so enable it before the
next boot:

  sudo fsverity enable /usr/bin/lota-agent

A rootfs without fs-verity (XFS below 6.13, for instance) satisfies the same
gate through an appraised signed security.ima xattr instead; see
Documentation/operator/agent-update-reboot.rst.
EOF
fi

# Upgrade changed the binary, so the running daemon and the file on disk are
# no longer the same program, and PCR 14 still commits to the old one.
# PCR 14 cannot be re-extended without hardware reset, so the swap only takes
# effect on the next cold boot - and until then the agent keeps attesting as
# the build that is still running
if [ "${1:-0}" != "1" ]; then
	cat <<'EOF'

This was an upgrade. PCR 14 commits to the agent binary that booted, and it
cannot be re-extended without a hardware reset, so the new build takes effect
on the next cold boot. Until then the running agent keeps attesting as the
build that is still loaded. Add the new hash to the verifier's agent_hashes
before the fleet reboots; a verifier that lists it re-pins each device on its
own.
EOF
fi
