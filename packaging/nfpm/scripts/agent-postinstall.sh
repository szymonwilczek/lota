#!/bin/sh
# SPDX-License-Identifier: MIT
# Post-install for lota-agent: refresh systemd, then drive the installer's own
# stage engine unattended.
#
# The engine decides what a package may do:
# everything host-local and reversible (BPF signature check, policy_pubkey
# in lota.conf, fs-verity on the binary, the SELinux fence) runs here,
# and the two stages that rewrite how the machine boots -- the 90lota initramfs
# and the kernel integrity floor -- wait for a person unless this host asked for
# them (/etc/lota/auto-bringup or LOTA_AUTO_BRINGUP=1).
#
# `dnf install` that quietly adds module.sig_enforce=1 and lockdown=integrity
# to every boot entry can leave a machine that does not come back the way it went
# down, and that is not a package's call to make.
#
# The enforcement object arrives signed by whoever built this package,
# with the matching public key, because enforcement is host-owned:
# one kernel, one LSM, and no publisher pushes kernel policy onto a player's machine.
set -e

# Create the 'lota' socket group from the shipped sysusers.d fragment.
# socket's SocketGroup=lota resolves only once this group exists.
systemd-sysusers /usr/lib/sysusers.d/lota-agent.conf >/dev/null 2>&1 || true

systemctl daemon-reload >/dev/null 2>&1 || true

cat <<'EOF'
lota-agent installed. The agent fails closed until host bring-up completes.

The BPF enforcement object ships signed, next to its signature and the public
key it verifies against (/usr/lib/lota/enforcement.pub). All three are
replaced together by an upgrade, so enforcement still arms after one.

A fleet that signs enforcement with its own key re-signs the object and puts
its key at /etc/lota/policy.pub, which no package owns and no upgrade
touches; the agent prefers it whenever it is there. lota-install verifies the
signature and never signs on this host.
EOF

# The stage engine is the one place that knows what each stage changes and how
# to probe whether it is already done, so the hook drives it rather than
# reimplementing a subset in shell.
# Its failure is never this transaction's failure:
# the package is installed either way, and the run says what is left.
if [ -x /usr/bin/lota-install ]; then
	echo
	/usr/bin/lota-install --unattended || true
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
