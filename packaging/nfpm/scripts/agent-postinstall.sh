#!/bin/sh
# SPDX-License-Identifier: MIT
# Post-install for lota-agent: refresh systemd only.
# Bring-up (90lota initramfs, PCR14 arming, fsverity) is
# deliberately left to lota-install, and BPF object signing to the operator,
# so a package install or upgrade never rewrites the boot path or signs
# trust material on its own.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

cat <<'EOF'
lota-agent installed. Agent fails closed until host bring-up completes.

BPF enforcement object ships UNSIGNED, and a package upgrade replaces it,
so sign it with your operator key (lota-install verifies the signature, it
never signs on this host):

  sudo lota-agent --sign-policy /usr/lib/lota/lota_lsm.bpf.o \
      --signing-key /etc/lota/policy.key

Then run `lota-install` (or the documented operator bring-up) to install the
90lota dracut module, arm the PCR14 boot commitment and enable fs-verity. The
agent refuses to load an unsigned BPF object, so it is not started
automatically.
EOF
