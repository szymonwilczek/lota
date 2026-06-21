#!/bin/sh
# SPDX-License-Identifier: MIT
# Post-install for lota-agent: refresh systemd only.
# Bring-up (BPF signing, 90lota initramfs, PCR14 arming, fsverity) is
# deliberately left to lota-install so package install or upgrade never
# rewrites the boot path on its own.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

cat <<'EOF'
lota-agent installed. Agent fails closed until host bring-up completes.

Run `lota-install` (or the documented operator bring-up) to sign the BPF
object with your signing key, install the 90lota dracut module into the
initramfs and arm the PCR14 boot commitment.

Agent refuses to load an unsigned BPF object, so it is not started
automatically.
EOF
