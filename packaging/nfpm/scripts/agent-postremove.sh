#!/bin/sh
# SPDX-License-Identifier: MIT
# Post-remove for lota-agent: refresh systemd after the units are gone.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true
