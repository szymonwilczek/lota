#!/bin/sh
# SPDX-License-Identifier: MIT
# Pre-remove for lota-agent: stop and disable the units on a real uninstall only.
# RPM passes the remaining-instance count (0 on uninstall);
# dpkg passes the "remove"/"purge" verb.
# Upgrade leaves the running unit alone.
set -e

case "$1" in
0 | remove | purge)
	systemctl --no-reload disable --now \
		lota-agent.service lota-agent.socket >/dev/null 2>&1 || true
	;;
esac
