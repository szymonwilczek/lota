#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_steam_setup_register_uid.sh
#
# `lota-steam-setup --register-uid` on a host whose /etc/lota holds no
# lota.conf yet. The package ships the directory, not the file, and a host
# configured only through the loop's own enrolment never writes one, so a
# missing file is an empty config, as it is to --add-publisher.
# A missing directory still means LOTA is not installed.
#
# Requires:
#   - ${BUILD_DIR}/lota-agent (build with `make all`), for the read-back.
#     Unset, BUILD_DIR follows LOTA_BUILD_DIR, which a make recipe exports
#     as the directory that build used.
#   - unshare -r, so the root-only verb runs without privilege
#
# Runs unprivileged and modifies nothing outside its temp directory.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "steam register uid"

# The assertions grep the script's own messages.
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/scripts/lota-steam-setup"
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
AGENT_BIN="$BUILD_DIR/lota-agent"

for f in "$SETUP" "$AGENT_BIN"; do
    if [[ ! -x "$f" ]]; then
	FAIL "missing artifact: %s" "$f"
	test_end
    fi
done

if ! unshare -r true 2>/dev/null; then
    SKIP "no unprivileged user namespace"
    test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

# root in a namespace of its own, the operator a made-up uid
register() {
    LOTA_CONF="$1" SUDO_UID=4242 PATH="$BUILD_DIR:$PATH" \
	unshare -r "$SETUP" --register-uid 2>&1
}

has_line() { grep -qx "$2" "$1"; }
says() { grep -qi -- "$2" <<<"$1"; }
mode_is() { [[ $(stat -c %a "$1") == "$2" ]]; }
loads() { "$AGENT_BIN" --dump-config --config "$1" >/dev/null 2>&1; }

# The directory the package ships, and no file in it.
mkdir "$WORK_DIR/etc"
conf="$WORK_DIR/etc/lota.conf"

rc=0
out=$(register "$conf") || rc=$?
TEST "an absent lota.conf is registered into"
test "$rc" -eq 0 || FAIL "exit %d: %s" "$rc" "$out"
TEST "the uid is written"
has_line "$conf" 'container_listener_uid = 4242' || FAIL
TEST "the file is created 0644"
mode_is "$conf" 644 || FAIL
TEST "the config the command wrote loads"
loads "$conf" || FAIL
TEST "no backup is left behind"
test ! -e "$conf.lota-steam-setup.bak" || FAIL

rc=0
out=$(register "$conf") || rc=$?
TEST "a second run finds the uid registered"
says "$out" 'already registered' || FAIL "%s" "$out"

# No directory: nothing installed LOTA here.
rc=0
out=$(register "$WORK_DIR/none/lota.conf") || rc=$?
TEST "a missing config directory is refused"
test "$rc" -ne 0 || FAIL "exit %d: %s" "$rc" "$out"
TEST "the refusal says LOTA is not installed"
says "$out" 'install LOTA' || FAIL "%s" "$out"
TEST "nothing is created for a missing directory"
test ! -e "$WORK_DIR/none" || FAIL

test_end
