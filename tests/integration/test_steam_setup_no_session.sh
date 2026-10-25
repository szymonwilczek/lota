#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_steam_setup_no_session.sh
#
# `lota-steam-setup` and `--verify` run with XDG_RUNTIME_DIR unset (no
# login session: a service account, `sudo -u`, cron) must report every
# check, not die on `set -u` at the first one that reads it.
#
# Requires:
#   - bash, and a writable temp directory
#
# Unprivileged and read-only: the plain run refuses before creating anything.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/scripts/lota-steam-setup"

if [[ ! -x "$SETUP" ]]; then
    echo "[steam-setup-no-session] missing artifact: $SETUP" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

failures=0

check() {
    local msg="$1"
    shift
    if "$@"; then
        echo "PASS: $msg"
    else
        echo "FAIL: $msg"
        failures=$((failures + 1))
    fi
}

says() { grep -qi -- "$2" <<<"$1"; }
denies() { ! grep -qi -- "$2" <<<"$1"; }

# --verify from an account with no session.
verify_rc=0
verify_out=$(env -u XDG_RUNTIME_DIR "$SETUP" --verify 2>&1) || verify_rc=$?

check "--verify without a session still exits non-zero" \
    test "$verify_rc" -ne 0
check "it does not die on an unset variable" \
    denies "$verify_out" 'unbound variable'
check "it names the missing session rather than a shell error" \
    says "$verify_out" 'no session runtime directory'

# checks after the first XDG_RUNTIME_DIR read
check "the container socket is reported" \
    says "$verify_out" 'container socket'
check "the hook token directory is reported" \
    says "$verify_out" 'hook token directory'
check "the run reaches the launch options it prints" \
    says "$verify_out" 'Steam Launch Options'
check "the run reaches its own verdict" \
    says "$verify_out" 'issue(s) detected'
check "the launch options are not passed off as this account's to paste" \
    says "$verify_out" "paths below are this account's own"

# with a session, the checks still use the runtime directory
session_dir="$WORK_DIR/run-user"
mkdir -p "$session_dir"

session_rc=0
session_out=$(XDG_RUNTIME_DIR="$session_dir" "$SETUP" --verify 2>&1) || session_rc=$?

check "a session's runtime directory is accepted" \
    says "$session_out" "XDG_RUNTIME_DIR=$session_dir"
check "the container socket is looked for under it" \
    says "$session_out" "$session_dir/lota/lota.sock"
check "the absent socket is still an issue" \
    test "$session_rc" -ne 0
check "no session is claimed when there is one" \
    denies "$session_out" 'no session runtime directory'

# the setup run, which creates the directory instead
setup_rc=0
setup_out=$(env -u XDG_RUNTIME_DIR "$SETUP" 2>&1) || setup_rc=$?

check "the setup run does not die on an unset variable" \
    denies "$setup_out" 'unbound variable'
check "the setup run says what it could not create" \
    says "$setup_out" 'no session runtime directory'
check "the setup run exits non-zero" \
    test "$setup_rc" -ne 0

if [[ $failures -gt 0 ]]; then
    echo ""
    echo "--- --verify output ---"
    printf '%s\n' "$verify_out"
    echo "--- session output ---"
    printf '%s\n' "$session_out"
    echo "--- setup output ---"
    printf '%s\n' "$setup_out"
    echo ""
    echo "[steam-setup-no-session] $failures check(s) failed"
    exit 1
fi

echo "[steam-setup-no-session] all checks passed"
