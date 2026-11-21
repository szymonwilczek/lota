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

. "$(dirname "$0")/../lib/test.sh"
test_begin "steam setup no session"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/scripts/lota-steam-setup"

if [[ ! -x "$SETUP" ]]; then
    FAIL "missing artifact: %s" "$SETUP"
    test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

says() { grep -qi -- "$2" <<<"$1"; }
denies() { ! grep -qi -- "$2" <<<"$1"; }

# --verify from an account with no session.
verify_rc=0
verify_out=$(env -u XDG_RUNTIME_DIR "$SETUP" --verify 2>&1) || verify_rc=$?

TEST "--verify without a session still exits non-zero"
test "$verify_rc" -ne 0 || FAIL
TEST "it does not die on an unset variable"
denies "$verify_out" 'unbound variable' || FAIL "%s" "$verify_out"
TEST "it names the missing session rather than a shell error"
says "$verify_out" 'no session runtime directory' || FAIL "%s" "$verify_out"

# checks after the first XDG_RUNTIME_DIR read
TEST "the container socket is reported"
says "$verify_out" 'container socket' || FAIL "%s" "$verify_out"
TEST "the hook token directory is reported"
says "$verify_out" 'hook token directory' || FAIL "%s" "$verify_out"
TEST "the run reaches the launch options it prints"
says "$verify_out" 'Steam Launch Options' || FAIL "%s" "$verify_out"
TEST "the run reaches its own verdict"
says "$verify_out" 'issue(s) detected' || FAIL "%s" "$verify_out"
TEST "the launch options are not passed off as this account's to paste"
says "$verify_out" "paths below are this account's own" ||
    FAIL "%s" "$verify_out"

# with a session, the checks still use the runtime directory
session_dir="$WORK_DIR/run-user"
mkdir -p "$session_dir"

session_rc=0
session_out=$(XDG_RUNTIME_DIR="$session_dir" "$SETUP" --verify 2>&1) || session_rc=$?

TEST "a session's runtime directory is accepted"
says "$session_out" "XDG_RUNTIME_DIR=$session_dir" || FAIL "%s" "$session_out"
TEST "the container socket is looked for under it"
says "$session_out" "$session_dir/lota/lota.sock" || FAIL "%s" "$session_out"
TEST "the absent socket is still an issue"
test "$session_rc" -ne 0 || FAIL
TEST "no session is claimed when there is one"
denies "$session_out" 'no session runtime directory' || FAIL "%s" "$session_out"

# the setup run, which creates the directory instead
setup_rc=0
setup_out=$(env -u XDG_RUNTIME_DIR "$SETUP" 2>&1) || setup_rc=$?

TEST "the setup run does not die on an unset variable"
denies "$setup_out" 'unbound variable' || FAIL "%s" "$setup_out"
TEST "the setup run says what it could not create"
says "$setup_out" 'no session runtime directory' || FAIL "%s" "$setup_out"
TEST "the setup run exits non-zero"
test "$setup_rc" -ne 0 || FAIL

test_end
