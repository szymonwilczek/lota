#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_demo_setup.sh
#
# How examples/demo/setup.sh ends and what it starts.
#
# Requires:
#   - bash, and a writable temp directory
#
# Runs unprivileged, with id, make, curl, swtpm and tpm2-tools stubbed on
# PATH; the host's TPM, agent and /run/lota are not touched.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "demo setup"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SETUP="$REPO_DIR/examples/demo/setup.sh"

if [[ ! -x "$SETUP" ]]; then
    FAIL "missing artifact: %s" "$SETUP"
    test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

says() { grep -q -e "$2" <<<"$1"; }
denies() { ! grep -q -e "$2" <<<"$1"; }

STUB_BIN="$WORK_DIR/bin"
mkdir -p "$STUB_BIN"
for tool in make curl swtpm swtpm_setup tpm2_getrandom tpm2_readpublic; do
    printf '#!/bin/sh\nexit 0\n' >"$STUB_BIN/$tool"
done
# a real run needs root; the stub lets it past that check
printf '#!/bin/sh\n[ "$1" = -u ] && echo 0 && exit 0\nexec /usr/bin/id "$@"\n' \
       >"$STUB_BIN/id"
chmod 0755 "$STUB_BIN"/*

# a signal at a pause ends the run instead of resuming the next step
signal_ends_run() {
    local sig="$1" want="$2" out="$WORK_DIR/signal.out" pid rc i
    PATH="$STUB_BIN:$PATH" "$SETUP" --no-build \
        < <(sleep 30) >"$out" 2>&1 &
    pid=$!
    for i in $(seq 50); do
        grep -q "skipping build" "$out" && break
        sleep 0.1
    done
    sleep 0.2
    kill "-$sig" "$pid"
    rc=0
    wait "$pid" || rc=$?
    signal_out=$(cat "$out")
    [[ "$rc" -eq "$want" ]] || FAIL "%s: exit %d, want %d" "$sig" "$rc" "$want"
}

dry=$(PATH="$STUB_BIN:$PATH" "$SETUP" --dry-run --no-build 2>&1 || true)
TEST "the agent reads an empty lota.conf of the run"
says "$dry" 'lota-agent --config /tmp/lota-demo.DRYRUN/lota.conf' ||
    FAIL "%s" "$dry"
TEST "that file is created empty"
says "$dry" 'install -m 0600 /dev/null /tmp/lota-demo.DRYRUN/lota.conf' ||
    FAIL "%s" "$dry"

dry=$(PATH="$STUB_BIN:$PATH" SUDO_USER=player SDL_VIDEODRIVER=dummy \
    "$SETUP" --dry-run --no-build 2>&1 || true)
TEST "the game under sudo keeps the SDL_ variables"
says "$dry" 'sudo -u player env .* SDL_VIDEODRIVER=dummy .*trust_pong' ||
    FAIL "%s" "$dry"

if [[ -S /run/lota/lota.sock ]]; then
    TEST "signal checks"
    SKIP "an agent socket exists on this host"
else
    TEST "TERM at a pause exits 143"
    signal_ends_run TERM 143
    TEST "TERM at a pause runs no later step"
    denies "$signal_out" "Step 2/7" || FAIL "%s" "$signal_out"
fi

test_end
