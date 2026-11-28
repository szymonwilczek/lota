#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_hook_container_report.sh
#
# The hook's stderr warning when its token directory is private to a
# container: the files are written but the host never sees them, which
# looks the same as a hook that never loaded.
#
# Requires:
#   - liblota_wine_hook.so in the build directory, which follows
#     LOTA_BUILD_DIR the way the other integration tests do
#   - hook_preload_target beside it, built with the same flags (make test-bins)
#   - bash, and a writable temp directory
#
# Runs unprivileged: no container or mount, only a container environment
# over a token directory that is not a bind mount.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "hook container report"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILD_DIR="${BUILD_DIR:-${LOTA_BUILD_DIR:-$REPO_DIR/build}}"
HOOK_LIB="$BUILD_DIR/liblota_wine_hook.so"
TARGET="$(dirname "$HOOK_LIB")/hook_preload_target"

for artifact in "$HOOK_LIB" "$TARGET"; do
    if [[ ! -f "$artifact" ]]; then
	FAIL "missing artifact: %s" "$artifact"
	test_end
    fi
done

# a sanitizer build's shared runtime has to load ahead of the hook
SAN_RT=$(ldd "$TARGET" |
	     awk '$1 ~ /^lib(a|t|ub)san\.so/ { printf "%s ", $3 }')

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

says() { grep -qi -- "$2" <<<"$1"; }
denies() { ! grep -qi -- "$2" <<<"$1"; }

# stderr only; there is no agent, so the rest is noise
run_hook() {
    local runtime="$1"
    shift

    set +e
    env -i PATH=/usr/bin:/bin HOME="$WORK_DIR" \
	XDG_RUNTIME_DIR="$runtime" \
	LOTA_HOOK_LOG_LEVEL=warn \
	LD_PRELOAD="$SAN_RT$HOOK_LIB" \
	"$@" "$GAME" 2>"$WORK_DIR/err" >/dev/null
    set -e
    err=$(cat "$WORK_DIR/err")
}

# outside system paths, which the hook skips
GAME="$WORK_DIR/game/fake-title"
mkdir -p "$WORK_DIR/game"
cp "$TARGET" "$GAME"

RUNTIME="$WORK_DIR/run"
mkdir -p "$RUNTIME"

# 1. Unshared token directory: warned, naming the directory.
run_hook "$RUNTIME" container=pressure-vessel
TEST "a container-private token directory is reported"
says "$err" "container" || FAIL "%s" "$err"
TEST "the directory that has to be shared is named"
says "$err" "$RUNTIME/lota-hook" || FAIL "%s" "$err"
TEST "the warning says the host cannot read it"
says "$err" "host" || FAIL "%s" "$err"
TEST "the wrapper that arranges it is named"
says "$err" "lota-proton-hook" || FAIL "%s" "$err"

# 2. Any container manager, not only pressure-vessel.
run_hook "$RUNTIME" container=docker
TEST "another container manager is reported too"
says "$err" "container" || FAIL "%s" "$err"

# 3. PRESSURE_VESSEL_* is set on the host too (the wrapper exports one),
#    so it does not mean a container.
run_hook "$RUNTIME" \
	 PRESSURE_VESSEL_FILESYSTEMS_RW="$RUNTIME/lota-hook:$RUNTIME/lota" \
	 PRESSURE_VESSEL_RUNTIME=/run/pressure-vessel/runtime
TEST "the container's own settings are not a container"
denies "$err" "inside this container" || FAIL "%s" "$err"

# 4. A host launch is not warned about.
run_hook "$RUNTIME"
TEST "a host launch is not warned about"
denies "$err" "container" || FAIL "%s" "$err"

# 5. LOTA_HOOK_DISABLE=1: nothing runs, nothing is reported.
run_hook "$RUNTIME" container=pressure-vessel LOTA_HOOK_DISABLE=1
TEST "DISABLE=1: nothing is reported"
denies "$err" "container" || FAIL "%s" "$err"

# 6. Warn level: silent suppresses it.
run_hook "$RUNTIME" container=pressure-vessel LOTA_HOOK_LOG_LEVEL=silent
TEST "silent: nothing is reported"
denies "$err" "container" || FAIL "%s" "$err"

test_end
