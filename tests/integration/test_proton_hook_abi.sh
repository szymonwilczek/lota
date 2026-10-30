#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_proton_hook_abi.sh
#
# Which hook library the Proton launch wrapper preloads.
# Steam's launch chain mixes 64- and 32-bit processes that all inherit
# LD_PRELOAD, so a pair of halves is named through ld.so's $LIB token;
# a lone half by path.
#
# Requires:
#   - bash, and a writable temp directory
#
# Unprivileged, loads nothing: the libraries are empty files,
# and the wrapped command only prints its environment.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
WRAPPER="$REPO_DIR/scripts/lota-proton-hook"

if [[ ! -x "$WRAPPER" ]]; then
    echo "[proton-hook-abi] missing artifact: $WRAPPER" >&2
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

says() { grep -q -- "$2" <<<"$1"; }
denies() { ! grep -q -- "$2" <<<"$1"; }

# as installed on a player's machine
SONAME="liblota_wine_hook.so.0"

make_root() { # <name> [lib64] [lib]
    local root="$WORK_DIR/$1"
    shift
    rm -rf "$root"
    mkdir -p "$root"
    local d
    for d in "$@"; do
	mkdir -p "$root/$d"
	: >"$root/$d/$SONAME"
    done
    echo "$root"
}

AMBIENT_PRELOAD=$(/bin/sh -c 'printf "%s" "${LD_PRELOAD:-}"')

own_preload() {
    local entry kept=""
    local -a entries ambient

    IFS=': ' read -ra ambient <<<"$AMBIENT_PRELOAD"
    IFS=': ' read -ra entries <<<"$1"
    for entry in "${entries[@]}"; do
	[[ " ${ambient[*]} " == *" $entry "* ]] && continue
	kept+="${kept:+:}$entry"
    done
    printf '%s' "$kept"
}

# The wrapped command prints its LD_PRELOAD; XDG_RUNTIME_DIR stays in
# the work directory.
run_wrapper() { # <env assignments...>
    local out_file="$WORK_DIR/out"

    set +e
    env XDG_RUNTIME_DIR="$WORK_DIR/run" "$@" \
	"$WRAPPER" /bin/sh -c \
	'printf "PRELOAD=[%s]\n" "${LD_PRELOAD:-}"' \
	>"$out_file" 2>"$WORK_DIR/err"
    rc=$?
    set -e
    out=$(cat "$out_file")
    err=$(cat "$WORK_DIR/err")
    preload=${out#*PRELOAD=[}
    preload=$(own_preload "${preload%]*}")
    return $rc
}

echo "=== lota-proton-hook: the library each ABI is given ==="

# 1. Both halves: the token, resolved by each process itself.
BOTH=$(make_root both lib64 lib)
run_wrapper LOTA_HOOK_LIB_ROOTS="$BOTH"
check "both ABIs installed: the preload names \$LIB" \
      says "$preload" '\$LIB'
check "and the soname beneath it" says "$preload" "$SONAME"
check "and no word size of its own" denies "$preload" "/lib64/"

# 2. Unexpanded: a shell would bake in the wrapper's own word size.
check "the token reaches the loader unexpanded" \
      test "$preload" = "$BOTH/\$LIB/$SONAME"

# 3. Only the 64-bit half: in a 32-bit process the token finds nothing.
ONLY64=$(make_root only64 lib64)
run_wrapper LOTA_HOOK_LIB_ROOTS="$ONLY64"
check "only the 64-bit half: the preload is a plain path" \
      denies "$preload" '\$LIB'
check "and it is the half that is there" \
      test "$preload" = "$ONLY64/lib64/$SONAME"

# 4. Only the 32-bit half.
ONLY32=$(make_root only32 lib)
run_wrapper LOTA_HOOK_LIB_ROOTS="$ONLY32"
check "only the 32-bit half: the preload is a plain path" \
      denies "$preload" '\$LIB'
check "and it is the half that is there" \
      test "$preload" = "$ONLY32/lib/$SONAME"

# 5. One token reaches only halves of one name.
MIXED=$(make_root mixed lib64)
mkdir -p "$MIXED/lib"
: >"$MIXED/lib/liblota_wine_hook.so.1"
run_wrapper LOTA_HOOK_LIB_ROOTS="$MIXED"
check "halves of different names are not a pair" \
      denies "$preload" '\$LIB'

# 6. The first root holding a pair wins, e.g. a local source build.
LOCAL=$(make_root localpair lib64 lib)
run_wrapper LOTA_HOOK_LIB_ROOTS="$ONLY64:$LOCAL"
check "a later root holding a pair beats an earlier half" \
      test "$preload" = "$LOCAL/\$LIB/$SONAME"

# 7. LOTA_HOOK_LIB_PATH overrides the probe.
EXPLICIT="$WORK_DIR/explicit.so"
: >"$EXPLICIT"
run_wrapper LOTA_HOOK_LIB_ROOTS="$BOTH" LOTA_HOOK_LIB_PATH="$EXPLICIT"
check "an explicit library path still wins" \
      test "$preload" = "$EXPLICIT"

# 8. No hook: reported, and the game still starts.
EMPTY=$(make_root empty)
run_wrapper LOTA_HOOK_LIB_ROOTS="$EMPTY"
check "no hook at all is reported" says "$err" "hook library not found"
check "and the game is started anyway" test "$rc" -eq 0
check "with the preload left alone" test -z "$preload"

# 9. A preload the player set stays in front of ours.
run_wrapper LOTA_HOOK_LIB_ROOTS="$BOTH" LD_PRELOAD=/opt/theirs.so
check "an existing preload is kept" says "$preload" "/opt/theirs.so"
check "and ours is still the token" says "$preload" '\$LIB'

echo ""
if [[ $failures -eq 0 ]]; then
    echo "[proton-hook-abi] OK"
    exit 0
fi
echo "[proton-hook-abi] $failures check(s) failed" >&2
exit 1
