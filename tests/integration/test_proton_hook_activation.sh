#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_proton_hook_activation.sh
#
# Which processes of a Steam launch the hook attests.
#
# LD_PRELOAD also reaches Steam's own helpers (launch wrapper, reaper),
# which live outside the FHS paths the hook's default policy keys on;
# one that loads the hook pins every library it maps, libc included,
# and outlives the title. The wrapper pins the hook to the directories
# Steam names for the launch:
#   STEAM_COMPAT_INSTALL_PATH and STEAM_COMPAT_TOOL_PATHS.
#
# Requires:
#   - bash, and a writable temp directory
#
# Unprivileged, loads nothing: the "library" is an empty file named
# through LOTA_HOOK_LIB_PATH, and the wrapped command prints its pin.

set -euo pipefail

# paths compare byte for byte
export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
WRAPPER="$REPO_DIR/scripts/lota-proton-hook"

if [[ ! -x "$WRAPPER" ]]; then
    echo "[proton-hook-activation] missing artifact: $WRAPPER" >&2
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

# The hook's match: an entry covers itself and every path under it
covers() {
    local pin="$1" exe="$2" entry

    local IFS=,
    for entry in $pin; do
	[[ -n "$entry" ]] || continue
	[[ "$exe" == "$entry" ]] && return 0
	[[ "$exe" == "${entry%/}"/* ]] && return 0
    done
    return 1
}

lacks() { ! covers "$@"; }

# @want is an entry of its own, not part of another
names() {
    local pin="$1" want="$2" entry

    local IFS=,
    for entry in $pin; do
	[[ "${entry%/}" == "${want%/}" ]] && return 0
    done
    return 1
}

LIB="$WORK_DIR/liblota_wine_hook.so"
: >"$LIB"

# $pin, $prog = what the wrapped command got; <unset> tells unset from empty
run_wrapper() {
    local out_file="$WORK_DIR/out"

    set +e
    env "$@" LOTA_HOOK_LIB_PATH="$LIB" \
	"$WRAPPER" /bin/sh -c \
	'printf "PIN=[%s]\nPROG=[%s]\n" \
		"${LOTA_HOOK_ACTIVATE_PATH-<unset>}" \
		"${LOTA_HOOK_ACTIVATE_PROGRAM-<unset>}"' \
	>"$out_file" 2>/dev/null
    rc=$?
    set -e
    pin=$(sed -n 's/^PIN=\[\(.*\)\]$/\1/p' "$out_file")
    prog=$(sed -n 's/^PROG=\[\(.*\)\]$/\1/p' "$out_file")
    return $rc
}

echo "=== lota-proton-hook: which processes of a launch are the title ==="

# Client helpers beside the library folder; the title dir has a space
STEAM="$WORK_DIR/Steam"
GAME="$STEAM/steamapps/common/A Title With Spaces"
TOOL="$STEAM/steamapps/common/SteamLinuxRuntime"
PROTON="$STEAM/steamapps/common/Proton"
mkdir -p "$GAME/bin" "$TOOL/bin" "$PROTON/files/bin" "$STEAM/ubuntu12_32"

# 1. Steam describes the launch: the title directory is pinned.
run_wrapper STEAM_COMPAT_INSTALL_PATH="$GAME" \
	    STEAM_COMPAT_TOOL_PATHS="$PROTON:$TOOL"
check "the title's program is one the hook attests" \
      covers "$pin" "$GAME/bin/title"

# 2. Proton runs from the tool paths, not the title directory.
check "so is the compatibility tool that runs it" \
      covers "$pin" "$PROTON/files/bin/wine64-preloader"
check "and the container runtime beside it" \
      covers "$pin" "$TOOL/bin/pressure-vessel-wrap"

# 3. Client helpers are in neither.
check "the client's helpers are not" \
      lacks "$pin" "$STEAM/ubuntu12_32/reaper"
check "nor is the client directory they sit in" \
      lacks "$pin" "$STEAM/steam.sh"

# 4. Steam's colon list becomes the hook's comma list, one entry each.
check "every tool the launch names is pinned on its own" \
      names "$pin" "$PROTON"
check "and so is the title" names "$pin" "$GAME"

# 5. A pin the player set wins.
run_wrapper STEAM_COMPAT_INSTALL_PATH="$GAME" \
	    STEAM_COMPAT_TOOL_PATHS="$TOOL" \
	    LOTA_HOOK_ACTIVATE_PATH="/opt/games"
check "a pin the player set is left alone" test "$pin" = "/opt/games"

# 6. Outside Steam: no pin, the hook's own policy decides.
run_wrapper
check "a launch Steam knows nothing about is left unpinned" \
      test "$pin" = "<unset>"

# 7. No install path, no pin: an empty one matches all or nothing.
run_wrapper STEAM_COMPAT_TOOL_PATHS="$TOOL"
check "a launch that names no title is left unpinned" \
      test "$pin" = "<unset>"

run_wrapper STEAM_COMPAT_INSTALL_PATH="$GAME"
check "a launch that names no tool still pins the title" \
      covers "$pin" "$GAME/bin/title"

# 8. An empty element matches every path; it is dropped.
run_wrapper STEAM_COMPAT_INSTALL_PATH="$GAME" \
	    STEAM_COMPAT_TOOL_PATHS="$TOOL::$PROTON"
check "an empty tool path is dropped rather than pinned" \
      lacks "$pin" "/anything/at/all"
check "and the tools around it survive" names "$pin" "$PROTON"

# 9. Without a trailing separator an entry covers a sibling title.
run_wrapper STEAM_COMPAT_INSTALL_PATH="$GAME" \
	    STEAM_COMPAT_TOOL_PATHS="$TOOL"
check "a title whose name merely starts the same is not attested" \
      lacks "$pin" "$GAME II/bin/title"

# 10. Every Wine process runs the pinned loader; the title's directory,
#     as Wine sees it, tells them apart. A library is a drive of its own
#     in the prefix, so the directory starts at the library root.
run_wrapper STEAM_COMPAT_INSTALL_PATH="$GAME" \
	    STEAM_COMPAT_TOOL_PATHS="$PROTON:$TOOL"
check "the title's directory is named from its library root" \
      test "$prog" = "steamapps/common/A Title With Spaces/"

run_wrapper STEAM_COMPAT_INSTALL_PATH="$GAME/" \
	    STEAM_COMPAT_TOOL_PATHS="$PROTON"
check "a trailing separator does not double" \
      test "$prog" = "steamapps/common/A Title With Spaces/"

# 11. A title outside any library is reached through the root drive.
run_wrapper STEAM_COMPAT_INSTALL_PATH="$WORK_DIR/Games/Shortcut" \
	    STEAM_COMPAT_TOOL_PATHS="$PROTON"
check "a title outside a library is named by its host path" \
      test "$prog" = "$WORK_DIR/Games/Shortcut/"

# 12. As with the pin: a set value wins; no install path, no program.
run_wrapper STEAM_COMPAT_INSTALL_PATH="$GAME" \
	    LOTA_HOOK_ACTIVATE_PROGRAM="games/mine/"
check "a title directory the player set is left alone" \
      test "$prog" = "games/mine/"

run_wrapper STEAM_COMPAT_TOOL_PATHS="$PROTON"
check "a launch that names no title names no program" \
      test "$prog" = "<unset>"

echo ""
if [[ $failures -eq 0 ]]; then
    echo "[proton-hook-activation] OK"
    exit 0
fi
echo "[proton-hook-activation] $failures check(s) failed" >&2
exit 1
