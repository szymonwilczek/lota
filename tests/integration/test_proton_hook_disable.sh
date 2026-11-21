#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_proton_hook_disable.sh
#
# What the Proton launch wrapper does with the two escape hatches it documents.
# Both end the same way -- the game is exec'd with LD_PRELOAD untouched and one
# warning on stderr -- and they are the only thing standing between a player
# and a launch the preload breaks, so they are driven through the script.
# Only LOTA_HOOK_DISABLE also skips lota-protect: a missing library still
# launches protected.
#
# The library honours LOTA_HOOK_DISABLE as well, but by the time it can it is
# already mapped into the game; the wrapper's answer is the one that keeps it out.
#
# Requires:
#   - bash, and a writable temp directory
#
# Runs unprivileged and loads nothing: the "library" the wrapper finds is a file
# in the temp directory, named through LOTA_HOOK_LIB_PATH, and the command it
# wraps only prints the environment it was handed.

set -euo pipefail

. "$(dirname "$0")/../lib/test.sh"
test_begin "proton hook disable"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
WRAPPER="$REPO_DIR/scripts/lota-proton-hook"

if [[ ! -x "$WRAPPER" ]]; then
    FAIL "missing artifact: %s" "$WRAPPER"
    test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

says() { grep -qi -- "$2" <<<"$1"; }
denies() { ! grep -qi -- "$2" <<<"$1"; }

# A library the wrapper can find, so every case below is decided by the switch.
# It is an empty file and not a loadable object: nothing here loads it,
# and the assertions read the LD_PRELOAD the game was handed.
LIB="$WORK_DIR/liblota_wine_hook.so"
: >"$LIB"

# lota-protect stand-in: leaves a mark, then runs what follows "--"
PROTECT="$WORK_DIR/lota-protect"
MARK="$WORK_DIR/protected"
cat >"$PROTECT" <<STUB
#!/bin/bash
[[ "\${1:-}" == "--" ]] || exit 99
shift
: >"$MARK"
exec "\$@"
STUB
chmod 755 "$PROTECT"
export LOTA_PROTECT_PATH="$PROTECT"

protected() { [[ -e "$MARK" ]]; }
unprotected() { [[ ! -e "$MARK" ]]; }

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

# The wrapped command reports the LD_PRELOAD it was exec'd with,
# which is the whole question. stdout and stderr are captured apart so a warning
# cannot be mistaken for the payload.
run_wrapper() {
    local out_file="$WORK_DIR/out"
    local err_file="$WORK_DIR/err"

    set +e
    env "$@" LOTA_HOOK_LIB_PATH="$LIB" \
        "$WRAPPER" /bin/sh -c 'printf "%s\n" "${LD_PRELOAD:-}"' \
        >"$out_file" 2>"$err_file"
    rc=$?
    set -e
    out="LD_PRELOAD=[$(own_preload "$(cat "$out_file")")]"
    err=$(cat "$err_file")
    return $rc
}

# the default: the library is found and preloaded
run_wrapper LOTA_HOOK_QUIET=
TEST "unset: the wrapper preloads the library"
says "$out" "LD_PRELOAD=\[$LIB\]" || FAIL "%s" "$out"
TEST "unset: no warning is printed"
denies "$err" "LOTA_HOOK_DISABLE" || FAIL "%s" "$err"

# the documented value
run_wrapper LOTA_HOOK_DISABLE=1
TEST "DISABLE=1: LD_PRELOAD reaches the game empty"
says "$out" 'LD_PRELOAD=\[\]' || FAIL "%s" "$out"
TEST "DISABLE=1: the library is not preloaded"
denies "$out" "$LIB" || FAIL "%s" "$out"
TEST "DISABLE=1: one warning names the switch"
says "$err" "LOTA_HOOK_DISABLE" || FAIL "%s" "$err"

# Count the wrapper's own lines, not every line on the channel:
# the stub library is not loadable, so when it does reach LD_PRELOAD the dynamic
# loader writes a line of its own, and counting those would score a wrapper that
# said nothing.
TEST "DISABLE=1: the wrapper writes one line"
test "$(grep -c "^lota-proton-hook:" <<<"$err")" -eq 1 || FAIL

# the value the library also accepts, so the two layers agre
run_wrapper LOTA_HOOK_DISABLE=true
TEST "DISABLE=true: LD_PRELOAD reaches the game empty"
says "$out" 'LD_PRELOAD=\[\]' || FAIL "%s" "$out"
TEST "DISABLE=true: one warning names the switch"
says "$err" "LOTA_HOOK_DISABLE" || FAIL "%s" "$err"

# anything else is not the switch:
#   an unset-shaped value must not disable the hook,
#   or a player who exports 0 loses attestation silently
run_wrapper LOTA_HOOK_DISABLE=0
TEST "DISABLE=0: the library is still preloaded"
says "$out" "LD_PRELOAD=\[$LIB\]" || FAIL "%s" "$out"
run_wrapper LOTA_HOOK_DISABLE=""
TEST "DISABLE=empty: the library is still preloaded"
says "$out" "LD_PRELOAD=\[$LIB\]" || FAIL "%s" "$out"

# player's own LD_PRELOAD survives the pass-through untouched:
#   the switch removes LOTA from the launch, not everything else
run_wrapper LOTA_HOOK_DISABLE=1 LD_PRELOAD=/lib64/libfoo.so
TEST "DISABLE=1: an existing LD_PRELOAD is passed through"
says "$out" 'LD_PRELOAD=\[/lib64/libfoo.so\]' || FAIL "%s" "$out"

# the other documented fallback still behaves, and says something different:
#   the two paths must not be told apart by guesswork
set +e
missing_err=$(env LOTA_HOOK_LIB_PATH="$WORK_DIR/no-such-hook.so" \
    "$WRAPPER" /bin/true 2>&1 >/dev/null)
set -e
TEST "missing library: the wrapper still warns"
says "$missing_err" "not found" || FAIL "%s" "$missing_err"
TEST "missing library: the warning is not the disable one"
denies "$missing_err" "LOTA_HOOK_DISABLE" || FAIL "%s" "$missing_err"

# the launch itself goes through lota-protect, arguments intact
rm -f "$MARK"
run_wrapper LOTA_HOOK_QUIET=
TEST "unset: the command runs through lota-protect"
protected || FAIL
set +e
args_out=$(env LOTA_HOOK_LIB_PATH="$LIB" \
    "$WRAPPER" /bin/sh -c 'printf "[%s]" "$@"' sh "a b" "" c 2>/dev/null)
set -e
TEST "unset: no argument is split or dropped"
test "$args_out" = '[a b][][c]' || FAIL

rm -f "$MARK"
run_wrapper LOTA_HOOK_DISABLE=1
TEST "DISABLE=1: lota-protect is skipped as well"
unprotected || FAIL

rm -f "$MARK"
set +e
env LOTA_HOOK_LIB_PATH="$WORK_DIR/no-such-hook.so" \
    "$WRAPPER" /bin/true >/dev/null 2>&1
set -e
TEST "missing library: the launch is still protected"
protected || FAIL

rm -f "$MARK"
set +e
noprotect_err=$(env LOTA_PROTECT_PATH="$WORK_DIR/no-such-protect" \
    LOTA_HOOK_LIB_PATH="$LIB" "$WRAPPER" /bin/true 2>&1 >/dev/null)
noprotect_rc=$?
set -e
TEST "no lota-protect: the command still runs"
test "$noprotect_rc" -eq 0 || FAIL
TEST "no lota-protect: the wrapper says it is unprotected"
says "$noprotect_err" "starting unprotected" || FAIL "%s" "$noprotect_err"

test_end
