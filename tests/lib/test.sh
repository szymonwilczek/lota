# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Report format of tests/test.h for shell tests:
#
#	. "$REPO_DIR/tests/lib/test.sh"
#	test_begin "proton hook abi"
#	TEST "the preload names \$LIB"
#	says "$preload" '\$LIB' || FAIL "preload %s" "$preload"
#	test_end
#
# test_begin owns the EXIT trap; exit-time commands go to test_cleanup.
# TEST, FAIL and SKIP must run in the script's own shell, not a subshell.

_TEST_WIDTH=80
_TEST_NAME_MAX=63

_test_group=
_test_color=0
_test_run=0
_test_passed=0
_test_failed=0
_test_skipped=0
_test_open=0
_test_state=0 # 0 pass, 1 fail, 2 skip
_test_name=
_test_detail=
_test_cleanup=()

_test_record() {
    [ -n "${LOTA_TEST_SUMMARY:-}" ] || return 0
    # shellcheck disable=SC2059
    printf "$@" >>"$LOTA_TEST_SUMMARY" 2>/dev/null || true
}

_test_close() {
    local word ansi dots line

    [ "$_test_open" -eq 1 ] || return 0
    _test_open=0

    case $_test_state in
	0) word=PASS ansi='\033[32m' ;;
	1) word=FAIL ansi='\033[1;31m' ;;
	*) word=SKIP ansi='\033[90m' ;;
    esac
    printf -v dots '%*s' $((_TEST_NAME_MAX + 3 - ${#_test_name})) ''
    if [ "$_test_color" -eq 1 ]; then
	printf "  [%3d] %s %s $ansi%s\033[0m\n" "$_test_run" \
	       "$_test_name" "${dots// /.}" "$word"
    else
	printf '  [%3d] %s %s %s\n' "$_test_run" "$_test_name" \
	       "${dots// /.}" "$word"
    fi
    if [ -n "$_test_detail" ]; then
	while IFS= read -r line; do
	    printf '        %s\n' "$line"
	done <<<"${_test_detail%$'\n'}"
    fi

    case $_test_state in
	0) _test_passed=$((_test_passed + 1)) ;;
	1)
	    _test_failed=$((_test_failed + 1))
	    _test_record 'F\t%s\t%d\t%s\n' "$_test_group" "$_test_run" \
			 "$_test_name"
	    ;;
	*) _test_skipped=$((_test_skipped + 1)) ;;
    esac
}

_test_footer() {
    local line="  $_test_group: $_test_passed passed"

    [ "$_test_failed" -eq 0 ] || line+=", $_test_failed failed"
    [ "$_test_skipped" -eq 0 ] || line+=", $_test_skipped skipped"
    printf '%s\n\n' "$line"
    _test_record 'G\t%s\t%d\t%d\t%d\n' "$_test_group" "$_test_passed" \
		 "$_test_failed" "$_test_skipped"
    _test_group=
}

_test_mark() {
    local state=$1 msg

    shift
    [ "$_test_open" -eq 1 ] || TEST "(setup)"
    if [ "$state" -eq 1 ] || [ "$_test_state" -eq 0 ]; then
	_test_state=$state
    fi
    [ $# -gt 0 ] || return 0
    # shellcheck disable=SC2059
    printf -v msg -- "$@"
    _test_detail+="$msg"$'\n'
}

_test_exit() {
    local rc=$? cmd

    set +e
    if [ -n "$_test_group" ]; then
	[ "$rc" -eq 0 ] || FAIL "exited with status %d" "$rc"
	_test_close
	_test_footer
    fi
    for cmd in "${_test_cleanup[@]}"; do
	eval "$cmd"
    done
    exit "$rc"
}

# test_begin <group> [<path>]: the header names <path>,
# by default the running script relative to the repository root
test_begin() {
    local root line pad path=${2:-}

    _test_group=$1
    case ${LOTA_TEST_COLOR:-auto} in
	always) _test_color=1 ;;
	never) _test_color=0 ;;
	*)
	    _test_color=0
	    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] &&
		   [ "${TERM:-}" != dumb ]; then
		_test_color=1
	    fi
	    ;;
    esac
    if [ -z "$path" ]; then
	root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
	path=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
	path=${path#"$root"/}
    fi
    printf -v line -- '-- %s (%s) ' "$_test_group" "$path"
    pad=$((_TEST_WIDTH - ${#line}))
    [ "$pad" -ge 3 ] || pad=3
    printf -v pad '%*s' "$pad" ''
    printf '%s%s\n' "$line" "${pad// /-}"
    trap _test_exit EXIT
}

# test_cleanup <command>: run by eval at exit, in the order given
test_cleanup() {
    _test_cleanup+=("$1")
}

TEST() {
    _test_close
    _test_run=$((_test_run + 1))
    _test_open=1
    _test_state=0
    _test_detail=
    if [ ${#1} -gt $_TEST_NAME_MAX ]; then
	_test_name="${1:0:$((_TEST_NAME_MAX - 3))}..."
    else
	_test_name=$1
    fi
}

FAIL() {
    _test_mark 1 "$@"
}

SKIP() {
    _test_mark 2 "$@"
}

test_end() {
    local failed

    _test_close
    failed=$_test_failed
    _test_footer
    [ "$failed" -eq 0 ] && exit 0
    exit 1
}
