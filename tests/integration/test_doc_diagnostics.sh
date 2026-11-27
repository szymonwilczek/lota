#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_doc_diagnostics.sh
#
# scripts/check-doc-diagnostics.sh passes a quoted message only when a source
# file can print it. Its reader must lex the source: a '"' character literal
# or a quote inside a comment must not open a string, or the literals after
# it can pair with the wrong partner: a real message is lost, and the code and
# comments between can become "messages" a quote matches.
#
# Each case quotes one literal in a scratch repository and runs the gate on it.
#
# Requires:
#   - git, python3
#
# Runs unprivileged: everything is built in a scratch directory.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

failures=0

check() {
    local msg="$1"
    shift
    if "$@"; then
	echo "PASS: $msg"
    else
	echo "FAIL: $msg" >&2
	failures=$((failures + 1))
    fi
}

# file PATH: write stdin to PATH under the scratch repository
file() {
    mkdir -p "$WORK_DIR/$(dirname "$1")"
    cat >"$WORK_DIR/$1"
}

# gate LITERAL: quote LITERAL in the documentation and run the gate
gate() {
    printf '====\nDemo\n====\n\nThe tool prints ``%s``.\n' "$1" \
	   >"$WORK_DIR/Documentation/index.rst"
    git -C "$WORK_DIR" add -A
    "$WORK_DIR/scripts/check-doc-diagnostics.sh" >"$WORK_DIR/log" 2>&1
}

passes() {
    if ! gate "$1"; then
	cat "$WORK_DIR/log" >&2
	return 1
    fi
}

fails() {
    ! gate "$1" &&
	grep -qF -- "no source message prints '$1'" "$WORK_DIR/log"
}

git -C "$WORK_DIR" init -q
mkdir -p "$WORK_DIR/scripts" "$WORK_DIR/Documentation"
cp "$REPO_DIR/scripts/check-doc-diagnostics.sh" "$WORK_DIR/scripts/"

file src/demo/stages.c <<'EOF'
/* the reader doesn't print this comment */
static int is_quote(char c)
{
	return c == '"'; /* Comment words are never printed */
}

static const char *const done = "Install finished "
	/* one message over two lines */
	"without errors.";
EOF

file src/demo/demo.go <<'EOF'
package demo

// the `go` reader keeps raw strings
func quote(r rune) bool { return r == '"' || r == '`' }

var msg = "Rune quotes leave this message whole"

const usage = `Usage shows every raw line`
EOF

file installer/demo.c <<'EOF'
static const char *const hint = "Installer messages count as well";
EOF

file include/demo.h <<'EOF'
#define DEMO_HINT "Header messages count as well"
EOF

file examples/demo/run.sh <<'EOF'
echo "Example scripts print their text"
EOF

file examples/demo/run.py <<'EOF'
print("Example programs print their text")
EOF

file packaging/nfpm/scripts/postinstall.sh <<'EOF'
echo "Package scripts print their text"
EOF

check "a message after a '\"' character literal passes" \
      passes "Install finished without errors."
check "a comment after a '\"' character literal fails" \
      fails "Comment words are never printed"
check "a message no source prints fails" \
      fails "Install never ran at all"
check "a Go raw string after a '\`' rune passes" \
      passes "Usage shows every raw line"
check "a Go message after a '\"' rune passes" \
      passes "Rune quotes leave this message whole"
check "a message in installer/ passes" \
      passes "Installer messages count as well"
check "a message in include/ passes" \
      passes "Header messages count as well"
check "an example shell script passes verbatim" \
      passes "Example scripts print their text"
check "an example Python program passes verbatim" \
      passes "Example programs print their text"
check "a package script passes verbatim" \
      passes "Package scripts print their text"

if ((failures != 0)); then
    echo "[doc-diagnostics] $failures case(s) failed" >&2
    exit 1
fi
echo "[doc-diagnostics] all cases passed"
