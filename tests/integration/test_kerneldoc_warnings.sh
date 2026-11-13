#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_kerneldoc_warnings.sh
#
# The kernel-doc directive (Documentation/sphinx/kerneldoc.py) turns every
# problem it finds in a header comment into a build warning, and the strict
# build fails on a warning. A wrong comment must never render quietly.
#
# The control renders every kernel-doc comment under include/ with the
# project's own conf.py and must build clean. The other cases render one
# made-up header each and expect the strict build to fail with the warning.
#
# Requires:
#   - sphinx-build (Documentation/requirements.txt)
#
# Runs unprivileged: everything is built in a scratch directory.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

if ! command -v sphinx-build >/dev/null 2>&1; then
    echo "[kerneldoc-warnings] sphinx-build not found" >&2
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

# project RST: a scratch Sphinx project using the real conf.py and extension,
# with kerneldoc_srctree pointed at $2
project() {
    rm -rf "$WORK_DIR/doc"
    mkdir -p "$WORK_DIR/doc"
    cp -a "$REPO_DIR/Documentation/conf.py" "$REPO_DIR/Documentation/sphinx" \
       "$REPO_DIR/Documentation/_templates" "$REPO_DIR/Documentation/_extra" \
       "$WORK_DIR/doc/"
    printf '\nkerneldoc_srctree = "%s"\n' "$2" >>"$WORK_DIR/doc/conf.py"
    printf '=====\nProbe\n=====\n\n%s\n' "$1" >"$WORK_DIR/doc/index.rst"
}

build() {
    sphinx-build -q -E -W --keep-going -b html "$WORK_DIR/doc" \
		 "$WORK_DIR/out" >"$WORK_DIR/log" 2>&1
}

builds_clean() {
    if ! build; then
	cat "$WORK_DIR/log" >&2
	return 1
    fi
}

fails_with() {
    ! build && grep -qF -- "$1" "$WORK_DIR/log"
}

# header NAME: write stdin as a made-up header under the scratch source tree
header() {
    mkdir -p "$WORK_DIR/src"
    cat >"$WORK_DIR/src/$1"
}

rst=""
for h in "$REPO_DIR"/include/*.h; do
    grep -qx '/\*\*' "$h" || continue
    rel=${h#"$REPO_DIR"/}
    rst+=$(printf '\n%s\n%s\n\n.. kernel-doc:: %s\n' "$rel" \
		  "$(printf '%*s' "${#rel}" '' | tr ' ' -)" "$rel")
    rst+=$'\n'
done
project "$rst" "$REPO_DIR"
check "every kernel-doc comment under include/ renders clean" builds_clean

header demo.h <<'EOF'
/**
 * demo_open() - Open a demo.
 * @path: where.
 *
 * Return: 0.
 */
int demo_open(const char *path, int mode);
EOF
project ".. kernel-doc:: demo.h" "$WORK_DIR/src"
check "an undescribed parameter fails" \
      fails_with "demo.h:1: WARNING: kernel-doc: parameter 'mode' not described in 'demo_open()'"

header demo.h <<'EOF'
/**
 * demo_open() - Open a demo.
 * @path: where.
 * @flags: not in the prototype.
 */
int demo_open(const char *path);
EOF
project ".. kernel-doc:: demo.h" "$WORK_DIR/src"
check "an excess parameter fails" \
      fails_with "demo.h:4: WARNING: kernel-doc: excess parameter 'flags' described in 'demo_open()'"

header demo.h <<'EOF'
/**
 * struct demo - A demo.
 * @a: first.
 */
struct demo {
	int a;
	unsigned int b[4];
};
EOF
project ".. kernel-doc:: demo.h" "$WORK_DIR/src"
check "an undescribed member fails" \
      fails_with "member 'b' not described in 'struct demo'"

header demo.h <<'EOF'
/**
 * this head names nothing
 */
int demo_close(int fd);
EOF
project ".. kernel-doc:: demo.h" "$WORK_DIR/src"
check "a comment head that does not parse fails" \
      fails_with "demo.h:2: WARNING: kernel-doc: cannot parse kernel-doc head"

header demo.h <<'EOF'
/**
 * demo_close() - Close a demo.
 * @fd: the demo.
 */
int demo_close(int fd);
EOF
project ".. kernel-doc:: demo.h
   :identifiers: demo_close demo_missing" "$WORK_DIR/src"
check "an identifier with no comment fails" \
      fails_with "no comment for 'demo_missing' in demo.h"

project ".. kernel-doc:: demo.h
   :doc: Nothing" "$WORK_DIR/src"
check "a DOC: title with no section fails" \
      fails_with "no 'DOC: Nothing' in demo.h"

project ".. kernel-doc:: missing.h" "$WORK_DIR/src"
check "a header that does not exist fails" \
      fails_with "kernel-doc: no such file missing.h"

if ((failures != 0)); then
    echo "[kerneldoc-warnings] $failures case(s) failed" >&2
    exit 1
fi
echo "[kerneldoc-warnings] all cases passed"
