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

. "$(dirname "$0")/../lib/test.sh"
test_begin "kerneldoc warnings"

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)

if ! command -v sphinx-build >/dev/null 2>&1; then
	FAIL "sphinx-build not found"
	test_end
fi

WORK_DIR=$(mktemp -d)
test_cleanup 'rm -rf "$WORK_DIR"'

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
		FAIL "%s" "$(cat "$WORK_DIR/log")"
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
TEST "every kernel-doc comment under include/ renders clean"
builds_clean || FAIL

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
TEST "an undescribed parameter fails"
fails_with "demo.h:1: WARNING: kernel-doc: parameter 'mode' not described in 'demo_open()'" || FAIL

header demo.h <<'EOF'
/**
 * demo_open() - Open a demo.
 * @path: where.
 * @flags: not in the prototype.
 */
int demo_open(const char *path);
EOF
project ".. kernel-doc:: demo.h" "$WORK_DIR/src"
TEST "an excess parameter fails"
fails_with "demo.h:4: WARNING: kernel-doc: excess parameter 'flags' described in 'demo_open()'" || FAIL

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
TEST "an undescribed member fails"
fails_with "member 'b' not described in 'struct demo'" || FAIL

header demo.h <<'EOF'
/**
 * this head names nothing
 */
int demo_close(int fd);
EOF
project ".. kernel-doc:: demo.h" "$WORK_DIR/src"
TEST "a comment head that does not parse fails"
fails_with "demo.h:2: WARNING: kernel-doc: cannot parse kernel-doc head" || FAIL

header demo.h <<'EOF'
/**
 * demo_close() - Close a demo.
 * @fd: the demo.
 */
int demo_close(int fd);
EOF
project ".. kernel-doc:: demo.h
   :identifiers: demo_close demo_missing" "$WORK_DIR/src"
TEST "an identifier with no comment fails"
fails_with "no comment for 'demo_missing' in demo.h" || FAIL

project ".. kernel-doc:: demo.h
   :doc: Nothing" "$WORK_DIR/src"
TEST "a DOC: title with no section fails"
fails_with "no 'DOC: Nothing' in demo.h" || FAIL

project ".. kernel-doc:: missing.h" "$WORK_DIR/src"
TEST "a header that does not exist fails"
fails_with "kernel-doc: no such file missing.h" || FAIL

test_end
