#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/integration/test_license_boundary_scripts.sh
#
# scripts/check-license-boundary.sh zones scripts and the documentation
# toolchain as well as C and Go: an MIT script must not import or run a
# GPL-2.0-only one, and every package in Documentation/requirements.txt
# must carry a permissive license.
#
# Each case builds a throwaway git tree holding the gate and a few files;
# the packages are fake dist-info directories put on PYTHONPATH.
# The first case is the control: a clean tree passes.
#
# Requires:
#   - git, python3
#
# Runs unprivileged: nothing is installed.

set -euo pipefail

export LC_ALL=C

REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
GATE=scripts/check-license-boundary.sh

if [[ ! -x "$REPO_DIR/$GATE" ]]; then
	echo "[license-boundary-scripts] missing gate: $GATE" >&2
	exit 2
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

TREE="$WORK_DIR/tree"
SITE="$WORK_DIR/site"
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

# file PATH SPDX [LINE...]: a tracked file with the given license tag
file() {
	local path="$1" spdx="$2"
	shift 2
	mkdir -p "$TREE/$(dirname "$path")"
	{
		case "$path" in
		*.py) ;;
		*) echo "#!/usr/bin/env python3" ;;
		esac
		[[ -n "$spdx" ]] && echo "# SPDX-License-Identifier: $spdx"
		printf '%s\n' "$@"
	} >"$TREE/$path"
}

# package NAME LICENSE: a fake installed distribution
package() {
	mkdir -p "$SITE/$1-1.0.dist-info"
	printf 'Metadata-Version: 2.4\nName: %s\nVersion: 1.0\nLicense-Expression: %s\n' \
		"$1" "$2" >"$SITE/$1-1.0.dist-info/METADATA"
}

fixture() {
	rm -rf "$TREE" "$SITE"
	mkdir -p "$TREE/scripts" "$TREE/Documentation" "$SITE"
	cp -a "$REPO_DIR/$GATE" "$TREE/$GATE"
	file Documentation/conf.py MIT "import os"
	printf 'docpkg>=1.0\n' >"$TREE/Documentation/requirements.txt"
	package docpkg MIT
}

gate() {
	git -C "$TREE" init -q
	git -C "$TREE" add -A
	(cd "$TREE" && PYTHONPATH="$SITE" "$GATE" "$@") >"$WORK_DIR/out" 2>&1
}

passes_with() {
	local want="$1"
	shift
	gate "$@" && grep -qF -- "$want" "$WORK_DIR/out"
}

fails_with() {
	local want="$1"
	shift
	if gate "$@"; then
		return 1
	fi
	grep -qF -- "$want" "$WORK_DIR/out"
}

fixture
check "a clean tree passes and reads the package license" \
	passes_with "1 documentation packages"

fixture
file Documentation/gplext.py GPL-2.0-only "X = 1"
file Documentation/conf.py MIT "import gplext"
check "an MIT Python file importing a GPL one fails" \
	fails_with "imports gplext (Documentation/gplext.py)"

fixture
file Documentation/ext/__init__.py GPL-2.0-only "X = 1"
file Documentation/conf.py MIT "from ext import X"
check "an MIT Python file importing a GPL package fails" \
	fails_with "imports ext (Documentation/ext/__init__.py)"

fixture
file scripts/kdoc GPL-2.0-only "print(1)"
file Documentation/conf.py MIT "import subprocess" \
	"subprocess.run(['scripts/kdoc'])"
check "an MIT file running a GPL script by path fails" \
	fails_with "names scripts/kdoc"

fixture
file scripts/tool "" "print(1)"
check "a script without a license tag fails" \
	fails_with "scripts/tool: no SPDX-License-Identifier"

fixture
package docpkg GPL-2.0-or-later
check "a GPL documentation package fails" \
	fails_with "docpkg is licensed 'GPL-2.0-or-later'"

fixture
package docpkg "MIT AND LicenseRef-Proprietary"
check "a package with a non-permissive term fails" \
	fails_with "docpkg is licensed"

fixture
rm -rf "$SITE/docpkg-1.0.dist-info"
check "a missing package is reported as not checked" \
	passes_with "not checked (not installed: docpkg)"

fixture
rm -rf "$SITE/docpkg-1.0.dist-info"
check "--doc-packages fails on a missing package" \
	fails_with "not installed, license unread: docpkg" --doc-packages

if ((failures != 0)); then
	echo "[license-boundary-scripts] $failures case(s) failed" >&2
	exit 1
fi
echo "[license-boundary-scripts] all cases passed"
