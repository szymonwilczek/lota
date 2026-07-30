#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Public API/ABI gate.
#
# The SDK is what integrator builds and ships against, so its surface is frozen:
# the symbols each library exports, the soname it carries, and the set of headers
# the -devel package installs.
#
# This gate compares all three against the baseline checked in under packaging/abi/
# and fails when they drift, so widening or breaking the surface is deliberate edit
# to that baseline rather than side effect of making a helper non-static.
#
# It also compiles each public header on its own against the installed set alone.
# In tree everything builds with -Iinclude, so public header that includes header
# the package does not ship compiles here and fails for the integrator.
#
# Usage:
#   scripts/check-abi.sh            check against the baseline
#   scripts/check-abi.sh --update   rewrite the baseline from the build
#
# Requires: git, make, a C toolchain, nm and readelf (binutils)
set -euo pipefail

cd "$(dirname "$0")/.."

BUILD_DIR="build"
ABI_DIR="packaging/abi"
HEADER_LIST="$ABI_DIR/public-headers.list"
DEVEL_PKG="packaging/nfpm/lota-sdk-devel.yaml"

LIBRARIES=(
	liblotagaming
	liblotaserver
	liblota_anticheat
	liblota_wine_hook
)

UPDATE=0
if [[ "${1:-}" == "--update" ]]; then
	UPDATE=1
elif [[ $# -gt 0 ]]; then
	printf 'usage: %s [--update]\n' "$0" >&2
	exit 2
fi

FAILURES=0

fail() {
	printf 'ABI: %s\n' "$1" >&2
	FAILURES=$((FAILURES + 1))
}

# Makefile is the single source of truth for the ABI version;
# baseline records what that version exports, not the version itself
abi_make_var() {
	sed -n "s/^$1 := \(.*\)$/\1/p" Makefile | head -1
}

ABI_MAJOR="$(abi_make_var LOTA_ABI_MAJOR)"
if [[ -z "$ABI_MAJOR" ]]; then
	fail "cannot read LOTA_ABI_MAJOR from the Makefile"
	exit 1
fi
ABI_VERSION="$ABI_MAJOR.$(abi_make_var LOTA_ABI_VERSION | cut -d. -f2-)"

# Exported symbols of shared library:
# dynamic table's defined text symbols, version node included,
# since symbol's node is part of what linked program records
exported_symbols() {
	nm --dynamic --defined-only "$1" | awk '$2 == "T" { print $3 }' | LC_ALL=C sort
}

make sdk server-sdk wine-hook anticheat >/dev/null

for lib in "${LIBRARIES[@]}"; do
	so="$BUILD_DIR/$lib.so.$ABI_VERSION"
	baseline="$ABI_DIR/$lib.symbols"

	if [[ ! -f "$so" ]]; then
		fail "$lib: $so was not built"
		continue
	fi

	if [[ $UPDATE -eq 1 ]]; then
		exported_symbols "$so" >"$baseline"
		continue
	fi

	if [[ ! -f "$baseline" ]]; then
		fail "$lib: no baseline at $baseline"
		continue
	fi

	if ! diff -u "$baseline" <(exported_symbols "$so") >/tmp/lota-abi-diff.$$ 2>&1; then
		fail "$lib: exported symbols differ from $baseline"
		sed 's/^/  /' /tmp/lota-abi-diff.$$ >&2
	fi
	rm -f /tmp/lota-abi-diff.$$

	soname="$(readelf --dynamic "$so" |
		sed -n 's/.*Library soname: \[\(.*\)\]/\1/p')"
	if [[ "$soname" != "$lib.so.$ABI_MAJOR" ]]; then
		fail "$lib: soname is $soname, expected $lib.so.$ABI_MAJOR"
	fi
done

if [[ $UPDATE -eq 1 ]]; then
	printf 'ABI: baseline rewritten from %s\n' "$BUILD_DIR"
	exit 0
fi

# Header set has three statements of itself that must agree:
# baseline list, what `make install` copies, and what the -devel package ships
mapfile -t PUBLIC_HEADERS < <(grep -v '^[[:space:]]*#' "$HEADER_LIST" |
	grep -v '^[[:space:]]*$' | LC_ALL=C sort)

installed_by_make() {
	sed -n 's|^[[:space:]]*install -m 644 \$(INC_DIR)/\([a-z_]*\.h\) .*|\1|p' \
		Makefile | LC_ALL=C sort
}

installed_by_package() {
	sed -n 's|^[[:space:]]*- src: \./include/\([a-z_]*\.h\)$|\1|p' \
		"$DEVEL_PKG" | LC_ALL=C sort
}

expected="$(printf '%s\n' "${PUBLIC_HEADERS[@]}")"

if [[ "$(installed_by_make)" != "$expected" ]]; then
	fail "make install copies a different header set than $HEADER_LIST"
	diff -u <(printf '%s\n' "$expected") <(installed_by_make) |
		sed 's/^/  /' >&2 || true
fi

if [[ "$(installed_by_package)" != "$expected" ]]; then
	fail "$DEVEL_PKG ships a different header set than $HEADER_LIST"
	diff -u <(printf '%s\n' "$expected") <(installed_by_package) |
		sed 's/^/  /' >&2 || true
fi

# Compile each public header alone,
# against prefix holding the installed set and nothing else
PREFIX="$(mktemp -d)"
trap 'rm -rf "$PREFIX"' EXIT
mkdir -p "$PREFIX/include/lota"

for header in "${PUBLIC_HEADERS[@]}"; do
	if [[ ! -f "include/$header" ]]; then
		fail "$header is listed in $HEADER_LIST but not in include/"
		continue
	fi
	cp "include/$header" "$PREFIX/include/lota/"
done

for header in "${PUBLIC_HEADERS[@]}"; do
	[[ -f "$PREFIX/include/lota/$header" ]] || continue
	printf '#include <lota/%s>\n' "$header" >"$PREFIX/tu.c"
	if ! output="$(${CC:-cc} -I"$PREFIX/include" -Wall -Wextra \
		-fsyntax-only "$PREFIX/tu.c" 2>&1)"; then
		fail "$header does not compile against the installed set alone"
		printf '%s\n' "$output" | sed 's/^/  /' >&2
	fi
done

if [[ $FAILURES -gt 0 ]]; then
	printf 'ABI: %d problem(s); see %s\n' "$FAILURES" \
		"Documentation/contributor/development/api-stability.rst" >&2
	exit 1
fi

printf 'ABI: %d libraries and %d public headers match the baseline\n' \
	"${#LIBRARIES[@]}" "${#PUBLIC_HEADERS[@]}"
