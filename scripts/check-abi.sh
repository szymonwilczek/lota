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
# It then stages a prefix holding exactly what the packages install and builds
# against it the way an integrator does: each public header on its own,
# and compile-and-link through each pkg-config module.
# In tree everything builds with -Iinclude and -Lbuild, so a header the package
# does not ship, or a .pc naming a library that is not there, works here and fails
# for the integrator.
#
# Usage:
#   scripts/check-abi.sh            check against the baseline
#   scripts/check-abi.sh --update   rewrite the baseline from the build
#
# Requires: git, make, a C toolchain, nm and readelf (binutils)
# pkg-config module checks are skipped when pkg-config is absent
set -euo pipefail

cd "$(dirname "$0")/.."

BUILD_DIR="build"
ABI_DIR="packaging/abi"
HEADER_LIST="$ABI_DIR/public-headers.list"
PKGCONFIG_DIR="$BUILD_DIR/pkgconfig"
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

make sdk server-sdk wine-hook anticheat pkgconfig >/dev/null

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

# Stage a prefix holding exactly what the packages install
# -- headers, libraries and the pkg-config files -- and exercise it the way
# integrator does.
# .pc files resolve their prefix from their own location, so staged tree is enough
# nothing has to be installed into /usr for this to be the real path
PREFIX="$(mktemp -d)"
trap 'rm -rf "$PREFIX"' EXIT
mkdir -p "$PREFIX/include/lota" "$PREFIX/lib64/pkgconfig"

for header in "${PUBLIC_HEADERS[@]}"; do
	if [[ ! -f "include/$header" ]]; then
		fail "$header is listed in $HEADER_LIST but not in include/"
		continue
	fi
	cp "include/$header" "$PREFIX/include/lota/"
done

for lib in "${LIBRARIES[@]}"; do
	[[ -f "$BUILD_DIR/$lib.so.$ABI_VERSION" ]] || continue
	cp "$BUILD_DIR/$lib.so.$ABI_VERSION" "$PREFIX/lib64/"
	ln -sf "$lib.so.$ABI_VERSION" "$PREFIX/lib64/$lib.so.$ABI_MAJOR"
	ln -sf "$lib.so.$ABI_VERSION" "$PREFIX/lib64/$lib.so"
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

# pkg-config module per library, and a compile-and-link through each one.
# `make install` copies whatever the templates produce,
# so the templates are the enumeration;
# the package has to be checked against them
declare -A PC_NAME=(
	[liblotagaming]=lota-gaming
	[liblotaserver]=lota-server
	[liblota_anticheat]=lota-anticheat
	[liblota_wine_hook]=lota-wine-hook
)

# One trivially callable function per library,
# so the link is real and not dropped by --as-needed
declare -A PC_PROBE=(
	[liblotagaming]='lota_gaming.h|(void)lota_sdk_version();'
	[liblotaserver]='lota_server.h|(void)lota_server_sdk_version();'
	[liblota_anticheat]='lota_anticheat.h|(void)lota_ac_state_str(0);'
	[liblota_wine_hook]='lota_wine_hook.h|(void)lota_hook_active();'
)

packaged_pkgconfig() {
	sed -n 's|^[[:space:]]*- src: \./build/pkgconfig/\(.*\.pc\)$|\1|p' \
		"$DEVEL_PKG" | LC_ALL=C sort
}

expected_pc="$(printf '%s\n' "${PC_NAME[@]}" | sed 's/$/.pc/' | LC_ALL=C sort)"

if [[ "$(packaged_pkgconfig)" != "$expected_pc" ]]; then
	fail "$DEVEL_PKG ships a different pkg-config set than the libraries"
	diff -u <(printf '%s\n' "$expected_pc") <(packaged_pkgconfig) |
		sed 's/^/  /' >&2 || true
fi

if ! command -v pkg-config >/dev/null 2>&1; then
	printf 'ABI: pkg-config is absent; skipping the module checks\n' >&2
else
	for lib in "${LIBRARIES[@]}"; do
		pc="${PC_NAME[$lib]}"
		generated="$PKGCONFIG_DIR/$pc.pc"

		if [[ ! -f "$generated" ]]; then
			fail "$pc.pc was not generated (template missing?)"
			continue
		fi
		cp "$generated" "$PREFIX/lib64/pkgconfig/"

		if [[ "$(PKG_CONFIG_PATH="$PREFIX/lib64/pkgconfig" \
			pkg-config --modversion "$pc")" != "$ABI_VERSION" ]]; then
			fail "$pc.pc does not report the ABI version $ABI_VERSION"
		fi

		header="${PC_PROBE[$lib]%%|*}"
		call="${PC_PROBE[$lib]#*|}"
		printf '#include <lota/%s>\nint main(void){%s return 0;}\n' \
			"$header" "$call" >"$PREFIX/tu.c"

		if ! output="$(PKG_CONFIG_PATH="$PREFIX/lib64/pkgconfig" sh -c \
			"${CC:-cc} \$(pkg-config --cflags $pc) -o $PREFIX/tu \
				$PREFIX/tu.c \$(pkg-config --libs $pc)" 2>&1)"; then
			fail "$pc: an integrator cannot build against the staged prefix"
			printf '%s\n' "$output" | sed 's/^/  /' >&2
		fi
	done
fi

if [[ $FAILURES -gt 0 ]]; then
	printf 'ABI: %d problem(s); see %s\n' "$FAILURES" \
		"Documentation/contributor/development/api-stability.rst" >&2
	exit 1
fi

printf 'ABI: %d libraries, %d public headers and %d pkg-config modules match the baseline\n' \
	"${#LIBRARIES[@]}" "${#PUBLIC_HEADERS[@]}" "${#LIBRARIES[@]}"
