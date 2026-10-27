#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Public API/ABI gate.
#
# The SDK is what integrator builds and ships against, so its surface is frozen:
# the symbols each library exports, the soname it carries, the symbols the static
# archives carry, the set of headers the -devel package installs, and the layout
# of the types those headers declare.
#
# This gate compares all of it against the baseline checked in under packaging/abi/
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
LAYOUT_BASELINE="$ABI_DIR/types.list"
PKGCONFIG_DIR="$BUILD_DIR/pkgconfig"
DEVEL_PKG="packaging/nfpm/lota-sdk-devel.yaml"

LIBRARIES=(
    liblotagaming
    liblotaserver
    liblota_anticheat
    liblota_wine_hook
)

# The two the SDK also ships as static archives.
ARCHIVES=(
    liblotagaming
    liblotaserver
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

    if ! symbol_diff="$(diff -u "$baseline" <(exported_symbols "$so") 2>&1)"; then
	fail "$lib: exported symbols differ from $baseline"
	printf '%s\n' "$symbol_diff" | sed 's/^/  /' >&2
    fi

    soname="$(readelf --dynamic "$so" |
		sed -n 's/.*Library soname: \[\(.*\)\]/\1/p')"
    if [[ "$soname" != "$lib.so.$ABI_MAJOR" ]]; then
	fail "$lib: soname is $soname, expected $lib.so.$ABI_MAJOR"
    fi
done

# No version script hides archive symbols: each archive must be one object
# exporting exactly the baseline, which holds only while every non-API
# function stays static.
archive_symbols() {
    nm --defined-only -g "$1" |
	awk '$2 ~ /^[TDBRWV]$/ { print $3 }' | LC_ALL=C sort -u
}

for lib in "${ARCHIVES[@]}"; do
    archive="$BUILD_DIR/$lib.a"
    baseline="$ABI_DIR/$lib.symbols"
    members=0

    if [[ ! -f "$archive" ]]; then
	fail "$lib: $archive was not built"
	continue
    fi

    # baseline records the shared library's nodes; an archive has none
    if ! symbol_diff="$(diff -u <(sed 's/@@.*//' "$baseline" | LC_ALL=C sort -u) \
		<(archive_symbols "$archive") 2>&1)"; then
	fail "$lib: the archive holds symbols that are not the API"
	printf '%s\n' "$symbol_diff" | sed 's/^/  /' >&2
    fi

    members="$(ar t "$archive" | grep -c .)"
    if [[ "$members" -ne 1 ]]; then
	fail "$lib: $members objects, so a static link no longer takes the whole API"
    fi
done

# Header set has three statements of itself that must agree:
# baseline list, what `make install` copies, and what the -devel package ships
mapfile -t PUBLIC_HEADERS < <(grep -v '^[[:space:]]*#' "$HEADER_LIST" |
	                          grep -v '^[[:space:]]*$' | LC_ALL=C sort)

# Size, alignment and member offsets of every public aggregate, every
# enumerator and every LOTA_* constant, as the compiler reports them:
# a moved member breaks a program without changing a symbol.
layout_dump() {
    local work probe gen tu
    work="$(mktemp -d)"
    probe="$work/probe.c"
    gen="$work/gen.awk"
    tu="$work/dump.c"

    # The preprocessor says which macros are strings (LOTA_HOOK_SNAPSHOT_FILE
    # expands through another macro); the quoted copy of the name stays put.
    {
	printf '#include "%s"\n' "${PUBLIC_HEADERS[@]}"
	sed -n 's/^#[[:space:]]*define[[:space:]]\{1,\}\(LOTA_[A-Z0-9_]\{1,\}\)[[:space:]].*/\1/p' \
	    "${PUBLIC_HEADERS[@]/#/include/}" | LC_ALL=C sort -u |
	    while read -r macro; do
		printf '__lota_abi_probe "%s" %s\n' "$macro" "$macro"
	    done
    } >"$probe"

    if ! ${CC:-cc} -E -Iinclude "$probe" >"$work/probe.i" 2>"$work/probe.err"; then
	sed 's/^/  /' "$work/probe.err" >&2
	rm -rf "$work"
	return 1
    fi

    # strings are frozen too (environment variables, state files); what
    # expands to neither, like the visibility attribute, is skipped
    awk '$1 == "__lota_abi_probe" {
		name = $2
		gsub(/"/, "", name)
		$1 = ""; $2 = ""
		sub(/^[[:space:]]+/, "")
		if ($0 ~ /^"/) print name " string"
		else if ($0 ~ /__attribute__/ || $0 == "") next
		else print name " value"
	}' "$work/probe.i" >"$work/macros"

    cat >"$gen" <<-'AWK'
		# Turn the public headers into a program that prints their layout.
		function strip(line,   res, p) {
			res = ""
			while (length(line)) {
				if (incomment) {
					p = index(line, "*/")
					if (p == 0) { line = ""; break }
					line = substr(line, p + 2)
					incomment = 0
				} else {
					p = index(line, "/*")
					if (p == 0) { res = res line; line = "" }
					else {
						res = res substr(line, 1, p - 1)
						line = substr(line, p + 2)
						incomment = 1
					}
				}
			}
			return res
		}

		function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }

		# Last identifier once array bounds and pointer punctuation are
		# gone, `uint8_t (*d)[32]` included.
		function member(agg, decl,   m) {
			m = decl
			sub(/;$/, "", m)
			gsub(/\[[^]]*\]/, "", m)
			gsub(/[^A-Za-z0-9_]+$/, "", m)
			if (!match(m, /[A-Za-z_][A-Za-z0-9_]*$/))
				return
			m = substr(m, RSTART, RLENGTH)
			printf "\tprintf(\"\\t%%-32s off=%%zu size=%%zu\\n\", \"%s\",\n", m
			printf "\t       offsetof(struct %s, %s),\n", agg, m
			printf "\t       sizeof(((struct %s *)0)->%s));\n", agg, m
	}

		BEGIN {
			while ((getline line < macros) > 0) {
				split(line, f, " ")
				kind[f[1]] = f[2]
			}
		}

		{
			raw = $0
			if (raw ~ /^#[ \t]*define[ \t]+LOTA_[A-Z0-9_]+[ \t]/) {
				name = raw
				sub(/^#[ \t]*define[ \t]+/, "", name)
				sub(/[ \t].*$/, "", name)
				if (kind[name] == "value")
					printf "\tprintf(\"macro %%-40s = %%lld\\n\", \"%s\",\n\t       (long long)(%s));\n", name, name
				else if (kind[name] == "string")
					printf "\tprintf(\"macro %%-40s = \\\"%%s\\\"\\n\", \"%s\", %s);\n", name, name
				next
			}

			l = trim(strip(raw))
			if (l == "")
				next

			if (state == "struct") {
				if (l ~ /^\}/) { state = ""; buf = ""; next }
				buf = buf " " l
				if (l ~ /;$/) { member(agg, trim(buf)); buf = "" }
				next
			}

			if (state == "enum") {
				if (l ~ /^\}/) { state = ""; next }
				if (match(l, /^[A-Z][A-Z0-9_]*/)) {
					e = substr(l, RSTART, RLENGTH)
					printf "\tprintf(\"\\t%%-40s = %%lld\\n\", \"%s\",\n\t       (long long)%s);\n", e, e
				}
				next
			}

			if (l ~ /^struct [A-Za-z_][A-Za-z0-9_]* \{$/) {
				split(l, a, /[ \t]+/)
				agg = a[2]
				state = "struct"
				buf = ""
				printf "\tprintf(\"struct %%s size=%%zu align=%%zu\\n\", \"%s\",\n", agg
				printf "\t       sizeof(struct %s), (size_t)_Alignof(struct %s));\n", agg, agg
				next
			}

			if (l ~ /^enum [A-Za-z_][A-Za-z0-9_]* \{$/) {
				split(l, a, /[ \t]+/)
				agg = a[2]
				state = "enum"
				printf "\tprintf(\"enum %%s size=%%zu\\n\", \"%s\", sizeof(enum %s));\n", agg, agg
				next
			}
		}
	AWK

    {
	printf '#include <stddef.h>\n#include <stdio.h>\n'
	printf '#include "%s"\n' "${PUBLIC_HEADERS[@]}"
	printf 'int main(void)\n{\n'
	awk -v macros="$work/macros" -f "$gen" \
	    "${PUBLIC_HEADERS[@]/#/include/}"
	printf '\treturn 0;\n}\n'
    } >"$tu"

    if ! ${CC:-cc} -Iinclude -Wall -Wextra -o "$work/dump" "$tu" \
	 2>"$work/cc.err"; then
	sed 's/^/  /' "$work/cc.err" >&2
	rm -rf "$work"
	return 1
    fi

    printf '# Layout of the public types, as the compiler reports it.\n'
    printf '# Regenerate with `make abi-baseline`; the diff is the review signal.\n'
    printf '# See Documentation/contributor/development/api-stability.rst\n'
    "$work/dump"
    local rc=$?
    rm -rf "$work"
    return $rc
}

if [[ $UPDATE -eq 1 ]]; then
    if ! layout_dump >"$LAYOUT_BASELINE"; then
	fail "the public types cannot be read out of the compiler"
	exit 1
    fi
    printf 'ABI: baseline rewritten from %s\n' "$BUILD_DIR"
    exit 0
fi

if ! layout="$(layout_dump)"; then
    fail "the public types cannot be read out of the compiler"
elif [[ ! -f "$LAYOUT_BASELINE" ]]; then
    fail "no layout baseline at $LAYOUT_BASELINE"
elif ! layout_diff="$(diff -u "$LAYOUT_BASELINE" <(printf '%s\n' "$layout") 2>&1)"; then
    fail "the layout of the public types differs from $LAYOUT_BASELINE"
    printf '%s\n' "$layout_diff" | sed 's/^/  /' >&2
fi

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

printf 'ABI: %d libraries, %d archives, %d public headers, the layout of the types they declare and %d pkg-config modules match the baseline\n' \
       "${#LIBRARIES[@]}" "${#ARCHIVES[@]}" "${#PUBLIC_HEADERS[@]}" "${#LIBRARIES[@]}"
