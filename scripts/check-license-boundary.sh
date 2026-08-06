#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# License-boundary gate.
#
# LOTA is dual-licensed on purpose:
# BPF programs that attach to kernel interfaces are GPL-2.0-only,
# and everything adopter embeds and ships
# -- agent userspace, SDK, verifier, CA -- is MIT so they can close
# their integration.
#
# That promise only holds while dependencies run one way:
# GPL file may include MIT one, MIT file may not include GPL one.
#
# This gate enforces that direction mechanically, and refuses source file that
# declares no license at all, since unlabelled file has no zone and would silently
# escape the rule.
#
# Usage: scripts/check-license-boundary.sh
# Requires: git, awk (no build, no toolchain)
set -euo pipefail

cd "$(dirname "$0")/.."

# vmlinux.h is generated from the running kernel's BTF by bpftool
# it is not project source and carries no SPDX tag of ours
EXEMPT_PATHS=(
	"include/vmlinux.h"
)

# Go module path prefix -> directory,
# so intra-project import resolves to the package it names
# Read from the go.mod files so new module is covered the moment it exists
declare -A GO_MODULE_DIRS=()

FAILURES=0

is_exempt() {
	local path="$1" exempt
	for exempt in "${EXEMPT_PATHS[@]}"; do
		[[ "$path" == "$exempt" ]] && return 0
	done
	return 1
}

# Reads the SPDX-License-Identifier from the first few lines of a file.
# Prints the expression, or nothing when the file declares none.
spdx_of() {
	awk '
		NR > 10 { exit }
		match($0, /SPDX-License-Identifier:[[:space:]]*/) {
			tag = substr($0, RSTART + RLENGTH)
			sub(/[[:space:]]*\*\/.*$/, "", tag)
			sub(/[[:space:]]*$/, "", tag)
			print tag
			exit
		}
	' "$1"
}

# Zone a license expression belongs to:
# gpl, mit, or empty when the expression is one this project does not use
# (which is itself an error)
zone_of() {
	case "$1" in
	"MIT") printf 'mit' ;;
	"GPL-2.0-only") printf 'gpl' ;;
	*) printf '' ;;
	esac
}

load_go_modules() {
	local modfile dir module
	while IFS= read -r modfile; do
		dir="$(dirname "$modfile")"
		module="$(awk '$1 == "module" { print $2; exit }' "$modfile")"
		[[ -n "$module" ]] && GO_MODULE_DIRS["$module"]="$dir"
	done < <(git ls-files '*go.mod')
}

# Resolves a quoted C include to repository path, the way the compiler does:
# first relative to the including file, then against -Iinclude.
# Prints nothing for header that is not in the tree (libc, libbpf, tss2)
resolve_c_include() {
	local from_dir="$1" header="$2" candidate

	for candidate in "$from_dir/$header" "include/$header"; do
		candidate="$(realpath -m --relative-to=. "$candidate")"
		if [[ -f "$candidate" ]]; then
			printf '%s' "$candidate"
			return
		fi
	done
}

# Resolves intra-project Go import to the directory holding its package.
# Prints nothing for third-party or stdlib import.
resolve_go_import() {
	local import="$1" module dir suffix

	for module in "${!GO_MODULE_DIRS[@]}"; do
		if [[ "$import" == "$module" ]]; then
			printf '%s' "${GO_MODULE_DIRS[$module]}"
			return
		fi
		if [[ "$import" == "$module"/* ]]; then
			suffix="${import#"$module"/}"
			dir="${GO_MODULE_DIRS[$module]}/$suffix"
			[[ -d "$dir" ]] && printf '%s' "$dir"
			return
		fi
	done
}

report() {
	printf 'check-license-boundary: %s\n' "$1" >&2
	FAILURES=$((FAILURES + 1))
}

main() {
	local path spdx zone
	local -A file_zone=()
	local -a sources=()

	load_go_modules

	while IFS= read -r path; do
		is_exempt "$path" && continue
		sources+=("$path")

		spdx="$(spdx_of "$path")"
		if [[ -z "$spdx" ]]; then
			report "$path: no SPDX-License-Identifier; every source file must name its license"
			continue
		fi

		zone="$(zone_of "$spdx")"
		if [[ -z "$zone" ]]; then
			report "$path: unexpected license '$spdx'; this project uses MIT (embeddable zone) or GPL-2.0-only (kernel-facing zone)"
			continue
		fi
		file_zone["$path"]="$zone"
	done < <(git ls-files '*.c' '*.h' '*.go')

	local header target import dep_zone
	for path in "${sources[@]}"; do
		[[ "${file_zone[$path]:-}" == "mit" ]] || continue

		case "$path" in
		*.c | *.h)
			while IFS= read -r header; do
				target="$(resolve_c_include "$(dirname "$path")" "$header")"
				[[ -n "$target" ]] || continue
				dep_zone="${file_zone[$target]:-}"
				if [[ "$dep_zone" == "gpl" ]]; then
					report "$path includes $target: an MIT file must not depend on a GPL-2.0-only one (the boundary allows the reverse only)"
				fi
			done < <(sed -n 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*"\([^"]*\)".*/\1/p' "$path")
			;;
		*.go)
			while IFS= read -r import; do
				target="$(resolve_go_import "$import")"
				[[ -n "$target" ]] || continue
				for dep in "$target"/*.go; do
					[[ -f "$dep" ]] || continue
					if [[ "${file_zone[$dep]:-}" == "gpl" ]]; then
						report "$path imports $import ($dep): an MIT file must not depend on a GPL-2.0-only one (the boundary allows the reverse only)"
					fi
				done
			done < <(sed -n 's/^[[:space:]]*\(_[[:space:]]*\|[A-Za-z0-9_]*[[:space:]]*\)\?"\(github\.com\/szymonwilczek\/[^"]*\)".*/\2/p' "$path")
			;;
		esac
	done

	if ((FAILURES != 0)); then
		printf 'check-license-boundary: %d violation(s)\n' "$FAILURES" >&2
		printf 'see Documentation/contributor/development/license-boundary.rst\n' >&2
		return 1
	fi

	printf 'check-license-boundary: clean (%d files)\n' "${#sources[@]}"
}

main "$@"
