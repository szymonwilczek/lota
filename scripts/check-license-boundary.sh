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
# Scripts count as source: *.py, *.pl, *.pm and every file with a shebang.
# An MIT script depends on what it imports and on any GPL script it names by
# path, since naming one is how it runs it.
#
# The documentation toolchain is a dependency too: every package in
# Documentation/requirements.txt must carry a permissive license. Reading that
# needs the packages installed; without them the check says so and is skipped,
# and --doc-packages turns the skip into a failure.
#
# Usage: scripts/check-license-boundary.sh [--doc-packages]
# Requires: git, awk; python3 with the documentation packages for that check
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

DOC_REQUIREMENTS="Documentation/requirements.txt"
DOC_PACKAGES_READ=0
PYTHON="${PYTHON:-python3}"

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

# Resolves a Python import to a tracked module, first next to the importing
# file, then from the repository root. Leading dots of a relative import
# resolve against the importing file's directory.
# Prints nothing for stdlib or third-party import.
resolve_py_import() {
	local from_dir="$1" module="$2" rel base candidate

	rel="${module##.}"
	rel="${rel##.}"
	rel="${rel//.//}"
	[[ -n "$rel" ]] || return 0
	for base in "$from_dir" "."; do
		for candidate in "$base/$rel.py" "$base/$rel/__init__.py"; do
			candidate="$(realpath -m --relative-to=. "$candidate")"
			if [[ -f "$candidate" ]]; then
				printf '%s' "$candidate"
				return
			fi
		done
	done
}

# Resolves a Perl module name (Foo::Bar) to a tracked Foo/Bar.pm,
# first next to the using file, then from the repository root.
resolve_pl_import() {
	local from_dir="$1" module="$2" rel base candidate

	rel="${module//:://}.pm"
	for base in "$from_dir" "."; do
		candidate="$(realpath -m --relative-to=. "$base/$rel")"
		if [[ -f "$candidate" ]]; then
			printf '%s' "$candidate"
			return
		fi
	done
}

# Module names a Python file imports, one per line.
py_imports() {
	awk '
		/^[[:space:]]*import[[:space:]]/ {
			sub(/^[[:space:]]*import[[:space:]]+/, "")
			sub(/#.*/, "")
			n = split($0, mods, ",")
			for (i = 1; i <= n; i++) {
				m = mods[i]
				sub(/^[[:space:]]+/, "", m)
				sub(/[[:space:]].*$/, "", m)
				if (m != "") print m
			}
		}
		/^[[:space:]]*from[[:space:]]+[.A-Za-z0-9_]+[[:space:]]+import/ {
			print $2
		}
	' "$1"
}

# Module names a Perl file uses or requires, one per line.
pl_imports() {
	sed -n 's/^[[:space:]]*\(use\|require\)[[:space:]]\+\([A-Za-z_][A-Za-z0-9_:]*\).*/\2/p' "$1"
}

# Tracked files the gate zones: C, headers, Go, and every script.
source_files() {
	git ls-files '*.c' '*.h' '*.go' '*.py' '*.pl' '*.pm'
	git ls-files -z | xargs -0 -r awk '
		FNR == 1 {
			if (/^#!/ && FILENAME !~ /\.(c|h|go|py|pl|pm)$/)
				print FILENAME
			nextfile
		}
	'
}

is_script() {
	case "$1" in
	*.c | *.h | *.go) return 1 ;;
	esac
	return 0
}

# Package names listed in the documentation requirements, one per line.
doc_packages() {
	sed -e 's/#.*//' -e 's/[[:space:]]//g' "$DOC_REQUIREMENTS" |
		sed -e 's/[<>=!~;\[].*//' | awk 'NF'
}

# Prints "name<TAB>license" per package, or "name<TAB>" when not installed.
# The license is the License-Expression, else the License field, else the
# License :: classifiers joined by " AND ".
doc_package_licenses() {
	"$PYTHON" - "$@" <<-'EOF'
		import importlib.metadata as md
		import sys
		for name in sys.argv[1:]:
		    try:
		        meta = md.metadata(name)
		    except md.PackageNotFoundError:
		        print(f"{name}\t")
		        continue
		    lic = meta.get("License-Expression") or ""
		    if not lic and len(meta.get("License") or "") <= 64:
		        lic = meta.get("License") or ""
		    if not lic:
		        lic = " AND ".join(c.split("::")[-1].strip()
		                           for c in meta.get_all("Classifier") or []
		                           if c.startswith("License ::"))
		    print(f"{name}\t{lic.strip() or '?'}")
	EOF
}

# Every license named in the expression is on the permissive list.
permissive() {
	local expr="$1" term
	[[ "$expr" == *GPL* ]] && return 1
	expr="${expr//(/ }"
	expr="${expr//)/ }"
	expr="${expr// AND /$'\n'}"
	expr="${expr// OR /$'\n'}"
	expr="${expr// WITH /$'\n'}"
	while IFS= read -r term; do
		term="${term#"${term%%[![:space:]]*}"}"
		term="${term%"${term##*[![:space:]]}"}"
		case "$term" in
		"" | MIT | "MIT License" | BSD-2-Clause | BSD-3-Clause | "BSD License" | \
			Apache-2.0 | "Apache Software License" | ISC | "ISC License (ISCL)" | \
			PSF-2.0 | Python-2.0 | "Python Software Foundation License") ;;
		*) return 1 ;;
		esac
	done <<<"$expr"
	return 0
}

check_doc_packages() {
	local required="$1" name lic missing=()
	DOC_PACKAGES_READ=0
	local -a names=()

	if [[ ! -f "$DOC_REQUIREMENTS" ]]; then
		return
	fi
	mapfile -t names < <(doc_packages)
	((${#names[@]} != 0)) || return 0

	if ! command -v "$PYTHON" >/dev/null 2>&1; then
		missing=("${names[@]}")
	else
		while IFS=$'\t' read -r name lic; do
			if [[ -z "$lic" ]]; then
				missing+=("$name")
				continue
			fi
			DOC_PACKAGES_READ=$((DOC_PACKAGES_READ + 1))
			if ! permissive "$lic"; then
				report "$DOC_REQUIREMENTS: $name is licensed '$lic'; the documentation toolchain must be permissive (MIT, BSD, Apache-2.0, ISC, PSF)"
			fi
		done < <(doc_package_licenses "${names[@]}")
	fi

	if ((${#missing[@]} != 0)); then
		if [[ "$required" == 1 ]]; then
			report "$DOC_REQUIREMENTS: not installed, license unread: ${missing[*]}"
		else
			printf 'check-license-boundary: documentation packages not checked (not installed: %s)\n' "${missing[*]}"
		fi
	fi
}

report() {
	printf 'check-license-boundary: %s\n' "$1" >&2
	FAILURES=$((FAILURES + 1))
}

main() {
	local doc_required=0
	case "${1:-}" in
	"") ;;
	--doc-packages) doc_required=1 ;;
	*)
		printf 'usage: %s [--doc-packages]\n' "$0" >&2
		return 2
		;;
	esac

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
	done < <(source_files | sort -u)

	local -a gpl_scripts=()
	for path in "${!file_zone[@]}"; do
		if [[ "${file_zone[$path]}" == "gpl" ]] && is_script "$path"; then
			gpl_scripts+=("$path")
		fi
	done

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
		*.py)
			while IFS= read -r import; do
				target="$(resolve_py_import "$(dirname "$path")" "$import")"
				[[ -n "$target" ]] || continue
				if [[ "${file_zone[$target]:-}" == "gpl" ]]; then
					report "$path imports $import ($target): an MIT file must not depend on a GPL-2.0-only one (the boundary allows the reverse only)"
				fi
			done < <(py_imports "$path")
			;;
		*.pl | *.pm)
			while IFS= read -r import; do
				target="$(resolve_pl_import "$(dirname "$path")" "$import")"
				[[ -n "$target" ]] || continue
				if [[ "${file_zone[$target]:-}" == "gpl" ]]; then
					report "$path uses $import ($target): an MIT file must not depend on a GPL-2.0-only one (the boundary allows the reverse only)"
				fi
			done < <(pl_imports "$path")
			;;
		esac

		if is_script "$path"; then
			for target in "${gpl_scripts[@]}"; do
				if grep -qF -- "$target" "$path"; then
					report "$path names $target: an MIT script must not run a GPL-2.0-only one (the boundary allows the reverse only)"
				fi
			done
		fi
	done

	check_doc_packages "$doc_required"

	if ((FAILURES != 0)); then
		printf 'check-license-boundary: %d violation(s)\n' "$FAILURES" >&2
		printf 'see Documentation/process/license-boundary.rst\n' >&2
		return 1
	fi

	printf 'check-license-boundary: clean (%d files, %d documentation packages)\n' \
		"${#sources[@]}" "$DOC_PACKAGES_READ"
}

main "$@"
