#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Compare the nfpm configs (`make packages`, release) with the RPM spec (COPR).
# A path only one manifest ships is silently missing on hosts built from the
# other, so installed paths must match per package. Modes and ownership are
# not compared.
#
# The spec hardcodes the version nfpm reads from VERSION, so its Version
# and newest %changelog entry must match; a stale one makes rpmbuild fail on
# a missing source tarball.
#
# Parent directories of other listed paths are dropped (rpm needs %dir, nfpm
# does not); a directory shipped empty stays compared.

set -euo pipefail

cd "$(dirname "$0")/.."

NFPM_DIR=packaging/nfpm
SPEC=packaging/rpm/lota.spec
VERSION_FILE=VERSION

fail=0

report() {
    local prefix=$1 line

    while IFS= read -r line; do
        printf '%s%s\n' "$prefix" "$line"
    done <<<"$2"
}

# Drop every path that is a parent directory of another path in the same list
drop_parents() {
    awk '
		{ paths[NR] = $0 }
		END {
			for (i = 1; i <= NR; i++) {
				parent = 0
				for (j = 1; j <= NR; j++)
					if (i != j &&
					    index(paths[j], paths[i] "/") == 1) {
						parent = 1
						break
					}
				if (!parent)
					print paths[i]
			}
		}
	'
}

# Installed paths one nfpm config ships, one per line.
#
# `dst:` is the installed path whether the entry carries a src, is bare directory
# or is a license file.
# dst ending in a slash is a destination directory and the name comes from the src,
# which for the shared libraries is a glob over the soname -- the same glob the spec
# has to use, since neither manifest spells the ABI version.
nfpm_paths() {
    local cfg=$1

    awk '
		/^[ \t]*-?[ \t]*src:[ \t]*/ {
			sub(/^[^:]*:[ \t]*/, "")
			gsub(/^["'"'"']|["'"'"']$/, "")
			src = $0
			next
		}
		/^[ \t]*-?[ \t]*dst:[ \t]*/ {
			sub(/^[^:]*:[ \t]*/, "")
			gsub(/^["'"'"']|["'"'"']$/, "")
			if ($0 ~ /\/$/ && src != "") {
				name = src
				sub(/.*\//, "", name)
				print $0 name
			} else {
				print
			}
			src = ""
		}
	' "$cfg" | sort -u | drop_parents | sort -u
}

# Installed paths one %files section of the spec ships, one per line.
#
# RPM macros are expanded against the distribution defaults the spec is built under;
# %license is expanded the way rpm does it, into the package's own licence directory,
# because that is where nfpm spells it literally.
spec_paths() {
    local section=$1 pkg=$2

    awk -v section="$section" -v pkg="$pkg" '
		/^%files/ {
			sub(/^%files[ \t]*/, "")
			in_section = ($0 == section)
			next
		}
		/^%(package|description|prep|build|install|post|preun|postun|changelog)/ {
			in_section = 0
			next
		}
		!in_section || /^[ \t]*$/ || /^#/ { next }
		{
			line = $0
			is_license = (line ~ /^%license[ \t]/)

			# %dir, %attr(...), %config(noreplace), %license and %ghost
			# may precede a path in any order and any number at once;
			# none of them changes which path is shipped
			while (line ~ /^%(dir|ghost|license|config|attr|verify)(\([^)]*\))?[ \t]+/)
				sub(/^%(dir|ghost|license|config|attr|verify)(\([^)]*\))?[ \t]+/, "", line)

			gsub(/%\{_bindir\}/, "/usr/bin", line)
			gsub(/%\{_sbindir\}/, "/usr/sbin", line)
			gsub(/%\{_libdir\}/, "/usr/lib64", line)
			gsub(/%\{_includedir\}/, "/usr/include", line)
			gsub(/%\{_datadir\}/, "/usr/share", line)
			gsub(/%\{_sysconfdir\}/, "/etc", line)
			gsub(/%\{_sharedstatedir\}/, "/var/lib", line)
			gsub(/%\{_unitdir\}/, "/usr/lib/systemd/system", line)
			gsub(/%\{_presetdir\}/, "/usr/lib/systemd/system-preset", line)
			gsub(/%\{_userunitdir\}/, "/usr/lib/systemd/user", line)
			gsub(/%\{_tmpfilesdir\}/, "/usr/lib/tmpfiles.d", line)
			gsub(/%\{_sysusersdir\}/, "/usr/lib/sysusers.d", line)
			gsub(/%\{_udevrulesdir\}/, "/usr/lib/udev/rules.d", line)
			gsub(/%\{_prefix\}/, "/usr", line)
			gsub(/%\{name\}/, "lota", line)

			if (is_license) {
				n = split(line, files, /[ \t]+/)
				for (i = 1; i <= n; i++)
					if (files[i] != "")
						print "/usr/share/licenses/" pkg "/" files[i]
				next
			}
			print line
		}
	' "$SPEC" | sort -u | drop_parents | sort -u
}

# rpm spells the prerelease separator `~`
# (sorts below the release; `-` is not allowed in a version)
spec_field() {
    awk -v field="$1" '
		$1 == field":" { print $2; exit }
	' "$SPEC"
}

tree_version=$(tr -d '[:space:]' <"$VERSION_FILE")
spec_version=$(spec_field Version)
want_version=${tree_version//-/\~}

if [ "$spec_version" != "$want_version" ]; then
    fail=1
    echo "FAIL: ${SPEC} says Version: ${spec_version}, the tree is ${tree_version}"
    echo "  rpmbuild would look for lota-${spec_version}.tar.gz and"
    echo "  \`make srpm\` writes lota-${want_version}.tar.gz"
fi

# %changelog head, which is the version an operator reads off the built package
spec_release=$(spec_field Release)
want_entry="${want_version}-${spec_release%\%*}"
changelog_entry=$(awk '
	/^%changelog/ { in_log = 1; next }
	in_log && /^\* / { sub(/^.* - /, ""); print; exit }
' "$SPEC")

if [ "$changelog_entry" != "$want_entry" ]; then
    fail=1
    echo "FAIL: the newest %changelog entry in ${SPEC} is ${changelog_entry:-none}, not ${want_entry}"
fi

for cfg in "$NFPM_DIR"/*.yaml; do
    pkg=$(awk '/^name:[ \t]*/ { sub(/^name:[ \t]*/, ""); print; exit }' "$cfg")
    [ -n "$pkg" ] || continue

    # lota-agent is built from the spec's `%files agent` and so on:
    # one source package, subpackages named after their section
    section=${pkg#lota-}

    if ! grep -q "^%files[ \t]*${section}\$" "$SPEC"; then
        echo "FAIL: ${pkg} has an nfpm config but no '%files ${section}' in ${SPEC}"
        fail=1
        continue
    fi

    only_nfpm=$(comm -23 <(nfpm_paths "$cfg") <(spec_paths "$section" "$pkg"))
    only_spec=$(comm -13 <(nfpm_paths "$cfg") <(spec_paths "$section" "$pkg"))

    if [ -n "$only_nfpm" ] || [ -n "$only_spec" ]; then
        fail=1
        echo "FAIL: ${pkg} ships different files depending on which manifest built it"
        [ -n "$only_nfpm" ] && report "  nfpm only: " "$only_nfpm"
        [ -n "$only_spec" ] && report "  spec only: " "$only_spec"
    fi
done

# the other direction: subpackage the spec builds and nfpm does not
while read -r section; do
    [ -n "$section" ] || continue
    if [ ! -f "${NFPM_DIR}/lota-${section}.yaml" ]; then
        echo "FAIL: '%files ${section}' in ${SPEC} has no ${NFPM_DIR}/lota-${section}.yaml"
        fail=1
    fi
done < <(awk '/^%files[ \t]+/ { sub(/^%files[ \t]+/, ""); print }' "$SPEC")

if [ "$fail" -ne 0 ]; then
    echo
    echo "The two manifests must list the same installed paths per package,"
    echo "and the spec must name the version the tree builds."
    exit 1
fi

echo "check-package-manifests: clean"
