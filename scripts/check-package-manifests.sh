#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Compare the two package manifests:
# 	the nfpm configs `make packages`
# 	and the release workflow build,
# 	and the RPM spec COPR builds from.
#
# Both describe the same packages, and a host gets whichever one built the package
# it installed.
# When they disagree the divergence is silent: file that only one manifest ships
# is simply absent on half the fleet, and the thing it configures stops happening
# there with no error anywhere.
#
# The check is set equality of installed paths, per package.
# It says nothing about file modes or ownership -- those are expressed too differently
# to compare -- so path listed by both still has to be reviewed by hand when it
# carries permissions that matter.
#
# Directories that only hold other listed paths are dropped from both sides:
# rpm requires %dir line for every directory a package owns while nfpm creates
# them along the way, so their absence is a spelling difference. A directory
# the package ships empty -- /var/lib/lota/profiles, whose contents are what says
# enrollment happened -- has no children to be dropped by, and stays compared.

set -euo pipefail

cd "$(dirname "$0")/.."

NFPM_DIR=packaging/nfpm
SPEC=packaging/rpm/lota.spec

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
	echo "The two manifests must list the same installed paths per package."
	exit 1
fi

echo "check-package-manifests: clean"
