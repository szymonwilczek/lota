#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Compare the nfpm configs (`make packages`, release) with the RPM spec (COPR).
# A path only one manifest ships is silently missing on hosts built from the
# other, so installed paths must match per package. Modes and ownership are
# not compared.
#
# The spec must not spell its version: Version and the newest %changelog
# entry are @VERSION@ and @CHANGELOG@, which make srpm fills from VERSION.
#
# A %files path `make install` writes only when its source exists must be
# produced by a target the spec's %build runs, or rpm fails with `File not
# found` after the whole tree has compiled.
#
# A path shipped under /var/lib/lota, /etc/lota, /usr/lib/lota or
# /usr/share/lota needs a package-owned parent: an unowned directory takes
# the umask's mode and escapes rpm -V.
#
# Parent directories of other listed paths are dropped (rpm needs %dir, nfpm
# does not); a directory shipped empty stays compared.

set -euo pipefail

cd "$(dirname "$0")/.."

NFPM_DIR=packaging/nfpm
SPEC=packaging/rpm/lota.spec
VERSION_FILE=VERSION
MAKEFILE=Makefile

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
		/^%(package|description|prep|build|install|check|post|preun|postun|changelog)/ {
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

# Paths the install target writes only under an `-f` guard, one per line as
# `<build artifact>\t<installed path>`, with Makefile variables expanded
# (DESTDIR empty)
guarded_installs() {
    awk '
		function expand(s,   rounds, name, val) {
			for (rounds = 0; rounds < 8; rounds++) {
				if (!match(s, /\$\([A-Za-z_][A-Za-z0-9_]*\)/))
					break
				name = substr(s, RSTART + 2, RLENGTH - 3)
				val = (name in var) ? var[name] : ""
				s = substr(s, 1, RSTART - 1) val \
				    substr(s, RSTART + RLENGTH)
			}
			return s
		}

		# first pass: the variable assignments, recipe lines excluded
		NR == FNR {
			if ($0 ~ /^[A-Za-z_][A-Za-z0-9_]*[ \t]*[:?]?=/) {
				name = $0
				sub(/[ \t]*[:?]?=.*$/, "", name)
				value = $0
				sub(/^[^=]*=[ \t]*/, "", value)
				if (!(name in var))
					var[name] = value
			}
			next
		}

		# second pass: join the continuation lines the guard is written across
		{
			line = joined $0
			if (line ~ /\\$/) {
				sub(/[ \t]*\\$/, " ", line)
				joined = line
				next
			}
			joined = ""
		}

		line ~ /^install:/ { in_install = 1; next }
		!in_install { next }
		line !~ /^[ \t]/ { in_install = 0; next }

		{
			n = split(line, stmt, /;/)
			for (i = 1; i <= n; i++) {
				if (match(stmt[i], /-f[ \t]+[^ \t\]]+/)) {
					guard = substr(stmt[i], RSTART + 2,
						       RLENGTH - 2)
					sub(/^[ \t]+/, "", guard)
				}
				if (guard != "" && stmt[i] ~ /install[ \t]+-m/) {
					m = split(stmt[i], word, /[ \t]+/)
					dest = expand(word[m])
					if (dest ~ /\/$/) {
						name = expand(guard)
						sub(/.*\//, "", name)
						dest = dest name
					}
					print guard "\t" dest
				}
				if (stmt[i] ~ /(^|[ \t])fi([ \t]|$)/)
					guard = ""
			}
		}
	' "$MAKEFILE" "$MAKEFILE" | sort -u
}

# Make targets the spec's %build runs, one per line (VAR=value excluded)
spec_build_targets() {
    awk '
		/^%build/ { in_build = 1; next }
		/^%(package|description|prep|install|check|files|post|preun|postun|changelog)/ {
			in_build = 0
			next
		}
		!in_build { next }
		/^%make_build[ \t]/ || /^[ \t]*make[ \t]/ {
			sub(/^%make_build[ \t]+/, "")
			sub(/^[ \t]*make[ \t]+/, "")
			for (i = 1; i <= NF; i++)
				if ($i !~ /=/ && $i !~ /^-/)
					print $i
		}
	' "$SPEC" | sort -u
}

# Whether a recipe of a target the spec builds names this artifact
build_produces() {
    local artifact=$1 target

    while read -r target; do
        [ -n "$target" ] || continue
        awk -v t="$target" '
			$0 ~ "^" t ":" { in_recipe = 1; next }
			in_recipe && /^[ \t]/ { print; next }
			in_recipe && !/^$/ { exit }
		' "$MAKEFILE" | grep -qF -- "$artifact" && return 0
    done < <(spec_build_targets)

    return 1
}

# a literal version here is the drift the placeholders exist to prevent
spec_version=$(awk '$1 == "Version:" { print $2; exit }' "$SPEC")
if [ "$spec_version" != "@VERSION@" ]; then
    fail=1
    echo "FAIL: ${SPEC} says Version: ${spec_version}, not @VERSION@"
    echo "  \`make srpm\` takes the version from ${VERSION_FILE}"
fi

changelog_head=$(awk '
	/^%changelog/ { in_log = 1; next }
	in_log { print; exit }
' "$SPEC")
if [ "$changelog_head" != "@CHANGELOG@" ]; then
    fail=1
    echo "FAIL: the %changelog in ${SPEC} does not open with @CHANGELOG@"
    echo "  \`make srpm\` writes the entry for ${VERSION_FILE} there"
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

# Directories the packages own: nfpm `type: dir` entries and spec %dir lines
owned_dirs() {
    local cfg section

    for cfg in "$NFPM_DIR"/*.yaml; do
        awk '
			/^[ \t]*-?[ \t]*dst:[ \t]*/ {
				sub(/^[^:]*:[ \t]*/, "")
				gsub(/^["'"'"']|["'"'"']$/, "")
				dst = $0
				next
			}
			/^[ \t]*type:[ \t]*dir[ \t]*$/ { if (dst != "") print dst }
		' "$cfg"
    done

    while read -r section; do
        [ -n "$section" ] || continue
        awk '
			/^%files/ { next }
			/^[ \t]*%dir[ \t]/ {
				line = $0
				while (line ~ /^[ \t]*%(dir|attr|ghost|config|verify)(\([^)]*\))?[ \t]+/)
					sub(/^[ \t]*%(dir|attr|ghost|config|verify)(\([^)]*\))?[ \t]+/, "", line)
				gsub(/%\{_sharedstatedir\}/, "/var/lib", line)
				gsub(/%\{_datadir\}/, "/usr/share", line)
				gsub(/%\{_sysconfdir\}/, "/etc", line)
				gsub(/%\{_prefix\}/, "/usr", line)
				gsub(/%\{_libdir\}/, "/usr/lib64", line)
				gsub(/%\{_includedir\}/, "/usr/include", line)
				gsub(/%\{name\}/, "lota", line)
				print line
			}
		' "$SPEC"
        break
    done < <(awk '/^%files[ \t]+/ { print }' "$SPEC")
}

check_declared_parents() {
    local dirs path parent
    dirs=$(owned_dirs | sort -u)

    while read -r path; do
        [ -n "$path" ] || continue
        parent=${path%/*}

        # /usr, /var/lib and the like belong to the distribution
        case "$parent" in
        /var/lib/lota* | /etc/lota* | /usr/lib/lota* | /usr/share/lota*) ;;
        *) continue ;;
        esac

        grep -qxF "$parent" <<<"$dirs" && continue

        fail=1
        echo "FAIL: ${path} is shipped and its parent ${parent} is owned by no package"
        echo "  an unowned directory is created at whatever mode the umask gives it,"
        echo "  is not verified by rpm -V, and is neither restored nor removed"
    done < <({
        for cfg in "$NFPM_DIR"/*.yaml; do nfpm_paths "$cfg"; done
        echo "$dirs"
    } | sort -u)
}

check_declared_parents

# Every path the spec ships, across its subpackages
spec_installed=$(while read -r section; do
    [ -n "$section" ] || continue
    spec_paths "$section" "lota-${section}"
done < <(awk '/^%files[ \t]+/ { sub(/^%files[ \t]+/, ""); print }' "$SPEC"))

# the other direction: subpackage the spec builds and nfpm does not
while read -r section; do
    [ -n "$section" ] || continue
    if [ ! -f "${NFPM_DIR}/lota-${section}.yaml" ]; then
        echo "FAIL: '%files ${section}' in ${SPEC} has no ${NFPM_DIR}/lota-${section}.yaml"
        fail=1
    fi
done < <(awk '/^%files[ \t]+/ { sub(/^%files[ \t]+/, ""); print }' "$SPEC")

# a guarded install the spec claims must be produced by its %build
while IFS=$'\t' read -r artifact path; do
    [ -n "$path" ] || continue
    grep -qxF "$path" <<<"$spec_installed" || continue
    build_produces "$artifact" && continue

    fail=1
    echo "FAIL: ${SPEC} claims ${path}, which nothing in its %build produces"
    echo "  \`make install\` writes it only when ${artifact} exists, so the"
    echo "  build ends in 'File not found' after compiling the whole tree"
done < <(guarded_installs)

if [ "$fail" -ne 0 ]; then
    echo
    echo "The two manifests must list the same installed paths per package,"
    echo "the spec must take its version from ${VERSION_FILE}, and it must"
    echo "produce every file it claims."
    exit 1
fi

echo "check-package-manifests: clean"
