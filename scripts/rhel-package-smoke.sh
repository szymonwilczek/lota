#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Build LOTA RPMs on RHEL-family (Rocky 9 / el9) userspace and prove they install,
# their binaries execute against el9 glibc, and their units ship.
#
# Confirms the nfpm/dracut packaging is not Fedora-only and starts converting
# RHEL-family RPMs from experimental toward supported.
#
# Two entry modes, one code path for the build+install+smoke phases:
#   host      : spawn rockylinux:9 podman container and re-invoke self
#   container : run the phases directly (LOTA_SMOKE_IN_CONTAINER=1; used by
#               CI, which already runs the job inside the el9 container).
#               LOTA_SMOKE_SRC points at the checkout (default /src, the
#               podman mount; CI sets it to the workspace).
#
# What it deliberately does NOT do: boot-measured enroll+attest.
# Container has no boot, so no PCR14 commitment and no firmware event log.
set -eu

IMAGE="${LOTA_SMOKE_IMAGE:-quay.io/rockylinux/rockylinux:9}"
SRC="${LOTA_SMOKE_SRC:-/src}"

run_host() {
	command -v podman >/dev/null 2>&1 || {
		echo "error: podman not found; needed to spawn the $IMAGE smoke" >&2
		exit 1
	}
	repo_root=$(cd "$(dirname "$0")/.." && pwd)
	echo "== spawning $IMAGE (repo mounted read-only at /src) =="
	# label=disable:
	# :Z relabel trips on stray xattr files in the tree
	# repo is read-only
	exec podman run --rm \
		--security-opt label=disable \
		-v "$repo_root":/src:ro \
		-e LOTA_SMOKE_IN_CONTAINER=1 \
		"$IMAGE" \
		/bin/sh /src/scripts/rhel-package-smoke.sh
}

install_toolchain() {
	echo "== installing the el9 build toolchain =="
	# baseos + appstream + crb carry the whole toolchain;
	# no EPEL, so nothing outside the distribution enters a packaging build
	dnf -y install dnf-plugins-core
	dnf config-manager --set-enabled crb
	dnf -y install \
		git make gcc clang llvm bpftool pkgconf-pkg-config \
		libbpf-devel elfutils-libelf-devel zlib-devel tpm2-tss-devel \
		openssl-devel systemd-devel libseccomp-devel dbus-devel \
		golang selinux-policy-devel rpm-build
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
}

build_rpms() {
	# build off pristine archive of HEAD, not the read-only /src mount,
	# so tree carries no host build artefacts
	echo "== exporting a clean tree from HEAD =="
	git config --global --add safe.directory "$SRC"
	rm -rf /build && mkdir -p /build
	git -C "$SRC" archive HEAD | tar -x -C /build
	cd /build
	PATH="$(go env GOPATH)/bin:$PATH"
	export PATH
	echo "== make packages =="
	make packages
}

# fail if shipped file's digest differs from the package or file is missing;
# config file legitimately touched at install is ignored
verify_pkg() {
	pkg="$1"
	# rpm -V on an unknown package prints nothing and the check would pass
	# without inspecting anything, so a rename would slip through the smoke
	rpm -q "$pkg" >/dev/null 2>&1 || {
		echo "$pkg: not installed under that name" >&2
		return 1
	}
	rpm -V "$pkg" 2>/dev/null | awk -v p="$pkg" '
		$1 == "missing"          { bad = 1; print p ": missing " $2 }
		$1 ~ /5/ && $2 != "c"    { bad = 1; print p ": digest " $0 }
		END { if (bad) exit 1 }
	'
}

smoke() {
	pkgdir=/build/build/packages
	echo "== RPMs built =="
	ls -1 "$pkgdir"/*.rpm

	echo "== dnf install agent + verifier + attest-ca =="
	dnf -y install \
		"$pkgdir"/lota-agent-*.rpm \
		"$pkgdir"/lota-verifier-*.rpm \
		"$pkgdir"/lota-attest-ca-*.rpm

	echo "== binaries execute against el9 glibc =="
	lota-agent --help >/dev/null
	lota-verifier -h 2>&1 | grep -q require-cert
	lota-attest-ca -h 2>&1 | grep -q listen

	echo "== units and boot-path files ship =="
	for f in \
		/usr/lib/systemd/system/lota-agent.service \
		/usr/lib/systemd/system/lota-agent.socket \
		/usr/lib/lota/lota-pcr14-lock \
		/usr/lib/dracut/modules.d/90lota/module-setup.sh \
		/usr/lib/dracut/modules.d/90lota/lota-pcr14-lock.service; do
		test -e "$f" || {
			echo "error: missing $f" >&2
			return 1
		}
	done

	echo "== rpm -V is clean =="
	rc=0
	for p in lota-agent lota-verifier lota-attest-ca; do
		verify_pkg "$p" || rc=1
	done
	test "$rc" -eq 0 || {
		echo "error: rpm -V reported a packaging fault" >&2
		return 1
	}

	echo "== RHEL-family package smoke PASSED =="
}

main() {
	if [ "${LOTA_SMOKE_IN_CONTAINER:-0}" != "1" ]; then
		run_host
	fi
	install_toolchain
	build_rpms
	smoke
}

main "$@"
