# SPDX-License-Identifier: MIT
# RPM spec for the LOTA packages, built from source for COPR / rpmbuild.
#
# This spec builds in a clean chroot, so rpmbuild generates the soname
# dependencies automatically and produces the four subpackages from one
# source RPM.
#
# Go services are not vendored, so the COPR project must have external
# network enabled for the module fetch (or vendor the dependencies).
#
# Keep Version in sync with the top-level VERSION file
# Example: 0.4.0-rc2 -> 0.4.0~rc2

# No debuginfo subpackage:
# rpm's debuginfo extraction strips the binaries, but the agent binary is
# fsverity-measured and its hash is pinned, so it must ship exactly as built.
# Disabling debug_package also keeps the Go binaries intact.
%global debug_package %{nil}

Name:           lota
Version:        0.4.0~rc2
Release:        1%{?dist}
Summary:        Measured-boot TPM attestation with BPF LSM runtime integrity

# Userspace is MIT
# Agent's bundled BPF LSM object is GPL-2.0-only
License:        MIT AND GPL-2.0-only
URL:            https://github.com/szymonwilczek/lota
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  make
BuildRequires:  golang
BuildRequires:  pkgconfig
BuildRequires:  libbpf-devel
BuildRequires:  bpftool
BuildRequires:  openssl-devel
BuildRequires:  tpm2-tss-devel
BuildRequires:  libseccomp-devel
BuildRequires:  systemd-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  dbus-devel
BuildRequires:  SDL2-devel
BuildRequires:  libcurl-devel
BuildRequires:  elfutils-libelf-devel
BuildRequires:  zlib-devel
BuildRequires:  selinux-policy-devel

%description
LOTA is a measured-boot remote-attestation framework with a BPF LSM
runtime-integrity enforcer. This source package builds the host agent, the
verifier and attestation CA services and the integrator SDK.

%package agent
Summary:        LOTA host attestation agent
License:        MIT AND GPL-2.0-only
Requires:       dracut
%{?systemd_requires}

%description agent
Measured-boot TPM attestation client with a BPF LSM runtime-integrity
enforcer. Fails closed until host bring-up (lota-install) signs the BPF
object, installs the 90lota initramfs module and arms the PCR14 commitment.
The BPF object ships unsigned: each adopter signs it with their own key.

%package verifier
Summary:        LOTA remote attestation verifier
License:        MIT

%description verifier
Relying-party service that verifies TPM attestation reports against a signed
PCR policy and issues short-lived session tokens. Backs onto SQLite or a
shared Postgres for the HA topology.

%package attest-ca
Summary:        LOTA attestation CA enrollment service
License:        MIT

%description attest-ca
Self-hosted enrollment service that proves an AIK lives in a genuine TPM
through credential activation and issues short-lived AIK certificates that
the fleet verifier trusts.

%package sdk-devel
Summary:        LOTA SDK headers and shared libraries
License:        MIT

%description sdk-devel
Headers and shared libraries for the gaming, anti-cheat and server SDKs,
with the Proton/Steam integration helpers. MIT, so a studio or vendor can
build a proprietary product on top.

%prep
%autosetup -n %{name}-%{version}

%build
# go.work puts the build in workspace mode, where modules resolve read-only
# from the proxy; COPR project must have external network enabled.
%make_build all
# Compiled SELinux policy module (needs selinux-policy-devel).
# lota-install's SELinux stage loads it from %{_datadir}/lota/selinux,
# so the agent RPM ships it.
%make_build selinux-pp

%install
%make_install
# make install does not place the SELinux module;
# install it where lota-install expects it (GPL-2.0-only, like the BPF object)
install -Dpm 0644 selinux/lota.pp %{buildroot}%{_datadir}/lota/selinux/lota.pp

%post agent
# lota-agent.socket sets SocketGroup=lota on the IPC socket, which resolves only
# once that group exists.
# Package ships the fragment; applying it is what creates the group
systemd-sysusers %{_sysusersdir}/lota-agent.conf >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :
cat <<'EOF'
lota-agent installed. The agent fails closed until host bring-up completes.
Run `lota-install` to sign the BPF object, install the 90lota initramfs
module and arm the PCR14 boot commitment. The agent is not started here.
EOF

%preun agent
%systemd_preun lota-agent.service lota-agent.socket lota-attest.service

%postun agent
%systemd_postun lota-agent.service lota-agent.socket lota-attest.service

%files agent
%license LICENSE LICENSE.GPL-2.0-only
%{_bindir}/lota-agent
%{_bindir}/lota-install
%dir %{_prefix}/lib/lota
%{_prefix}/lib/lota/lota-pcr14-lock
%{_prefix}/lib/lota/lota_lsm.bpf.o
%dir %{_prefix}/lib/dracut/modules.d/90lota
%{_prefix}/lib/dracut/modules.d/90lota/module-setup.sh
%{_prefix}/lib/dracut/modules.d/90lota/lota-pcr14-lock.service
%{_sysusersdir}/lota-agent.conf
%{_unitdir}/lota-agent.service
%{_unitdir}/lota-agent.socket
%{_unitdir}/lota-attest.service
%{_presetdir}/85-lota.preset
%{_prefix}/lib/udev/rules.d/99-lota-tpm.rules
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.lota.Agent1.conf
%dir %{_datadir}/lota
%{_datadir}/lota/VERSION
%dir %{_datadir}/lota/ima
%{_datadir}/lota/ima/lota-ima-policy
%dir %{_datadir}/lota/selinux
%{_datadir}/lota/selinux/lota.pp
%dir %{_datadir}/lota/systemd
%{_datadir}/lota/systemd/10-xdg-runtime.conf.example
%dir %attr(0700,root,root) %{_sharedstatedir}/lota/aiks

%files verifier
%license LICENSE
%{_bindir}/lota-verifier

%files attest-ca
%license LICENSE
%{_bindir}/lota-attest-ca

%files sdk-devel
%license LICENSE
%{_bindir}/lota-proton-hook
%{_bindir}/lota-steam-setup
%dir %{_includedir}/lota
%{_includedir}/lota/lota_gaming.h
%{_includedir}/lota/lota_wine_hook.h
%{_includedir}/lota/lota_server.h
%{_includedir}/lota/lota_ipc.h
%{_includedir}/lota/lota_anticheat.h
%{_libdir}/liblotagaming.so
%{_libdir}/liblotaserver.so
%{_libdir}/liblota_wine_hook.so
%{_libdir}/liblota_anticheat.so

%changelog
* Sun Jun 21 2026 Szymon Wilczek <swilczek.lx@gmail.com> - 0.4.0~rc2-1
- Initial COPR packaging: agent, verifier, attest-CA and SDK subpackages.
