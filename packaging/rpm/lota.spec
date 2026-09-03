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
# Version and the newest %changelog entry are filled in by `make srpm` from the
# top-level VERSION file (0.9.0-rc1 -> 0.9.0~rc1), so a version bump touches
# VERSION alone; build through `make srpm`, not rpmbuild on this file.

# No debuginfo subpackage:
# rpm's debuginfo extraction strips the binaries, but the agent binary is
# fsverity-measured and its hash is pinned, so it must ship exactly as built.
# Disabling debug_package also keeps the Go binaries intact.
%global debug_package %{nil}

Name:           lota
Version:        @VERSION@
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
PCR policy and answers with a verdict and its validity deadline. Backs onto
SQLite or a shared Postgres for the HA topology.

%package attest-ca
Summary:        LOTA attestation CA enrollment service
License:        MIT

%description attest-ca
Self-hosted enrollment service that proves an AIK lives in a genuine TPM
through credential activation and issues short-lived AIK certificates that
the fleet verifier trusts.

%package sdk
Summary:        LOTA SDK runtime libraries
License:        MIT

%description sdk
Versioned shared libraries for the gaming, anti-cheat and server SDKs and the
Proton/Steam hook. Install lota-sdk-devel to build against them.

%package sdk-devel
Summary:        LOTA SDK headers and shared libraries
License:        MIT
Requires:       %{name}-sdk%{?_isa} = %{version}-%{release}
Requires:       pkgconfig(libcrypto)

%description sdk-devel
Headers and shared libraries for the gaming, anti-cheat and server SDKs,
with the Proton/Steam integration helpers. MIT, so a studio or vendor can
build a proprietary product on top.

%prep
%autosetup -n %{name}-%{version}

%build
# Whoever builds the package signs the enforcement object; the agent will not
# load it unsigned. Refuse before compiling, as `make packages` does.
if [ -z "%{?lota_signing_key}" ]; then
	cat >&2 <<'LOTA_EOF'
The enforcement object must be signed by whoever builds this package.
Rebuild with the release key:

    rpmbuild --rebuild --define "lota_signing_key /path/to/enforcement.key"

The public half is read from the same path with a .pub suffix, which is where
`lota-agent --gen-signing-key` writes it; point at it directly with
--define "lota_signing_pubkey /path/to/enforcement.pub".
LOTA_EOF
	exit 1
fi

# go.work puts the build in workspace mode, where modules resolve read-only
# from the proxy; COPR project must have external network enabled.
%make_build all
# Compiled SELinux policy module (needs selinux-policy-devel).
# lota-install's SELinux stage loads it from %{_datadir}/lota/selinux,
# so the agent RPM ships it.
%make_build selinux-pp
# the .sig and enforcement.pub %files claims
%make_build sign-bpf SIGNING_KEY=%{lota_signing_key} %{?lota_signing_pubkey:SIGNING_PUBKEY=%{lota_signing_pubkey}}

%install
%make_install
# make install does not place the SELinux module;
# install it where lota-install expects it (GPL-2.0-only, like the BPF object)
install -Dpm 0644 selinux/lota.pp %{buildroot}%{_datadir}/lota/selinux/lota.pp
# The documented interfaces are callable only from a file the SELinux devel
# Makefile can see; ship the source so a caller has something to copy.
install -Dpm 0644 selinux/lota.if %{buildroot}%{_datadir}/lota/selinux/lota.if

%check
# rpm's strip BRPs rewrite ELF files after %install. The packaged object must
# still match its signature and the agent binary its pinned fs-verity hash.
build/lota-agent --verify-policy \
	%{buildroot}%{_prefix}/lib/lota/lota_lsm.bpf.o \
	--policy-pubkey %{buildroot}%{_prefix}/lib/lota/enforcement.pub

built=$(sha256sum <build/lota-agent)
packaged=$(sha256sum <%{buildroot}%{_bindir}/lota-agent)
if [ "$built" != "$packaged" ]; then
	echo "the packaged lota-agent is not the binary that was built" >&2
	echo "  built:    $built" >&2
	echo "  packaged: $packaged" >&2
	exit 1
fi

%post agent
# lota-agent.socket sets SocketGroup=lota on the IPC socket, which resolves only
# once that group exists.
# Package ships the fragment; applying it is what creates the group
systemd-sysusers %{_sysusersdir}/lota-agent.conf >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :

# Relabel on every transaction, not only the first: restorecon is a no-op
# until lota-install loads the module, and new files inherit the directory's
# type.
if [ -d %{_sysconfdir}/lota ]; then
	restorecon -R %{_sysconfdir}/lota >/dev/null 2>&1 || :
fi
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
%{_prefix}/lib/lota/lota_lsm.bpf.o.sig
%{_prefix}/lib/lota/enforcement.pub
%dir %{_prefix}/lib/dracut/modules.d/90lota
%{_prefix}/lib/dracut/modules.d/90lota/module-setup.sh
%{_prefix}/lib/dracut/modules.d/90lota/lota-pcr14-lock.service
%{_sysusersdir}/lota-agent.conf
%{_unitdir}/lota-agent.service
%{_unitdir}/lota-agent.socket
%{_unitdir}/lota-attest.service
%{_prefix}/lib/udev/rules.d/99-lota-tpm.rules
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.lota.Agent1.conf
%dir %{_datadir}/lota
%{_datadir}/lota/VERSION
%dir %{_datadir}/lota/ima
%{_datadir}/lota/ima/lota-ima-policy
%dir %{_datadir}/lota/selinux
%{_datadir}/lota/selinux/lota.pp
%{_datadir}/lota/selinux/lota.if
%dir %{_datadir}/lota/systemd
%{_datadir}/lota/systemd/10-xdg-runtime.conf.example
%dir %attr(0700,root,root) %{_sharedstatedir}/lota/aiks
%dir %attr(0700,root,root) %{_sharedstatedir}/lota/profiles

%files verifier
%license LICENSE
%{_bindir}/lota-verifier

%files attest-ca
%license LICENSE
%{_bindir}/lota-attest-ca

%files sdk
%license LICENSE
%{_libdir}/liblotagaming.so.*
%{_libdir}/liblotaserver.so.*
%{_libdir}/liblota_wine_hook.so.*
%{_libdir}/liblota_anticheat.so.*

%files sdk-devel
%license LICENSE
%{_bindir}/lota-proton-hook
%{_bindir}/lota-steam-setup
%dir %{_includedir}/lota
%{_includedir}/lota/lota_gaming.h
%{_includedir}/lota/lota_wine_hook.h
%{_includedir}/lota/lota_server.h
%{_includedir}/lota/lota_anticheat.h
%{_includedir}/lota/lota_token.h
%{_includedir}/lota/lota_snapshot.h
%{_libdir}/liblotagaming.so
%{_libdir}/liblotaserver.so
%{_libdir}/liblota_wine_hook.so
%{_libdir}/liblota_anticheat.so
%{_libdir}/pkgconfig/lota-gaming.pc
%{_libdir}/pkgconfig/lota-server.pc
%{_libdir}/pkgconfig/lota-anticheat.pc
%{_libdir}/pkgconfig/lota-wine-hook.pc

%changelog
@CHANGELOG@
* Wed Oct 14 2026 Szymon Wilczek <swilczek.lx@gmail.com> - 0.8.0-1
- ci: drop the emulated arm64 cross-build (#174)
- build: make the sparse check required (#175)
- agent: take the configuration off the stack (#176)
- build: bring every stack frame under 32 KB (#177)
- build: make the smatch check required (#178)
- tests: stop the seccomp kill cases from dumping core (#179)
- build: fail the checkers when they die instead of reporting no findings
  (#180)
- ci: build the release notes from the tagged commit (#181)
- build: exempt the version bump from the Problem/Solution contract (#182)
- agent/attestca: enrol a TPM whose EK chain lives on the chip (#183)
- verifier: replay the event log the way the TPM extended it (#184)
- agent: say where an attestation round failed (#185)
- installer: require the agent's units to be enabled, not only running
  (#186)
- agent: measure a protected process's image on every filesystem (#187)
- agent: keep the PCR 14 boot commitment across a TPM restart (#190)
- agent: make a running agent stoppable, and say what stopping it costs
  (#191)
- agent: give a Proton title the socket it is supposed to connect to (#192)
- agent: commit PCR 14 to the agent binary, not to the TPM's clock (#193)
- agent: give each publisher an attestation key that is actually its own
  (#194)
- agent: answer the publisher who has no verifier, and stop one title
  deciding for all (#195)
- agent: attribute PCR 14 from the clock every reader shares (#196)
- agent: let --add-publisher write the publisher who runs no verifier (#197)
- agent: name the two verdicts an administrator causes on purpose (#198)
- agent: re-read the publisher list when the attest loop is told to (#199)
- sdk: say why an anti-cheat session could not start or beat (#200)
- installer: put the PCR 14 lock in every kernel's initramfs, not one (#201)
- examples: issue the CA example's listener certificate from its own anchor
  (#202)
- tools: resolve an EK root through the certificates the chip carries (#203)
- sdk: classify a runtime image mismatch as one in the Go SDK too (#204)
- agent: keep a title's publisher when the list is reloaded under it (#205)
- verifier: say when a re-pin was refused by the interval, not the
  allow-list (#206)
- agent: keep the enforcement state the command line asked for across a
  reload (#207)
- agent: keep the enforcement switches the command line turned on (#208)
- agent: key trusted libraries on the device the kernel reads (#209)
- bpf: refuse a shadowing mount on the new mount API too (#210)
- bpf: stop arming the directories above a trusted library (#211)
- agent: say nothing about a key that has not been created (#212)
- verifier: keep the kernel hash the quote already carries (#213)
- verifier: record the kernel this host booted, not the boot it made (#214)
- agent: report a TPM failure as the failure it was (#215)
- agent: resolve the endorsement key the way enrolment already does (#216)
- agent: say when a new key leaves a certificate naming the old one (#217)
- verifier: give a certificate that names another key its own verdict (#218)
- docs: quote the diagnostics the machine prints, and gate the quotes (#220)
- docs: put the hardware TPM facts on the platform-support page (#221)
- installer: let a host that answers to publishers pass its self-check
  (#222)
- docs: stop every unit that runs an agent before wiping its state (#223)
- docs: say what the bring-up commands print when they succeed (#224)
- agent: let a TPM probe report without provisioning a key (#225)
- bpf: read the fs-verity digest the way the kernel writes it (#226)
- bpf: let the global ptrace block cover attach only (#227)
- agent: refuse a mis-signed enforcement object before the boot commitment
  (#228)
- agent: refuse a publisher whose key its certificate does not name (#229)
- agent: seal to the platform, not to the agent binary (#230)
- agent: seal and rotate every key the host attests with (#231)
- agent: report how the AIK authorization is kept, instead of asserting it
  (#232)
- agent: name the TPM error instead of numbering it (#233)
- fleet: attribute every change to a client's trust state (#234)
- bpf: refuse the compressed module the kernel actually sends (#235)
- agent: report a daemonised start's verdict to its launcher (#236)
- verifier: withdraw the session token nothing could present (#237)
- config: refuse a publisher label that forges a configuration section
  (#238)
- bpf: deliver signals to the agent outside enforce mode (#239)
- attestca: refuse a partly-specified HSM key configuration (#240)
- attestca: answer a refused device with the decision that refused it (#241)
- agent: explain every enrollment refusal instead of printing its number
  (#242)
- verifier: name every stale PCR in one failure (#243)
- agent: pin each publisher's verifier with that publisher's own
  fingerprint (#244)
- agent: enforce the AIK TTL floor where the value is settled (#245)
- agent: attribute an exported digest to the register it came from (#246)
- agent: refuse GET_TOKEN by name when the agent has no TPM (#247)
- installer: refuse a named file that cannot be read before any stage runs
  (#248)
- agent: claim the socket before --test-signed spends a persistent key
  (#249)
- agent: refuse a --protect-pid that names no process before PCR 14 is
  spent (#250)
- agent: refuse a container listener path another agent is serving (#251)
- scripts: install the XDG drop-in without stopping the agent (#252)
- sdk: give the hook a token directory the player owns (#253)
- attestca: pin EK path material without making it an anchor (#254)
- agent: make push notification work on both roads (#255)
- sdk: make an anti-cheat session trusted only when it is attested (#256)
- agent: read the IMA policy scope, not only the appraisal mode (#257)
- sdk: keep the anti-cheat error spaces apart (#258)
- sdk: make a verified heartbeat trusted only when it is attested (#259)
- agent: the module gate reads the verdict the hardening gate reached (#260)
- agent: a refusal only a reboot can clear leaves through the operator exit
  (#261)
- agent: refuse an enforcement object whose integrity map this build cannot
  read (#262)
- verifier: advertise the endpoints the API registers (#263)
- agent: let the runtime-directory listener follow the login too (#264)
- agent: make --test-tpm exit on what it found (#265)
- agent: bind the configured publishers in the diagnostic servers (#266)
- agent: answer the bus with the daemon's own status word (#267)
- agent: answer the bus version with the build the agent came from (#268)
- agent: refuse a runtime PID change by name where nothing is enforced
  (#269)
- bpf: report a mount refused for shadowing a trusted file (#270)
- build: make the C tree compile on every distribution it is packaged for
  (#271)

* Thu Aug 13 2026 Szymon Wilczek <swilczek.lx@gmail.com> - 0.7.0-1
- feat: make the measured-boot trust chain mandatory (#139)
- feat: let a policy-listed agent update move its pinned baseline (#140)
- bug: keep the agent runnable across a package upgrade (#142)
- feat: teach lota.conf a publisher profile list (#144)
- feat: keep enforcing when a publisher profile will not bind (#146)
- feat: one owner for the host IPC socket (#147)
- feat: let an installer register a publisher (#148)
- feat: tell the player how to turn Secure Boot on (#149)
- packaging: drive bring-up from the post-install hook (#150)
- feat: let a publisher verify tokens without running a verifier (#151)
- feat: lint every Go module, and export the v1 protect-digest fold (#153)
- feat: enforce the MIT/GPL license boundary in CI (#154)
- bug: correct three live features documented as leftovers (#155)
- fix: drop the dead EK certificate field and require the ESRT section
  (#156)
- feat: freeze and gate the public API and ABI (#157)
- feat: ship pkg-config modules for the SDK (#158)
- fix: stop staging the ABI diff in a predictable temp file (#159)
- feat: add the enterprise CI/CD release-gate reference (#160)
- feat: make the anti-cheat material a reference a studio can fork (#161)
- fix: report one build identity from a single source (#162)
- feat: report that an agent update is waiting on a reboot (#163)
- fix: take the fs-verity digest the kernel actually reports (#164)
- fix: name the object that stopped a runtime measurement (#165)
- feat: report how much of a runtime the measurement covered (#166)
- feat: cache fs-verity digests by the inode they came from (#167)
- feat: enable fs-verity on the objects a title ships (#168)
- docs: state what runtime measurement can cover per platform (#169)
- fix: let the anti-cheat reference be measured, and its server demand it
  (#170)
- fix: report runtime coverage in the status word (#171)
- feat: end a protected process for its owner (#172)

* Tue Aug 04 2026 Szymon Wilczek <swilczek.lx@gmail.com> - 0.6.0-1
- fix: bound the attestation listener by default (#109)
- feat: add the lota-loadgen synthetic attestation fleet harness (#106)
- fix: unserialize the Postgres write path for fleet-scale attestation
  (#107)
- docs: publish the fleet-scale numbers and the operator sizing guide (#108)
- feat: batch attestation-log writes off the verification hot path (#110)
- feat: shard the Postgres write tier across N databases (#111)
- feat: make the Postgres connection pool tunable for enrollment bursts
  (#112)
- feat: platform support matrix (#116)
- fix: el-family bring-up fixes (seccomp, PCR14 handoff, lota group) (#117)
- fix: require the current enroll_state record (#124)
- fix: collapse the schema history into one consolidated migration (#126)
- fix: require explicit runtime_protect_version on the token wire (#128)
- fix: stop describing live features as backward compatibility (#130)
- feat: make the two manifests ship the same files, and gate it (#133)
- fix: say why a connection failed, and label the ports the policy gates on
  (#134)
- fix: drop protected PIDs whose process has exited (#135)
- fix: make runtime image measurement work on an enforcing host (#136)
- feat: let every storage backend verify AIK certificates (#137)

* Fri Jul 24 2026 Szymon Wilczek <swilczek.lx@gmail.com> - 0.5.0-1
- feat: package the agent, verifier, attest-CA and SDK as native RPMs (#84)
- build: version SDK shared libraries and split runtime from devel (#90)
- feat: package the verifier and attest-CA as distroless OCI images (#85)
- feat: add a Helm chart to deploy the verifier on Kubernetes (#86)
- feat: add an RPM spec and COPR entry point to build the packages from
  source (#87)
- feat: sign the RPMs and serve them from a signed dnf repository (#88)
- feat: build, sign and publish the packages from CI (#89)
- docs: mark the COPR repository as not yet published (#91)
- feat: publish the signed dnf repository under Pages /rpm (#92)
- github: add issue and pull request templates (#93)
- feat: add operator re-anchor and client removal to the verifier API (#96)
- fix: align the verifier's dead AIK-store surface with the Privacy CA
  model (#97)
- feat: multi-tenancy and tenant scoping (#98)
- feat: add the lota-fleet operator CLI for the monitoring API (#99)
- feat: make the fleet CLI tenant-aware (#100)
- docs: add the monitoring API endpoint reference (#101)
- feat: assign a tenant at enrollment from an EK manifest (#102)
- feat: assign tenants from per-tenant enrollment tokens (#103)
- feat: ship the verifier observability stack (#95)
- feat: verifier upgrade and migration story (#94)

* Tue Jun 30 2026 Szymon Wilczek <swilczek.lx@gmail.com> - 0.4.0-1
- feat: add BPF LSM decision-logic oracle sandbox (#72)
- feat: give the harnesses real oracles so they exercise trust logic (#73)
- fix: anchor the PCR14 boot commitment on the shim/MOK baseline (#74)
- feat: accept fs-verity or a signed IMA xattr for binary immutability (#75)
- feat: run continuous attestation as a fire-and-forget unit (#76)
- fix: omit drift-prone PCR 8/9/14 from the exported policy (#77)
- fix: report why enrollment failed instead of failing silently (#78)
- fix: relabel /var/lib/lota state in the installer SELinux stage (#79)
- fix: pass the CA cert to the installer attestation self-check (#80)
- fix: accept a valid sub-day AIK certificate in the installer (#81)
- fix: guide BPF re-signing after a package upgrade (#82)

* Sun Jun 21 2026 Szymon Wilczek <swilczek.lx@gmail.com> - 0.4.0~rc2-1
- Initial COPR packaging: agent, verifier, attest-CA and SDK subpackages.
