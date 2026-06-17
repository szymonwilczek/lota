# SPDX-License-Identifier: MIT
#
# LOTA - Linux Open Trusted Attestation
# Master Makefile
#
# Targets:
#   help      - Show operator-facing target list
#   all       - Build agent, verifier, SDKs, initramfs helper and BPF program
#   test-unit - Build and run local unit tests
#   install   - Install to system
#
# Requirements:
#   - clang, llvm (for BPF compilation)
#   - gcc (for user-space)
#   - libbpf-devel
#   - tpm2-tss-devel
#   - openssl-devel (for SHA-256)
#

.DEFAULT_GOAL := help

# Compiler settings
CC ?= gcc
CLANG ?= clang
LLC ?= llc

# Build verbosity:
# `make V=1` prints full commands
# default prints a terse one-line summary per artifact
ifeq ($(V),1)
  Q =
  QUIET_CC =
  QUIET_CLANG =
  QUIET_LD =
  QUIET_AR =
  QUIET_GO =
  QUIET_GEN =
else
  Q = @
  # strip the build-directory prefix so the summary stays readable
  # and independent of overridden BUILD_DIR
  quiet_name = $(patsubst $(BUILD_DIR)/%,%,$@)
  QUIET_CC      = @echo "  CC      $(quiet_name)"
  QUIET_CLANG   = @echo "  CLANG   $(quiet_name)"
  QUIET_LD      = @echo "  LD      $(quiet_name)"
  QUIET_AR      = @echo "  AR      $(quiet_name)"
  QUIET_GO      = @echo "  GO      $(quiet_name)"
  QUIET_GEN     = @echo "  GEN     $(quiet_name)"
endif

# Directories
SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
AGENT_DIR := $(SRC_DIR)/agent
INC_DIR := include
BUILD_DIR := build
VERSION_FILE := VERSION
PROJECT_VERSION := $(strip $(shell sed -n '1p' $(VERSION_FILE) 2>/dev/null))
GOCACHE ?= $(abspath $(BUILD_DIR)/.gocache)

ifeq ($(PROJECT_VERSION),)
$(error VERSION file is missing or empty)
endif

# Output files
AGENT_BIN := $(BUILD_DIR)/lota-agent
INITRAMFS_LOCK_BIN := $(BUILD_DIR)/lota-pcr14-lock
INSTALLER_BIN := $(BUILD_DIR)/lota-install
VERIFIER_BIN := $(BUILD_DIR)/lota-verifier
ATTESTCA_BIN := $(BUILD_DIR)/lota-attest-ca
BPF_OBJ := $(BUILD_DIR)/lota_lsm.bpf.o
SDK_LIB := $(BUILD_DIR)/liblotagaming.so
SDK_STATIC := $(BUILD_DIR)/liblotagaming.a
SERVER_SDK_LIB := $(BUILD_DIR)/liblotaserver.so
SERVER_SDK_STATIC := $(BUILD_DIR)/liblotaserver.a

# Detect target architecture (overridable)
ifndef ARCH
	HOST_ARCH := $(shell $(CC) -dumpmachine | cut -d- -f1)
	ARCH := $(HOST_ARCH)
endif

# Compiler flags
CFLAGS := -Wall -Wextra -Werror -O2 -g
CFLAGS += -I$(INC_DIR)
CFLAGS += -D_GNU_SOURCE
CFLAGS += -fstack-protector-strong
CFLAGS += -fstack-clash-protection
# Control-flow integrity is architecture-specific: Intel CET
# (-fcf-protection) on x86_64, branch protection (BTI/PAC) on aarch64.
# -fcf-protection is an x86-only option and errors out on other targets.
ifeq ($(ARCH),x86_64)
CFLAGS += -fcf-protection=full
else ifeq ($(ARCH),aarch64)
CFLAGS += -mbranch-protection=standard
endif
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fPIE
CFLAGS += -Wformat -Wformat-security
CFLAGS += -Wshadow -Wpointer-arith -Wcast-align
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -Wundef -Wvla

# Reproducible builds
# Map the build root to a constant so the output depends only on the
# source.
# SOURCE_DATE_EPOCH (honored by the compiler for __DATE__/__TIME__)
# is pinned by `make reproducible-build` and the CI audit.
# Applied to the BPF object too.
REPRO_CFLAGS := -ffile-prefix-map=$(CURDIR)=.
CFLAGS += $(REPRO_CFLAGS)

# Optional sanitizer build for the host C side (agent, SDK, tests).
# Set SANITIZE=address,undefined to rebuild every host object under
# ASan/UBSan; CI uses this to surface memory and UB defects the normal
# hardened build cannot see. BPF objects use BPF_CFLAGS and stay
# untouched. -fno-sanitize-recover makes a finding abort the process so
# a CI run fails loudly instead of logging and continuing.
ifdef SANITIZE
CFLAGS += -fsanitize=$(SANITIZE) -fno-omit-frame-pointer
CFLAGS += -fno-sanitize-recover=all
endif

# Version string injected into the server-side SDK at build time.
LOTA_VERSION_STRING ?= $(PROJECT_VERSION)
SERVER_SDK_VERSION_CFLAGS := -DLOTA_SERVER_SDK_VERSION_STRING=\"$(LOTA_VERSION_STRING)\"

# Linker hardening
HARDENING_LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code

# Agent link flags
LDFLAGS := -pie $(HARDENING_LDFLAGS)
LDFLAGS += -lbpf -ltss2-esys -ltss2-mu -ltss2-tcti-device -ltss2-tctildr -lcrypto -lssl -lsystemd -lseccomp

ifdef SANITIZE
LDFLAGS += -fsanitize=$(SANITIZE)
endif

# BPF target architecture mapping
BPF_ARCH := $(ARCH)
ifeq ($(ARCH),x86_64)
	BPF_ARCH := x86
endif
ifeq ($(ARCH),aarch64)
	BPF_ARCH := arm64
endif

# BPF compilation flags
# -target bpf: Generate BPF bytecode
# -g: Include debug info
# -O2: Optimization level (for BPF verifier)
# -mcpu=v3: Enable the atomic xchg/cmpxchg instructions used by the
# allow-event budget counter.
BPF_CFLAGS := -target bpf -g -O2 -mcpu=v3
BPF_CFLAGS += -D__TARGET_ARCH_$(BPF_ARCH)
BPF_CFLAGS += -D__BPF_PROGRAM__
BPF_CFLAGS += -I$(INC_DIR)
BPF_CFLAGS += $(REPRO_CFLAGS)

# Agent test source files
AGTEST_SRCS = tests/test_main.c \
            tests/test_config.c \
            tests/test_policy.c \
            tests/test_tpm_aik.c \
            tests/test_server_sdk.c \
            tests/test_anticheat_compat.c \
            tests/test_loader_symbols.c \
              $(AGENT_DIR)/report.c \
              $(AGENT_DIR)/hash_verify.c \
              $(AGENT_DIR)/daemon.c \
              $(AGENT_DIR)/shutdown.c \
              $(AGENT_DIR)/policy.c \
              $(AGENT_DIR)/policy_sign.c \

# Agent main source files
AGENT_SRCS := $(AGENT_DIR)/main.c \
			  $(AGENT_DIR)/cli.c \
			  $(AGENT_DIR)/diagnostics.c \
			  $(AGENT_DIR)/daemon_loop.c \
			  $(AGENT_DIR)/daemon_loop_telemetry.c \
			  $(AGENT_DIR)/main_utils.c \
			  $(AGENT_DIR)/io_utils.c \
			  $(AGENT_DIR)/reload.c \
			  $(AGENT_DIR)/test_servers.c \
			  $(AGENT_DIR)/startup_policy.c \
              $(AGENT_DIR)/tpm.c \
              $(AGENT_DIR)/seal_envelope.c \
              $(AGENT_DIR)/iommu.c \
              $(AGENT_DIR)/bpf_loader.c \
              $(AGENT_DIR)/net.c \
              $(AGENT_DIR)/ipc.c \
              $(AGENT_DIR)/runtime_image_measure.c \
              $(AGENT_DIR)/report.c \
              $(AGENT_DIR)/esrt.c \
              $(AGENT_DIR)/hash_verify.c \
              $(AGENT_DIR)/daemon.c \
              $(AGENT_DIR)/shutdown.c \
              $(AGENT_DIR)/policy.c \
              $(AGENT_DIR)/policy_sign.c \
              $(AGENT_DIR)/config.c \
              $(AGENT_DIR)/steam_runtime.c \
              $(AGENT_DIR)/dbus.c \
              $(AGENT_DIR)/sdnotify.c \
              $(AGENT_DIR)/journal.c \
              $(AGENT_DIR)/selftest.c \
              $(AGENT_DIR)/event.c \
              $(AGENT_DIR)/hardening.c \
              $(AGENT_DIR)/enroll.c \
              $(AGENT_DIR)/enroll_client.c \
              $(AGENT_DIR)/enroll_state.c \
              $(AGENT_DIR)/aik_cert.c \
              $(AGENT_DIR)/attest.c

AGENT_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(AGENT_SRCS))

# SDK source files
SDK_DIR := $(SRC_DIR)/sdk
SDK_SRCS := $(SDK_DIR)/lota_gaming.c
SDK_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SDK_SRCS))

# Server SDK source files
SERVER_SDK_SRCS := $(SDK_DIR)/lota_server.c
SERVER_SDK_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SERVER_SDK_SRCS))

# Wine/Proton hook
WINE_HOOK_LIB := $(BUILD_DIR)/liblota_wine_hook.so
WINE_HOOK_SRCS := $(SDK_DIR)/lota_wine_hook.c
WINE_HOOK_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(WINE_HOOK_SRCS))

# Anti-cheat compatibility layer
ANTICHEAT_LIB := $(BUILD_DIR)/liblota_anticheat.so
ANTICHEAT_SRCS := $(SDK_DIR)/lota_anticheat.c
ANTICHEAT_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(ANTICHEAT_SRCS))

# Default target
.PHONY: all
all: $(AGENT_BIN) $(INITRAMFS_LOCK_BIN) $(INSTALLER_BIN) $(BPF_OBJ) $(VERIFIER_BIN) $(ATTESTCA_BIN) $(SDK_LIB) $(SERVER_SDK_LIB) $(WINE_HOOK_LIB) $(ANTICHEAT_LIB)

# build directories
$(BUILD_DIR):
	$(Q)mkdir -p $(BUILD_DIR)/agent

# build agent binary
$(AGENT_BIN): $(AGENT_OBJS) | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# build the initramfs PCR14 lock helper. The binary stays small and
# self-contained: it links only against TSS2-ESYS and OpenSSL so the
# 90lota dracut module can copy a minimal closure of shared objects
# into the initramfs image. PIE + the rest of the agent's hardening
# flags are inherited from CFLAGS so the helper is built with the
# same protections as the daemon.
$(INITRAMFS_LOCK_BIN): src/initramfs/lota-pcr14-lock.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -pie -Wl,-z,relro,-z,now \
		-ltss2-esys -ltss2-mu -ltss2-tcti-device -lcrypto

# build the guided player installer.
# Self-contained TUI binary that links only libcrypto
# (PCR14 lock-constant derivation + AIK certificate expiry)
# Every privileged action shells out to the same tooling the documentation names
# (dracut, grubby, systemctl, ...)
INSTALLER_SRCS := installer/main.c installer/stages.c installer/tui.c \
	installer/ui.c installer/run.c installer/probe.c
$(INSTALLER_BIN): $(INSTALLER_SRCS) installer/install.h installer/probe.h \
		installer/run.h installer/tui.h installer/ui.h | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_INSTALL_VERSION=\"$(LOTA_VERSION_STRING)\" \
		-o $@ $(INSTALLER_SRCS) -pie -Wl,-z,relro,-z,now -lcrypto

# auto-generated header dependencies. -MMD writes a sibling
# <object>.d listing every header the .c file pulled in;
# -MP adds phony targets for those headers so a deleted header
# does not break the next build. The .d files are included at the
# bottom of this Makefile so make rebuilds any .o whose headers
# changed.
DEPFLAGS = -MMD -MP -MF $(@:.o=.d)

# compile agent
$(BUILD_DIR)/agent/%.o: $(AGENT_DIR)/%.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

# compile SDK
$(BUILD_DIR)/sdk/%.o: $(SDK_DIR)/%.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -fPIC -c -o $@ $<

# server SDK version string (liblotaserver + dependents)
$(BUILD_DIR)/sdk/lota_server.o: CFLAGS += $(SERVER_SDK_VERSION_CFLAGS)
$(BUILD_DIR)/sdk/lota_server.o: $(VERSION_FILE)

# build SDK shared library
$(SDK_LIB): $(SDK_OBJS) | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $@) $(HARDENING_LDFLAGS) -o $@ $^

# build SDK static library
$(SDK_STATIC): $(SDK_OBJS) | $(BUILD_DIR)
	$(QUIET_AR)
	$(Q)$(AR) rcs $@ $^

# build server SDK shared library
$(SERVER_SDK_LIB): $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $@) $(HARDENING_LDFLAGS) -o $@ $^ -lcrypto

# build server SDK static library
$(SERVER_SDK_STATIC): $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(QUIET_AR)
	$(Q)$(AR) rcs $@ $^

# build Wine/Proton hook (self-contained: includes gaming SDK)
$(WINE_HOOK_LIB): $(WINE_HOOK_OBJS) $(SDK_OBJS) | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $@) $(HARDENING_LDFLAGS) -o $@ $^ -lpthread

# build anti-cheat compatibility layer (includes gaming + server SDK)
$(ANTICHEAT_LIB): $(ANTICHEAT_OBJS) $(SDK_OBJS) $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $@) $(HARDENING_LDFLAGS) -o $@ $^ -lcrypto

# build bpf program
$(BPF_OBJ): $(BPF_DIR)/lota_lsm.bpf.c $(INC_DIR)/vmlinux.h $(INC_DIR)/lota.h $(INC_DIR)/lota_devt.h | $(BUILD_DIR)
	$(QUIET_CLANG)
	$(Q)$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

# generate vmlinux.h from running kernel btf
$(INC_DIR)/vmlinux.h:
	$(QUIET_GEN)
	$(Q)bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Phony targets
.PHONY: help all bpf agent initramfs-lock installer verifier attest-ca sdk server-sdk wine-hook anticheat clean htmldocs docs-lint docs-linkcheck docs-serve cleandocs install check-version-tag check-includes lint lint-c lint-go reproducible-build test test-unit test-bins test-hardware test-sdk sanitizer-build valgrind-unit valgrind-smoke fuzz-agent fuzz-config fuzz-net-pin fuzz-net-wire fuzz-enroll fuzz-seal-envelope fuzz-tpm-attest fuzz-policy-sign fuzz-server-sdk fuzz-tpm-resp fuzz-all syzkaller-fuzz-loader examples examples-clean sign-bpf

bpf: $(BPF_OBJ)

agent: $(AGENT_BIN)

initramfs-lock: $(INITRAMFS_LOCK_BIN)

installer: $(INSTALLER_BIN)

verifier: $(VERIFIER_BIN)

attest-ca: $(ATTESTCA_BIN)

sdk: $(SDK_LIB) $(SDK_STATIC)

server-sdk: $(SERVER_SDK_LIB) $(SERVER_SDK_STATIC)

wine-hook: $(WINE_HOOK_LIB)

anticheat: $(ANTICHEAT_LIB)

# Examples (opt-in: end-to-end demo material under examples/).
#
# `make all` deliberately does NOT depend on this target so the agent
# build stays fast and the demo SDL2/libcurl/Go toolchains stay
# optional. Recurse into every per-component fragment that is in tree;
# each fragment writes its artifacts under build/examples/.
EXAMPLES_DIR := examples
EXAMPLES_BUILD_DIR := $(BUILD_DIR)/examples
EXAMPLES_FRAGMENTS := $(wildcard $(EXAMPLES_DIR)/*/Makefile.fragment)

$(EXAMPLES_BUILD_DIR): | $(BUILD_DIR)
	$(Q)mkdir -p $@

examples: $(EXAMPLES_BUILD_DIR)
	@for frag in $(EXAMPLES_FRAGMENTS); do \
		dir=$$(dirname $$frag); \
		echo "==> examples: $$dir"; \
		$(MAKE) -C $$dir -f Makefile.fragment \
			TOP_DIR=$(CURDIR) \
			BUILD_DIR=$(abspath $(EXAMPLES_BUILD_DIR)) \
			INC_DIR=$(CURDIR)/$(INC_DIR) \
			SDK_BUILD_DIR=$(abspath $(BUILD_DIR)) || exit $$?; \
	done
	@if command -v go >/dev/null 2>&1 && [ -f $(EXAMPLES_DIR)/demo_server/main.go ]; then \
		echo "==> examples: $(EXAMPLES_DIR)/demo_server"; \
		cd $(EXAMPLES_DIR)/demo_server && \
			go build -o $(abspath $(EXAMPLES_BUILD_DIR))/demo_server . ; \
	else \
		echo "SKIP: demo_server (go not installed or stub absent)"; \
	fi

examples-clean:
	rm -rf $(EXAMPLES_BUILD_DIR)
	@for frag in $(EXAMPLES_FRAGMENTS); do \
		dir=$$(dirname $$frag); \
		$(MAKE) -C $$dir -f Makefile.fragment clean \
			BUILD_DIR=$(abspath $(EXAMPLES_BUILD_DIR)) 2>/dev/null || true; \
	done

#
# Sign the in-tree BPF object with the deployed agent's signing key.
# Produces $(BPF_OBJ).sig next to the .o so bpf_loader's signature
# check accepts the load. SIGNING_KEY defaults to the operator key
# laid down by lota-dev-bringup.sh; override on the command line for
# CI / packaging.
#
# Prerequisites:
#   - $(BPF_OBJ) built (`make bpf` or `make all`).
#   - $(AGENT_BIN) built so `--sign-policy` is available.
#   - SIGNING_KEY points at a readable Ed25519 PEM private key, e.g.
#     the one generated by `lota-agent --gen-signing-key
#     /etc/lota/policy`.
#
# Usage:
#   sudo make sign-bpf SIGNING_KEY=/etc/lota/policy.key
#
SIGNING_KEY ?= /etc/lota/policy.key
sign-bpf: $(BPF_OBJ) $(AGENT_BIN)
	@test -r $(SIGNING_KEY) || { \
		echo "sign-bpf: signing key not readable: $(SIGNING_KEY)" >&2; \
		echo "Generate one with: sudo $(AGENT_BIN) --gen-signing-key /etc/lota/policy" >&2; \
		exit 1; \
	}
	$(AGENT_BIN) --sign-policy $(BPF_OBJ) --signing-key $(SIGNING_KEY)
	@test -r $(BPF_OBJ).sig
	@echo "Signed: $(BPF_OBJ).sig"

# Go verifier
$(VERIFIER_BIN): $(wildcard $(SRC_DIR)/verifier/*.go $(SRC_DIR)/verifier/**/*.go $(SRC_DIR)/crl/*.go) | $(BUILD_DIR)
	$(QUIET_GO)
	$(Q)cd $(SRC_DIR)/verifier && env GOCACHE=$(GOCACHE) go build -trimpath -o $(abspath $@) .

# Go attestation CA
# GO_TAGS optionally selects build tags, e.g. GO_TAGS=pkcs11 to compile the
# HSM-backed signing-key support (needs cgo and a PKCS#11 module at runtime).
GO_TAGS ?=
$(ATTESTCA_BIN): $(wildcard $(SRC_DIR)/attestca/*.go $(SRC_DIR)/attestca/**/*.go $(SRC_DIR)/crl/*.go) | $(BUILD_DIR)
	$(QUIET_GO)
	$(Q)cd $(SRC_DIR)/attestca && env GOCACHE=$(GOCACHE) go build -trimpath $(if $(GO_TAGS),-tags $(GO_TAGS),) -o $(abspath $@) .

# Canonical reproducible build
# This target pins the remaining environmental inputs the toolchain reads
# -- the build timestamp (SOURCE_DATE_EPOCH), the time zone and the local
#  -- so the artifacts depend only on the source tree.
# SOURCE_DATE_EPOCH defaults to the HEAD commit time, so a build from a
# given commit (or tag) is deterministic.
# Override REPRO_SOURCE_DATE_EPOCH for an out-of-tree source drop without
# git.
# See Documentation/security/reproducible-builds.rst for how to verify shipped == tag.
REPRO_SOURCE_DATE_EPOCH ?= $(shell git -C $(CURDIR) log -1 --pretty=%ct 2>/dev/null || echo 1700000000)
reproducible-build: export SOURCE_DATE_EPOCH = $(REPRO_SOURCE_DATE_EPOCH)
reproducible-build: export TZ = UTC
reproducible-build: export LC_ALL = C
reproducible-build: all
	@echo "Reproducible build complete (SOURCE_DATE_EPOCH=$(REPRO_SOURCE_DATE_EPOCH), TZ=UTC, LC_ALL=C)"

clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

# Documentation (Sphinx
# Config and sources live under Documentation/
# htmldocs builds strictly (-W)
# docs-lint runs the reStructuredText linter
htmldocs:
	$(MAKE) -C Documentation html
docs-lint:
	$(MAKE) -C Documentation lint
docs-linkcheck:
	$(MAKE) -C Documentation linkcheck
docs-serve:
	$(MAKE) -C Documentation serve
cleandocs:
	$(MAKE) -C Documentation clean

check-version-tag:
	@if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
		tag="$$(git describe --tags --exact-match 2>/dev/null || true)"; \
		if [ -n "$$tag" ]; then \
			version_tag="$${tag#v}"; \
			if [ "$$version_tag" != "$(PROJECT_VERSION)" ]; then \
				echo "ERROR: VERSION ($(PROJECT_VERSION)) does not match current git tag $$tag" >&2; \
				exit 1; \
			fi; \
		fi; \
	fi

# Include-hygiene gate
# Fails on any header pulled in but not used directly (transitive dependency).
# Drives clang-include-cleaner over a bear-built compile database.
# See scripts/check-includes.sh; auto-fix with scripts/fix-includes.sh
check-includes:
	@scripts/check-includes.sh

# Combined lint:
# clang-format style check on the C sources and headers plus golangci-lint
# on every Go module.
# Read-only -- it reports, it never rewrites.
# Use `clang-format -i` / `golangci-lint fmt` to apply fixes.
CLANG_FORMAT ?= $(shell command -v clang-format-22 2>/dev/null || \
	command -v clang-format 2>/dev/null)
GOLANGCI_LINT ?= golangci-lint
LINT_GO_MODULES := src/verifier src/attestca src/crl

lint: lint-c lint-go

lint-c:
	@test -n "$(CLANG_FORMAT)" || { \
		echo "lint-c: clang-format not found (install clang-tools / clang-format-22)" >&2; \
		exit 1; }
	@files=$$(git ls-files '*.c' '*.h' | grep -v '^include/vmlinux.h$$'); \
		$(CLANG_FORMAT) --dry-run --Werror $$files
	@echo "lint-c: clean"

lint-go:
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "lint-go: golangci-lint not found" >&2; exit 1; }
	@for m in $(LINT_GO_MODULES); do \
		echo "==> golangci-lint $$m"; \
		( cd $$m && $(GOLANGCI_LINT) run --config $(CURDIR)/.golangci.yml ./... ) \
			|| exit $$?; \
	done
	@echo "lint-go: clean"

# Install to system (requires root)
install: check-version-tag all
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib/lota
	install -d $(DESTDIR)/usr/lib/dracut/modules.d/90lota
	install -d $(DESTDIR)/usr/lib64
	install -d $(DESTDIR)/usr/include/lota
	install -d $(DESTDIR)/usr/share/lota
	install -d $(DESTDIR)/var/lib/lota/aiks
	install -m 755 $(AGENT_BIN) $(DESTDIR)/usr/bin/
	install -m 755 $(INSTALLER_BIN) $(DESTDIR)/usr/bin/
	install -m 755 $(INITRAMFS_LOCK_BIN) $(DESTDIR)/usr/lib/lota/
	install -m 755 $(VERIFIER_BIN) $(DESTDIR)/usr/bin/
	install -m 755 $(ATTESTCA_BIN) $(DESTDIR)/usr/bin/
	install -m 644 $(BPF_OBJ) $(DESTDIR)/usr/lib/lota/
	@# Install the detached BPF signature too when sign-bpf produced
	@# one. Agent's bpf_loader_load() reads <obj>.sig next to the .o,
	@# so the two files must land in the same directory. Production
	@# installs the .sig generated against the operator key; CI
	@# packaging that has not signed yet leaves the file absent so
	@# the agent will refuse to load until sign-bpf runs.
	@if [ -f $(BPF_OBJ).sig ]; then \
		install -m 644 $(BPF_OBJ).sig $(DESTDIR)/usr/lib/lota/; \
	fi
	install -m 644 $(VERSION_FILE) $(DESTDIR)/usr/share/lota/VERSION
	install -m 755 $(SDK_LIB) $(DESTDIR)/usr/lib64/
	install -m 755 $(SERVER_SDK_LIB) $(DESTDIR)/usr/lib64/
	install -m 755 $(WINE_HOOK_LIB) $(DESTDIR)/usr/lib64/
	install -m 755 $(ANTICHEAT_LIB) $(DESTDIR)/usr/lib64/
	install -m 755 scripts/lota-proton-hook $(DESTDIR)/usr/bin/
	install -m 755 scripts/lota-steam-setup $(DESTDIR)/usr/bin/
	install -m 755 scripts/lota-dev-bringup.sh $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/usr/share/lota/ima
	install -m 644 configs/ima/lota-ima-policy \
		$(DESTDIR)/usr/share/lota/ima/lota-ima-policy
	install -d $(DESTDIR)/etc/dbus-1/system.d
	install -m 644 dbus/org.lota.Agent1.conf $(DESTDIR)/etc/dbus-1/system.d/
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 644 systemd/lota-agent.service $(DESTDIR)/usr/lib/systemd/system/
	install -m 644 systemd/lota-agent.socket $(DESTDIR)/usr/lib/systemd/system/
	install -d $(DESTDIR)/usr/share/lota/systemd
	install -m 644 systemd/lota-agent.service.d/10-xdg-runtime.conf.example \
		$(DESTDIR)/usr/share/lota/systemd/
	install -d $(DESTDIR)/usr/lib/udev/rules.d
	install -m 644 configs/udev/99-lota-tpm.rules $(DESTDIR)/usr/lib/udev/rules.d/
	install -m 755 src/initramfs/90lota/module-setup.sh $(DESTDIR)/usr/lib/dracut/modules.d/90lota/
	install -m 644 src/initramfs/90lota/lota-pcr14-lock.service $(DESTDIR)/usr/lib/dracut/modules.d/90lota/
	install -m 644 $(INC_DIR)/lota_gaming.h $(DESTDIR)/usr/include/lota/
	install -m 644 $(INC_DIR)/lota_wine_hook.h $(DESTDIR)/usr/include/lota/
	install -m 644 $(INC_DIR)/lota_server.h $(DESTDIR)/usr/include/lota/
	install -m 644 $(INC_DIR)/lota_ipc.h $(DESTDIR)/usr/include/lota/
	install -m 644 $(INC_DIR)/lota_anticheat.h $(DESTDIR)/usr/include/lota/
	@echo "Installed to $(DESTDIR)/usr"

# Build test binaries
TEST_SDK_BIN := $(BUILD_DIR)/test_sdk_ipc
TEST_BIN_DIR := $(BUILD_DIR)

TEST_BINS := \
	$(TEST_BIN_DIR)/test_hash_verify \
	$(TEST_BIN_DIR)/test_dbus \
	$(TEST_BIN_DIR)/test_systemd \
	$(TEST_BIN_DIR)/test_packaging \
	$(TEST_BIN_DIR)/test_steam_runtime \
	$(TEST_BIN_DIR)/test_wine_hook \
	$(TEST_BIN_DIR)/test_daemon \
	$(TEST_BIN_DIR)/test_signal_shutdown \
	$(TEST_BIN_DIR)/test_daemon_loop \
	$(TEST_BIN_DIR)/test_tls_verify \
	$(TEST_BIN_DIR)/test_config \
	$(TEST_BIN_DIR)/test_subscribe \
	$(TEST_BIN_DIR)/test_policy_sign \
	$(TEST_BIN_DIR)/test_policy_export \
	$(TEST_BIN_DIR)/test_aik_rotation \
	$(TEST_BIN_DIR)/test_signed_clockinfo \
	$(TEST_BIN_DIR)/test_credential_activation \
	$(TEST_BIN_DIR)/test_enroll_wire \
	$(TEST_BIN_DIR)/test_enroll_state \
	$(TEST_BIN_DIR)/test_esrt \
	$(TEST_BIN_DIR)/test_aik_cert_renew \
	$(TEST_BIN_DIR)/test_io_read_file \
	$(TEST_BIN_DIR)/test_devt \
	$(TEST_BIN_DIR)/test_event_budget \
	$(TEST_BIN_DIR)/test_initramfs_lock \
	$(TEST_BIN_DIR)/test_hardening \
	$(TEST_BIN_DIR)/test_server_sdk \
	$(TEST_BIN_DIR)/demo_sdk \
	$(TEST_BIN_DIR)/test_ipc_client \
	$(TEST_BIN_DIR)/test_cross_lang_verify \
	$(TEST_BIN_DIR)/test_anticheat \
	$(TEST_BIN_DIR)/test_runtime_measure \
	$(TEST_BIN_DIR)/test_runtime_image_measure \
	$(TEST_BIN_DIR)/test_runtime_protect_digest \
	$(TEST_BIN_DIR)/test_runtime_image_collect \
	$(TEST_BIN_DIR)/test_runtime_measure_pid \
	$(TEST_BIN_DIR)/test_seal_blob \
	$(TEST_BIN_DIR)/test_seal_envelope \
	$(TEST_BIN_DIR)/test_seal_tpm \
	$(TEST_BIN_DIR)/test_seal_aik \
	$(TEST_BIN_DIR)/test_ipc_dos \
	$(TEST_BIN_DIR)/test_loader_symbols \
	$(TEST_BIN_DIR)/test_installer_probe \
	$(TEST_SDK_BIN)

$(TEST_SDK_BIN): tests/test_sdk_ipc.c $(SDK_LIB) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -llotagaming -Wl,-rpath,$(abspath $(BUILD_DIR))

$(TEST_BIN_DIR)/test_hash_verify: tests/test_hash_verify.c $(AGENT_DIR)/hash_verify.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_installer_probe: tests/test_installer_probe.c installer/probe.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_dbus: tests/test_dbus.c $(AGENT_DIR)/dbus.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lsystemd

$(TEST_BIN_DIR)/test_systemd: tests/test_systemd.c $(AGENT_DIR)/sdnotify.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lsystemd

$(TEST_BIN_DIR)/test_packaging: tests/test_packaging.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_steam_runtime: tests/test_steam_runtime.c $(AGENT_DIR)/steam_runtime.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lsystemd

$(TEST_BIN_DIR)/test_wine_hook: tests/test_wine_hook.c $(SDK_DIR)/lota_gaming.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_HOOK_TESTING -o $@ $^ -lpthread

$(TEST_BIN_DIR)/test_daemon: tests/test_daemon.c $(AGENT_DIR)/daemon.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_signal_shutdown: tests/test_signal_shutdown.c $(AGENT_DIR)/daemon.c $(AGENT_DIR)/shutdown.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -pthread

$(TEST_BIN_DIR)/test_daemon_loop: tests/test_daemon_loop.c $(AGENT_DIR)/daemon_loop_telemetry.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_tls_verify: tests/test_tls_verify.c $(AGENT_DIR)/net.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -lsystemd

$(TEST_BIN_DIR)/test_config: tests/test_config.c $(AGENT_DIR)/config.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_subscribe: tests/test_subscribe.c $(SDK_DIR)/lota_gaming.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_policy_sign: tests/test_policy_sign.c $(AGENT_DIR)/policy_sign.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_policy_export: tests/test_policy_export.c $(AGENT_DIR)/policy.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_aik_rotation: tests/test_aik_rotation.c $(AGENT_DIR)/tpm.c $(AGENT_DIR)/seal_envelope.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_INTERNAL_TESTS -o $@ $^ -ltss2-esys -ltss2-mu -ltss2-tcti-device -ltss2-tctildr -lcrypto -lssl

$(TEST_BIN_DIR)/test_credential_activation: tests/test_credential_activation.c $(AGENT_DIR)/tpm.c $(AGENT_DIR)/seal_envelope.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_INTERNAL_TESTS -o $@ $^ -ltss2-esys -ltss2-mu -ltss2-tcti-device -ltss2-tctildr -lcrypto -lssl

$(TEST_BIN_DIR)/test_signed_clockinfo: tests/test_signed_clockinfo.c $(AGENT_DIR)/tpm.c $(AGENT_DIR)/seal_envelope.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_INTERNAL_TESTS -o $@ $^ -ltss2-esys -ltss2-mu -ltss2-tcti-device -ltss2-tctildr -lcrypto -lssl

$(TEST_BIN_DIR)/test_enroll_wire: tests/test_enroll_wire.c $(AGENT_DIR)/enroll.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_enroll_state: tests/test_enroll_state.c $(AGENT_DIR)/enroll_state.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_esrt: tests/test_esrt.c $(AGENT_DIR)/esrt.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_aik_cert_renew: tests/test_aik_cert_renew.c $(AGENT_DIR)/aik_cert.c $(AGENT_DIR)/io_utils.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_io_read_file: tests/test_io_read_file.c $(AGENT_DIR)/io_utils.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_devt: tests/test_devt.c $(INC_DIR)/lota_devt.h | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $<

$(TEST_BIN_DIR)/test_event_budget: tests/test_event_budget.c $(INC_DIR)/lota_event_budget.h | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $<

$(TEST_BIN_DIR)/test_initramfs_lock: tests/test_initramfs_lock.c src/initramfs/lota-pcr14-lock.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_INITRAMFS_LOCK_NO_MAIN -o $@ $^ -ltss2-esys -ltss2-mu -ltss2-tcti-device -lcrypto

$(TEST_BIN_DIR)/test_hardening: tests/test_hardening.c $(AGENT_DIR)/hardening.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lseccomp -lsystemd -pthread

$(TEST_BIN_DIR)/test_server_sdk: tests/test_server_sdk.c $(SDK_DIR)/lota_server.c $(SDK_DIR)/lota_gaming.c $(VERSION_FILE) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) $(SERVER_SDK_VERSION_CFLAGS) -o $@ $(filter-out $(VERSION_FILE),$^) -lcrypto

$(TEST_BIN_DIR)/demo_sdk: tests/demo_sdk.c $(SDK_DIR)/lota_gaming.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_anticheat: tests/test_anticheat.c $(SDK_DIR)/lota_anticheat.c $(SDK_DIR)/lota_gaming.c $(SDK_DIR)/lota_server.c $(VERSION_FILE) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) $(SERVER_SDK_VERSION_CFLAGS) -o $@ $(filter-out $(VERSION_FILE),$^) -lcrypto

$(TEST_BIN_DIR)/test_runtime_measure: tests/test_runtime_measure.c $(SDK_DIR)/lota_anticheat.c $(SDK_DIR)/lota_gaming.c $(SDK_DIR)/lota_server.c $(VERSION_FILE) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) $(SERVER_SDK_VERSION_CFLAGS) -o $@ $(filter-out $(VERSION_FILE),$^) -lcrypto

$(TEST_BIN_DIR)/test_runtime_image_measure: tests/test_runtime_image_measure.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_runtime_protect_digest: tests/test_runtime_protect_digest.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_runtime_image_collect: tests/test_runtime_image_collect.c $(AGENT_DIR)/runtime_image_measure.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_runtime_measure_pid: tests/test_runtime_measure_pid.c $(AGENT_DIR)/runtime_image_measure.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_seal_blob: tests/test_seal_blob.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN_DIR)/test_seal_envelope: tests/test_seal_envelope.c $(AGENT_DIR)/seal_envelope.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_seal_tpm: tests/test_seal_tpm.c $(AGENT_DIR)/tpm.c $(AGENT_DIR)/seal_envelope.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_INTERNAL_TESTS -o $@ $^ -ltss2-esys -ltss2-mu -ltss2-tcti-device -ltss2-tctildr -lcrypto -lssl

$(TEST_BIN_DIR)/test_seal_aik: tests/test_seal_aik.c $(AGENT_DIR)/tpm.c $(AGENT_DIR)/seal_envelope.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_INTERNAL_TESTS -o $@ $^ -ltss2-esys -ltss2-mu -ltss2-tcti-device -ltss2-tctildr -lcrypto -lssl

$(TEST_BIN_DIR)/test_ipc_client: tests/test_ipc_client.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(TEST_BIN_DIR)/test_cross_lang_verify: tests/cross_lang/test_verify.c $(SERVER_SDK_LIB) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -llotaserver -Wl,-rpath,$(abspath $(BUILD_DIR)) -lcrypto

$(TEST_BIN_DIR)/test_ipc_dos: tests/test_ipc_dos.c $(SDK_LIB) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -llotagaming -Wl,-rpath,$(abspath $(BUILD_DIR))

$(TEST_BIN_DIR)/test_loader_symbols: tests/test_loader_symbols.c $(AGENT_DIR)/bpf_loader.c $(AGENT_DIR)/journal.c $(AGENT_DIR)/policy_sign.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lbpf -lsystemd -lcrypto

# Build the unit/integration test binaries without running them. Used by
# the include-hygiene gate so test sources are analyzed too.
test-bins: $(TEST_BINS)

# Full test suite (unit + integration + hardware)
# Note: hardware tests require root. Run 'sudo make test-hardware' for them.
test: test-unit

test-unit: all $(TEST_BINS)
	@echo "=== Running unit tests ==="
	@$(BUILD_DIR)/test_hash_verify
	@$(BUILD_DIR)/test_dbus
	@$(BUILD_DIR)/test_systemd
	@$(BUILD_DIR)/test_packaging
	@$(BUILD_DIR)/test_steam_runtime
	@$(BUILD_DIR)/test_wine_hook
	@$(BUILD_DIR)/test_daemon
	@$(BUILD_DIR)/test_signal_shutdown
	@$(BUILD_DIR)/test_daemon_loop
	@$(BUILD_DIR)/test_config
	@$(BUILD_DIR)/test_subscribe
	@$(BUILD_DIR)/test_policy_sign
	@$(BUILD_DIR)/test_policy_export
	@$(BUILD_DIR)/test_aik_rotation
	@$(BUILD_DIR)/test_signed_clockinfo
	@$(BUILD_DIR)/test_credential_activation
	@$(BUILD_DIR)/test_enroll_wire
	@$(BUILD_DIR)/test_enroll_state
	@$(BUILD_DIR)/test_io_read_file
	@$(BUILD_DIR)/test_devt
	@$(BUILD_DIR)/test_event_budget
	@$(BUILD_DIR)/test_initramfs_lock
	@$(BUILD_DIR)/test_installer_probe
	@$(BUILD_DIR)/test_hardening
	@$(BUILD_DIR)/test_server_sdk
	@$(BUILD_DIR)/test_anticheat
	@$(BUILD_DIR)/test_runtime_measure
	@$(BUILD_DIR)/test_runtime_image_measure
	@$(BUILD_DIR)/test_runtime_protect_digest
	@$(BUILD_DIR)/test_runtime_image_collect
	@$(BUILD_DIR)/test_runtime_measure_pid
	@$(BUILD_DIR)/test_seal_blob
	@$(BUILD_DIR)/test_seal_envelope
	@$(BUILD_DIR)/test_seal_tpm
	@$(BUILD_DIR)/test_seal_aik
	@$(BUILD_DIR)/test_loader_symbols
	@echo ""
	@echo "=== Running integration tests (best effort) ==="
	@if [ -S /run/lota/lota.sock ]; then \
		$(BUILD_DIR)/test_sdk_ipc; \
		$(BUILD_DIR)/test_ipc_client status; \
		$(BUILD_DIR)/demo_sdk; \
	else \
		echo "SKIP: SDK/IPC tests (agent socket not found)"; \
	fi
	@if [ -n "$$LOTA_RUN_TLS_TESTS" ]; then \
		$(BUILD_DIR)/test_tls_verify; \
	elif [ -f /tmp/lota-tls-test/ca.pem ]; then \
		if command -v ss >/dev/null 2>&1; then \
			if ss -lnt | grep -q ":9443 "; then $(BUILD_DIR)/test_tls_verify /tmp/lota-tls-test/ca.pem; else echo "SKIP: test_tls_verify (no server on 9443)"; fi; \
		elif command -v nc >/dev/null 2>&1; then \
			if nc -z 127.0.0.1 9443; then $(BUILD_DIR)/test_tls_verify /tmp/lota-tls-test/ca.pem; else echo "SKIP: test_tls_verify (no server on 9443)"; fi; \
		else \
			echo "SKIP: test_tls_verify (no ss/nc to check server)"; \
		fi; \
	else \
		echo "SKIP: test_tls_verify (missing /tmp/lota-tls-test/ca.pem)"; \
	fi
	@if command -v go >/dev/null 2>&1; then \
		cd $(SRC_DIR)/sdk/server && go run ../../../tests/cross_lang/test_gen.go && \
		cd $(CURDIR) && $(BUILD_DIR)/test_cross_lang_verify; \
	else \
		echo "SKIP: test_gen.go (go not installed)"; \
	fi
	@echo ""
	@echo "Tests complete. Run 'make test-hardware' (as root) for hardware tests."

test-hardware: $(AGENT_BIN)
	@echo "=== Agent hardware tests (require root) ==="
	$(AGENT_BIN) --test-iommu
	@echo ""
	$(AGENT_BIN) --test-tpm
	@echo ""

test-sdk: $(TEST_SDK_BIN) $(SDK_LIB) $(AGENT_BIN)
	@echo "=== SDK Integration Test ==="
	@echo "Start agent in another terminal: sudo $(BUILD_DIR)/lota-agent --test-ipc"
	@echo "Then run: $(BUILD_DIR)/test_sdk_ipc"

# Build every CI-safe userspace artifact under ASan/UBSan. This is a
# compilation/smoke gate for broad coverage; make test-unit remains the
# runtime sanitizer gate for the standalone unit tests.
SANITIZER_BUILD_TARGETS = all examples $(BENCH_C_BIN) syzkaller-fuzz-loader
sanitizer-build:
	$(MAKE) SANITIZE=address,undefined $(SANITIZER_BUILD_TARGETS)

# Memcheck the standalone unit tests. test_hardening is excluded on
# purpose: it probes seccomp (syscall 317, which valgrind cannot model)
# and issues a mount(2) with a deliberately invalid source pointer to
# prove the call reached the kernel rather than being filtered. Both
# are reported as errors by valgrind by design, so AddressSanitizer
# (make SANITIZE=address,undefined test-unit) covers that test instead.
VALGRIND ?= valgrind
VALGRIND_FLAGS := --error-exitcode=1 --leak-check=full \
	--errors-for-leak-kinds=definite,indirect --track-origins=yes -q
VALGRIND_UNIT_BINS := \
	test_hash_verify test_dbus test_systemd test_packaging \
	test_steam_runtime test_wine_hook test_daemon test_signal_shutdown \
	test_daemon_loop test_config test_subscribe test_policy_sign \
	test_policy_export test_aik_rotation test_initramfs_lock \
	test_installer_probe test_devt test_event_budget \
	test_server_sdk test_anticheat test_loader_symbols test_enroll_state

valgrind-unit: $(TEST_BINS)
	@echo "=== Running unit tests under valgrind memcheck ==="
	@for b in $(VALGRIND_UNIT_BINS); do \
		echo "--> $$b"; \
		$(VALGRIND) $(VALGRIND_FLAGS) $(BUILD_DIR)/$$b || exit 1; \
	done
	@echo "valgrind-unit: clean"

# Keep valgrind-unit for exhaustive standalone unit binaries, and add
# a separate smoke pass for operator-facing binaries that are safe to
# execute without TPM/BPF/root.
VALGRIND_SMOKE_CONFIG := $(BUILD_DIR)/valgrind-smoke.conf
valgrind-smoke: all examples
	@echo "=== Running CLI smoke paths under valgrind memcheck ==="
	@: > $(VALGRIND_SMOKE_CONFIG)
	@chmod 600 $(VALGRIND_SMOKE_CONFIG)
	@echo "--> lota-agent --help"; \
		$(VALGRIND) $(VALGRIND_FLAGS) $(AGENT_BIN) \
			--config $(VALGRIND_SMOKE_CONFIG) --help >/dev/null
	@if [ -x "$(EXAMPLES_BUILD_DIR)/demo_anticheat" ]; then \
		echo "--> demo_anticheat --help"; \
		$(VALGRIND) $(VALGRIND_FLAGS) \
			$(EXAMPLES_BUILD_DIR)/demo_anticheat --help >/dev/null; \
	else \
		echo "SKIP: demo_anticheat (not built)"; \
	fi
	@if [ -x "$(EXAMPLES_BUILD_DIR)/trust_pong" ]; then \
		echo "--> trust_pong --help"; \
		$(VALGRIND) $(VALGRIND_FLAGS) \
			$(EXAMPLES_BUILD_DIR)/trust_pong --help >/dev/null; \
	else \
		echo "SKIP: trust_pong (not built)"; \
	fi
	@echo "valgrind-smoke: clean"

# Fuzzing
FUZZ_CFLAGS := $(CFLAGS) -fsanitize=fuzzer,address -g -O1
FUZZ_LDFLAGS := $(LDFLAGS) -fsanitize=fuzzer,address

# Every C libFuzzer harness lives under fuzz/ as fuzz_<name>.c;
# the agent sources they exercise stay under src/agent/
FUZZ_AGENT_OBJS := $(filter-out $(BUILD_DIR)/agent/main.o $(BUILD_DIR)/agent/ipc.o $(BUILD_DIR)/agent/reload.o $(BUILD_DIR)/agent/test_servers.o $(BUILD_DIR)/agent/startup_policy.o $(BUILD_DIR)/agent/daemon_loop.o, $(AGENT_OBJS))
FUZZ_AGENT_OBJS += $(BUILD_DIR)/fuzz/fuzz_ipc.o

$(BUILD_DIR)/fuzz/fuzz_ipc.o: fuzz/fuzz_ipc.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz:
	$(Q)mkdir -p $@

fuzz-agent: $(FUZZ_AGENT_OBJS)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-agent $(FUZZ_AGENT_OBJS) $(LDFLAGS)

# Config parser fuzz (standalone, libc only)
$(BUILD_DIR)/fuzz/fuzz_config.o: fuzz/fuzz_config.c src/agent/config.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz/config_obj.o: src/agent/config.c src/agent/config.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -DLOTA_TPM_H -DTPM_AIK_HANDLE=0x81010002 -c $< -o $@

fuzz-config: $(BUILD_DIR)/fuzz/fuzz_config.o $(BUILD_DIR)/fuzz/config_obj.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-config $^

# Net pin SHA-256 parser fuzz (standalone, libc only)
$(BUILD_DIR)/fuzz/fuzz_net_pin.o: fuzz/fuzz_net_pin.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

fuzz-net-pin: $(BUILD_DIR)/fuzz/fuzz_net_pin.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-net-pin $^

# Net wire protocol parser fuzz (standalone, libc only)
$(BUILD_DIR)/fuzz/fuzz_net_wire.o: fuzz/fuzz_net_wire.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

fuzz-net-wire: $(BUILD_DIR)/fuzz/fuzz_net_wire.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-net-wire $^

# Enrollment reply decoders fuzz (standalone, includes enroll.c, libc only)
$(BUILD_DIR)/fuzz/fuzz_enroll.o: fuzz/fuzz_enroll.c src/agent/enroll.c src/agent/enroll.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

fuzz-enroll: $(BUILD_DIR)/fuzz/fuzz_enroll.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-enroll $^

# Sealed-envelope parser + AES-256-GCM core fuzz (links seal_envelope.c)
$(BUILD_DIR)/fuzz/fuzz_seal_envelope.o: fuzz/fuzz_seal_envelope.c include/lota_envelope.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz/seal_envelope_obj.o: src/agent/seal_envelope.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

fuzz-seal-envelope: $(BUILD_DIR)/fuzz/fuzz_seal_envelope.o $(BUILD_DIR)/fuzz/seal_envelope_obj.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-seal-envelope $^ -lcrypto

# TPM attestation-structure unmarshal fuzz (standalone, tss2-mu only)
$(BUILD_DIR)/fuzz/fuzz_tpm_attest.o: fuzz/fuzz_tpm_attest.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

fuzz-tpm-attest: $(BUILD_DIR)/fuzz/fuzz_tpm_attest.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-tpm-attest $^ -ltss2-mu

# Policy Ed25519 signature-verify fuzz (links policy_sign.c)
$(BUILD_DIR)/fuzz/fuzz_policy_sign.o: fuzz/fuzz_policy_sign.c src/agent/policy_sign.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz/policy_sign_obj.o: src/agent/policy_sign.c src/agent/policy_sign.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

fuzz-policy-sign: $(BUILD_DIR)/fuzz/fuzz_policy_sign.o $(BUILD_DIR)/fuzz/policy_sign_obj.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-policy-sign $^ -lcrypto

# Server SDK attestation-token verify fuzz (links lota_server.c)
$(BUILD_DIR)/fuzz/fuzz_server_sdk.o: fuzz/fuzz_server_sdk.c include/lota_server.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz/server_sdk_obj.o: src/sdk/lota_server.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

fuzz-server-sdk: $(BUILD_DIR)/fuzz/fuzz_server_sdk.o $(BUILD_DIR)/fuzz/server_sdk_obj.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-server-sdk $^ -lcrypto

# TPM2B response/credential unmarshal fuzz (standalone, tss2-mu only)
$(BUILD_DIR)/fuzz/fuzz_tpm_resp.o: fuzz/fuzz_tpm_resp.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

fuzz-tpm-resp: $(BUILD_DIR)/fuzz/fuzz_tpm_resp.o
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-tpm-resp $^ -ltss2-mu

fuzz-all: fuzz-agent fuzz-config fuzz-net-pin fuzz-net-wire fuzz-enroll \
	fuzz-seal-envelope fuzz-tpm-attest fuzz-policy-sign fuzz-server-sdk \
	fuzz-tpm-resp

# syzkaller bring-up harness: loads the production BPF LSM object,
# attaches every hook in enforce mode, and idles so syz-executor's
# syscalls run through the LOTA kernel surface. See syzkaller/README.rst.
SYZ_FUZZ_LOADER := $(BUILD_DIR)/lota_bpf_fuzz

syzkaller-fuzz-loader: $(SYZ_FUZZ_LOADER)

$(SYZ_FUZZ_LOADER): syzkaller/lota_bpf_fuzz.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $< -lbpf

help:
	@echo "LOTA $(PROJECT_VERSION)"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build targets:"
	@echo "  all              Build agent, verifier, SDKs, initramfs helper and BPF object"
	@echo "  agent            Build user-space agent only"
	@echo "  bpf              Build BPF LSM object only"
	@echo "  initramfs-lock   Build PCR14 initramfs lock helper only"
	@echo "  verifier         Build Go verifier only"
	@echo "  attest-ca        Build Go attestation CA only"
	@echo "  sdk              Build gaming SDK shared/static libraries"
	@echo "  server-sdk       Build server SDK shared/static libraries"
	@echo "  wine-hook        Build Wine/Proton LD_PRELOAD hook"
	@echo "  anticheat        Build anti-cheat compatibility layer"
	@echo "  examples         Build end-to-end demo material under examples/"
	@echo "  examples-clean   Remove demo build artifacts under build/examples"
	@echo ""
	@echo "Test targets:"
	@echo "  test             Run unit tests and best-effort integration checks"
	@echo "  test-unit        Same as test; builds required artifacts first"
	@echo "  test-sdk         Print SDK integration-test instructions"
	@echo "  test-hardware    Run hardware tests against local IOMMU/TPM (root required)"
	@echo "  sanitizer-build  Build CI-safe userspace artifacts under ASan/UBSan"
	@echo "  valgrind-unit    Run unit tests under valgrind memcheck"
	@echo "  valgrind-smoke   Run CLI smoke paths under valgrind memcheck"
	@echo "  check-includes   Fail on transitive (unused-direct) #includes"
	@echo "  lint             clang-format (C) + golangci-lint (Go) checks"
	@echo ""
	@echo "  SANITIZE=address,undefined make test-unit  build+run under ASan/UBSan"
	@echo ""
	@echo "Fuzz targets:"
	@echo "  fuzz-all         Build every fuzz target"
	@echo "  fuzz-agent       Build IPC/agent fuzz target"
	@echo "  fuzz-config      Build config parser fuzz target"
	@echo "  fuzz-net-pin     Build TLS pin parser fuzz target"
	@echo "  fuzz-net-wire    Build verifier wire-protocol fuzz target"
	@echo "  fuzz-seal-envelope Build sealed-envelope parser/AEAD fuzz target"
	@echo "  fuzz-tpm-attest  Build TPM attestation-structure unmarshal fuzz target"
	@echo "  fuzz-policy-sign Build policy signature-verify fuzz target"
	@echo "  fuzz-server-sdk  Build server SDK token-verify fuzz target"
	@echo "  fuzz-tpm-resp    Build TPM2B response/credential unmarshal fuzz target"
	@echo "  syzkaller-fuzz-loader  Build the syzkaller BPF LSM bring-up harness"
	@echo ""
	@echo "Benchmark targets (see benchmarks/README.rst):"
	@echo "  bench            Run L1 C + Go micro-benchmarks"
	@echo "  bench-go         Run Go benchmarks (verifier, sdk/server, attestca)"
	@echo "  bench-c          Build and run C SDK micro-benchmarks"
	@echo "  bench-clean      Remove benchmark binaries and raw results"
	@echo ""
	@echo "  BENCH_COUNT=10 make bench-go   more samples for benchstat"
	@echo ""
	@echo "Release targets:"
	@echo "  reproducible-build  Build all with pinned timestamp/TZ/locale (see Documentation/security/reproducible-builds.rst)"
	@echo ""
	@echo "Documentation targets (Sphinx, see Documentation/conf.py):"
	@echo "  htmldocs         Build HTML docs strictly (-W) into Documentation/_build"
	@echo "  docs-lint        Lint reStructuredText sources (sphinx-lint)"
	@echo "  docs-linkcheck   Verify documentation links resolve"
	@echo "  docs-serve       Build then serve docs at http://localhost:8000"
	@echo "  cleandocs        Remove built documentation"
	@echo ""
	@echo "Install/cleanup targets:"
	@echo "  install          Install to DESTDIR/usr (root required without DESTDIR)"
	@echo "  clean            Remove build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make all"
	@echo "  make test-unit"
	@echo "  sudo make install"

# Benchmarks (see benchmarks/README.rst).
# L1 micro-benchmarks only
# L2 macro suite (hyperfine over swtpm)
# L3 kernel suite (perf over the BPF LSM)
# are operator runbooks documented in benchmarks/README.rst.
.PHONY: bench bench-go bench-c bench-clean

BENCH_DIR := benchmarks
BENCH_RESULTS := $(BENCH_DIR)/results
BENCH_C_BIN := $(BUILD_DIR)/bench_sdk
GO_BENCH_MODULES := $(SRC_DIR)/verifier $(SRC_DIR)/sdk/server $(SRC_DIR)/attestca
# -count feeds benchstat
BENCH_COUNT ?= 6
BENCH_TIME ?= 1s

bench: bench-c bench-go
	@echo "Benchmarks complete. Raw output under $(BENCH_RESULTS)/"
	@echo "Render Documentation/performance/evaluation.rst with: benchmarks/scripts/run_all.sh"

bench-go:
	@mkdir -p $(BENCH_RESULTS)
	@for m in $(GO_BENCH_MODULES); do \
		name=$$(echo $$m | tr '/' '-'); \
		echo "== go bench: $$m =="; \
		( cd $$m && go test -run '^$$' -bench=. -benchmem \
			-count=$(BENCH_COUNT) -benchtime=$(BENCH_TIME) ./... ) \
			| tee $(abspath $(BENCH_RESULTS))/go-$$name.txt; \
	done

bench-c: $(BENCH_C_BIN)
	@mkdir -p $(BENCH_RESULTS)
	@rm -f $(BENCH_RESULTS)/c-sdk.json
	@BENCH_JSON=$(abspath $(BENCH_RESULTS))/c-sdk.json $(BENCH_C_BIN) \
		| tee $(BENCH_RESULTS)/c-sdk.txt

$(BENCH_C_BIN): $(BENCH_DIR)/c/bench_sdk.c $(ANTICHEAT_SRCS) \
		$(SDK_DIR)/lota_gaming.c $(SERVER_SDK_SRCS) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -I$(BENCH_DIR)/include -o $@ $^ -lcrypto -lm

bench-clean:
	rm -rf $(BENCH_RESULTS)/*.txt $(BENCH_RESULTS)/*.json $(BENCH_C_BIN)

# pull in auto-generated header dependencies
-include $(AGENT_OBJS:.o=.d)
-include $(SDK_OBJS:.o=.d)
-include $(SERVER_SDK_OBJS:.o=.d)
-include $(WINE_HOOK_OBJS:.o=.d)
-include $(ANTICHEAT_OBJS:.o=.d)
