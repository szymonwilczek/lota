# SPDX-License-Identifier: MIT

.DEFAULT_GOAL := help

CC ?= gcc
CLANG ?= clang

# V=1 prints every command in full.
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
  quiet_name = $(patsubst $(BUILD_DIR)/%,%,$@)
  QUIET_CC      = @echo "  CC      $(quiet_name)"
  QUIET_CLANG   = @echo "  CLANG   $(quiet_name)"
  QUIET_LD      = @echo "  LD      $(quiet_name)"
  QUIET_AR      = @echo "  AR      $(quiet_name)"
  QUIET_GO      = @echo "  GO      $(quiet_name)"
  QUIET_GEN     = @echo "  GEN     $(quiet_name)"
endif

SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
AGENT_DIR := $(SRC_DIR)/agent
INC_DIR := include
LOTA_BENCH_DIR := tools/lota-bench
BUILD_DIR := build
export LOTA_BUILD_DIR := $(abspath $(BUILD_DIR))
VERSION_FILE := VERSION
PROJECT_VERSION := $(strip $(shell sed -n '1p' $(VERSION_FILE) 2>/dev/null))
GOCACHE ?= $(abspath $(BUILD_DIR)/.gocache)

ifeq ($(PROJECT_VERSION),)
$(error VERSION file is missing or empty)
endif

AGENT_BIN := $(BUILD_DIR)/lota-agent
INITRAMFS_LOCK_BIN := $(BUILD_DIR)/lota-pcr14-lock
INSTALLER_BIN := $(BUILD_DIR)/lota-install
VERIFIER_BIN := $(BUILD_DIR)/lota-verifier
ATTESTCA_BIN := $(BUILD_DIR)/lota-attest-ca
FLEETCTL_BIN := $(BUILD_DIR)/lota-fleet
LOADGEN_BIN := $(BUILD_DIR)/lota-loadgen
BPF_OBJ := $(BUILD_DIR)/lota_lsm.bpf.o
LEGACY_BPF_OBJ := $(BUILD_DIR)/legacy_integrity_map.bpf.o
SDK_LIB := $(BUILD_DIR)/liblotagaming.so
SDK_STATIC := $(BUILD_DIR)/liblotagaming.a
SERVER_SDK_LIB := $(BUILD_DIR)/liblotaserver.so
SERVER_SDK_STATIC := $(BUILD_DIR)/liblotaserver.a

# Shared-library ABI version, independent of VERSION.
# The soname carries the major only; the file carries the full version.
LOTA_ABI_MAJOR := 1
LOTA_ABI_VERSION := $(LOTA_ABI_MAJOR).0.0

ifndef ARCH
	HOST_ARCH := $(shell $(CC) -dumpmachine | cut -d- -f1)
	ARCH := $(HOST_ARCH)
endif

CFLAGS := -Wall -Wextra -Werror -O2 -g
CFLAGS += -I$(INC_DIR)
CFLAGS += -D_GNU_SOURCE
CFLAGS += -fstack-protector-strong
CFLAGS += -fstack-clash-protection
# -fcf-protection is x86-only.
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

REPRO_CFLAGS := -ffile-prefix-map=$(CURDIR)=.
CFLAGS += $(REPRO_CFLAGS)

# SANITIZE=address,undefined builds the host C objects, not the BPF object,
# under the sanitizers; a finding aborts the process.
ifdef SANITIZE
CFLAGS += -fsanitize=$(SANITIZE) -fno-omit-frame-pointer
CFLAGS += -fno-sanitize-recover=all
endif

LOTA_VERSION_STRING ?= $(PROJECT_VERSION)
SDK_VERSION_CFLAGS := -DLOTA_BUILD_VERSION_STRING=\"$(LOTA_VERSION_STRING)\"

HARDENING_LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code

# -pthread: the watchdog runs on a thread of its own.
LDFLAGS := -pie -pthread $(HARDENING_LDFLAGS)
LDFLAGS += -lbpf -ltss2-esys -ltss2-mu -ltss2-tcti-device -ltss2-tctildr -lcrypto -lssl -lsystemd -lseccomp

ifdef SANITIZE
LDFLAGS += -fsanitize=$(SANITIZE)
endif

BPF_ARCH := $(ARCH)
ifeq ($(ARCH),x86_64)
	BPF_ARCH := x86
endif
ifeq ($(ARCH),aarch64)
	BPF_ARCH := arm64
endif

# -mcpu=v3 for the atomic exchange and compare-and-swap of the event budget.
BPF_CFLAGS := -target bpf -g -O2 -mcpu=v3
BPF_CFLAGS += -D__TARGET_ARCH_$(BPF_ARCH)
BPF_CFLAGS += -D__BPF_PROGRAM__
BPF_CFLAGS += -I$(INC_DIR)
BPF_CFLAGS += $(REPRO_CFLAGS)

AGENT_SRCS := $(AGENT_DIR)/main.c \
			  $(AGENT_DIR)/cli.c \
			  $(AGENT_DIR)/diagnostics.c \
			  $(AGENT_DIR)/daemon_loop.c \
			  $(AGENT_DIR)/daemon_loop_telemetry.c \
			  $(AGENT_DIR)/main_utils.c \
			  $(AGENT_DIR)/io_utils.c \
			  $(AGENT_DIR)/bench.c \
			  $(AGENT_DIR)/bench_proc.c \
			  $(AGENT_DIR)/bench_snapshot.c \
			  $(AGENT_DIR)/bench_bpf.c \
			  $(AGENT_DIR)/bench_protected.c \
			  $(AGENT_DIR)/status_cmd.c \
			  $(AGENT_DIR)/exit_status.c \
			  $(AGENT_DIR)/sb_dev.c \
			  $(AGENT_DIR)/cgroup_guard.c \
			  $(AGENT_DIR)/reload.c \
			  $(AGENT_DIR)/test_servers.c \
			  $(AGENT_DIR)/startup_policy.c \
              $(AGENT_DIR)/policy_pubkey.c \
              $(AGENT_DIR)/tpm.c \
              $(AGENT_DIR)/tpm_errno.c \
              $(AGENT_DIR)/seal_envelope.c \
              $(AGENT_DIR)/iommu.c \
              $(AGENT_DIR)/kernel_measure.c \
              $(AGENT_DIR)/kernel_image.c \
              $(AGENT_DIR)/tcg_log.c \
              $(AGENT_DIR)/boot_evidence.c \
              $(AGENT_DIR)/bpf_loader.c \
              $(AGENT_DIR)/net.c \
              $(AGENT_DIR)/net_errno.c \
              $(AGENT_DIR)/pin.c \
              $(AGENT_DIR)/ipc.c \
              $(AGENT_DIR)/runtime_image_measure.c \
              $(AGENT_DIR)/report.c \
              $(AGENT_DIR)/esrt.c \
              $(AGENT_DIR)/moklist.c \
              $(AGENT_DIR)/daemon.c \
              $(AGENT_DIR)/shutdown.c \
              $(AGENT_DIR)/policy.c \
              $(AGENT_DIR)/policy_sign.c \
              $(AGENT_DIR)/config.c \
              $(AGENT_DIR)/steam_runtime.c \
              $(AGENT_DIR)/container_watch.c \
              $(AGENT_DIR)/token_gate.c \
              $(AGENT_DIR)/dbus.c \
              $(AGENT_DIR)/sdnotify.c \
              $(AGENT_DIR)/watchdog.c \
              $(AGENT_DIR)/journal.c \
              $(AGENT_DIR)/selftest.c \
              $(AGENT_DIR)/event.c \
              $(AGENT_DIR)/hardening.c \
              $(AGENT_DIR)/enroll.c \
              $(AGENT_DIR)/enroll_client.c \
              $(AGENT_DIR)/enroll_state.c \
              $(AGENT_DIR)/publishers.c \
              $(AGENT_DIR)/profile.c \
              $(AGENT_DIR)/aik_cert.c \
              $(AGENT_DIR)/attest_targets.c \
              $(AGENT_DIR)/attest_peer.c \
              $(AGENT_DIR)/attest_stage.c \
              $(AGENT_DIR)/attest.c

AGENT_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(AGENT_SRCS))

SDK_DIR := $(SRC_DIR)/sdk
SDK_SRCS := $(SDK_DIR)/lota_gaming.c
SDK_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SDK_SRCS))

SERVER_SDK_SRCS := $(SDK_DIR)/lota_server.c
SERVER_SDK_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SERVER_SDK_SRCS))

WINE_HOOK_LIB := $(BUILD_DIR)/liblota_wine_hook.so
WINE_HOOK_SRCS := $(SDK_DIR)/lota_wine_hook.c
# the hook links its own SDK objects, built hidden
WINE_HOOK_OBJS := $(patsubst $(SDK_DIR)/%.c,$(BUILD_DIR)/hook/%.o,\
	$(WINE_HOOK_SRCS) $(SDK_SRCS))

# The hook's 32-bit half, x86_64 only: lota-proton-hook names the hook through
# ld.so's $$LIB token. auto builds it when a -m32 program links; install
# requires it.
LOTA_HOOK32 ?= auto
ifeq ($(ARCH),x86_64)
ifeq ($(LOTA_HOOK32),auto)
LOTA_HOOK32 := $(shell echo 'int main(void){return 0;}' | \
	$(CC) -m32 -x c -o /dev/null - >/dev/null 2>&1 && echo 1 || echo 0)
endif
else
LOTA_HOOK32 := 0
endif

HOOK32_MISSING := the 32-bit half of the Wine hook needs a multilib toolchain \
(glibc-devel.i686 and libatomic.i686 on Fedora, gcc-multilib on \
Debian/Ubuntu)

ifeq ($(LOTA_HOOK32),1)
WINE_HOOK_LIB32 := $(BUILD_DIR)/lib32/liblota_wine_hook.so
WINE_HOOK_OBJS32 := $(patsubst $(SDK_DIR)/%.c,$(BUILD_DIR)/hook32/%.o,\
	$(WINE_HOOK_SRCS) $(SDK_SRCS))
endif

PROTECT_BIN := $(BUILD_DIR)/lota-protect
PROTECT_SRCS := $(SDK_DIR)/lota_protect.c

ANTICHEAT_LIB := $(BUILD_DIR)/liblota_anticheat.so
ANTICHEAT_SRCS := $(SDK_DIR)/lota_anticheat.c
ANTICHEAT_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(ANTICHEAT_SRCS))

SDK_VERSION_SCRIPT = $(SDK_DIR)/$(basename $(notdir $(1))).map
VERSION_SCRIPT_LDFLAGS = -Wl,--version-script=$(call SDK_VERSION_SCRIPT,$(1))

# The .pc files carry the ABI version, not VERSION.
PKGCONFIG_DIR := $(BUILD_DIR)/pkgconfig
PKGCONFIG_TEMPLATES := $(wildcard packaging/pkgconfig/*.pc.in)
PKGCONFIG_FILES := $(patsubst packaging/pkgconfig/%.pc.in,$(PKGCONFIG_DIR)/%.pc,\
	$(PKGCONFIG_TEMPLATES))

.PHONY: all
all: $(AGENT_BIN) $(INITRAMFS_LOCK_BIN) $(INSTALLER_BIN) $(BPF_OBJ) $(VERIFIER_BIN) $(ATTESTCA_BIN) $(SDK_LIB) $(SERVER_SDK_LIB) $(WINE_HOOK_LIB) $(WINE_HOOK_LIB32) $(PROTECT_BIN) $(ANTICHEAT_LIB) $(PKGCONFIG_FILES)
ifeq ($(ARCH),x86_64)
ifneq ($(LOTA_HOOK32),1)
	@echo "note: $(HOOK32_MISSING); this tree cannot be installed as it is"
endif
endif

$(BUILD_DIR):
	$(Q)mkdir -p $(BUILD_DIR)/agent

$(AGENT_BIN): $(AGENT_OBJS) | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(INITRAMFS_LOCK_BIN): src/initramfs/lota-pcr14-lock.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -pie $(HARDENING_LDFLAGS) \
		-ltss2-esys -ltss2-mu -ltss2-tcti-device -lcrypto

# profile.c comes from the agent, so the installer names the same publisher
# profile directory the agent enrolls into.
INSTALLER_SRCS := installer/main.c installer/stages.c installer/tui.c \
	installer/ui.c installer/run.c installer/probe.c \
	$(AGENT_DIR)/config.c $(AGENT_DIR)/io_utils.c $(AGENT_DIR)/pin.c \
	$(AGENT_DIR)/policy_pubkey.c $(AGENT_DIR)/profile.c
$(INSTALLER_BIN): $(INSTALLER_SRCS) installer/install.h installer/probe.h \
		installer/run.h installer/tui.h installer/ui.h \
		$(AGENT_DIR)/config.h $(AGENT_DIR)/profile.h | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_INSTALL_VERSION=\"$(LOTA_VERSION_STRING)\" \
		-o $@ $(INSTALLER_SRCS) -pie $(HARDENING_LDFLAGS) -lbpf -lcrypto

# No package ships lota-bench.
LOTA_BENCH_BIN := $(BUILD_DIR)/lota-bench
LOTA_BENCH_SRCS := $(addprefix $(LOTA_BENCH_DIR)/,main.c cgroup.c result.c json.c \
	validate.c frames.c field.c machine.c agentsnap.c run.c report.c) \
	$(AGENT_DIR)/status_cmd.c $(AGENT_DIR)/io_utils.c
LOTA_BENCH_PREFIX ?= /usr/local
$(LOTA_BENCH_BIN): $(LOTA_BENCH_SRCS) $(wildcard $(LOTA_BENCH_DIR)/*.h) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -DLOTA_BENCH_VERSION=\"$(LOTA_VERSION_STRING)\" \
		-o $@ $(LOTA_BENCH_SRCS) -pie $(HARDENING_LDFLAGS)

DEPFLAGS = -MMD -MP -MF $(@:.o=.d)

$(BUILD_DIR)/agent/%.o: $(AGENT_DIR)/%.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

$(BUILD_DIR)/sdk/%.o: $(SDK_DIR)/%.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -fPIC -c -o $@ $<

# compile the hook and its SDK copy hidden; a version script would hide
# the dlopen wrapper behind dlopen@GLIBC_2.x
$(BUILD_DIR)/hook/%.o: $(SDK_DIR)/%.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -fPIC -fvisibility=hidden -c -o $@ $<

# the hook links only libc, so -m32 is the whole difference
$(BUILD_DIR)/hook32/%.o: $(SDK_DIR)/%.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) -m32 $(CFLAGS) $(DEPFLAGS) -fPIC -fvisibility=hidden \
		-c -o $@ $<

$(BUILD_DIR)/agent/dbus.o: CFLAGS += $(SDK_VERSION_CFLAGS)
$(BUILD_DIR)/agent/dbus.o: $(VERSION_FILE)
$(BUILD_DIR)/sdk/lota_server.o: CFLAGS += $(SDK_VERSION_CFLAGS)
$(BUILD_DIR)/sdk/lota_server.o: $(VERSION_FILE)
$(BUILD_DIR)/sdk/lota_gaming.o: CFLAGS += $(SDK_VERSION_CFLAGS)
$(BUILD_DIR)/sdk/lota_gaming.o: $(VERSION_FILE)
$(BUILD_DIR)/hook/lota_gaming.o: CFLAGS += $(SDK_VERSION_CFLAGS)
$(BUILD_DIR)/hook/lota_gaming.o: $(VERSION_FILE)
$(BUILD_DIR)/hook32/lota_gaming.o: CFLAGS += $(SDK_VERSION_CFLAGS)
$(BUILD_DIR)/hook32/lota_gaming.o: $(VERSION_FILE)

$(SDK_LIB): $(SDK_OBJS) $(call SDK_VERSION_SCRIPT,$(SDK_LIB)) Makefile | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)rm -f $@ $@.*
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $@).$(LOTA_ABI_MAJOR) \
		$(call VERSION_SCRIPT_LDFLAGS,$@) \
		$(HARDENING_LDFLAGS) -o $@.$(LOTA_ABI_VERSION) $(SDK_OBJS)
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@.$(LOTA_ABI_MAJOR)
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@

$(PKGCONFIG_DIR):
	$(Q)mkdir -p $@

.PHONY: pkgconfig
pkgconfig: $(PKGCONFIG_FILES)

# An SDK prefix built without root: the headers listed in the ABI baseline,
# the four shared libraries and the .pc files. The examples build against it.
STAGE_DIR := $(BUILD_DIR)/stage
STAGE_HEADERS := $(shell grep -v '^[[:space:]]*\#' packaging/abi/public-headers.list 2>/dev/null | grep -v '^[[:space:]]*$$')

.PHONY: sdk-stage
sdk-stage: $(SDK_LIB) $(SERVER_SDK_LIB) $(WINE_HOOK_LIB) $(ANTICHEAT_LIB) \
		$(PKGCONFIG_FILES)
	$(Q)rm -rf $(STAGE_DIR)
	$(Q)install -d $(STAGE_DIR)/include/lota $(STAGE_DIR)/lib64/pkgconfig
	$(Q)for h in $(STAGE_HEADERS); do \
		install -m 644 $(INC_DIR)/$$h $(STAGE_DIR)/include/lota/; \
	done
	$(Q)for l in liblotagaming liblotaserver liblota_wine_hook liblota_anticheat; do \
		install -m 755 $(BUILD_DIR)/$$l.so.$(LOTA_ABI_VERSION) \
			$(STAGE_DIR)/lib64/; \
		ln -sf $$l.so.$(LOTA_ABI_VERSION) \
			$(STAGE_DIR)/lib64/$$l.so.$(LOTA_ABI_MAJOR); \
		ln -sf $$l.so.$(LOTA_ABI_VERSION) $(STAGE_DIR)/lib64/$$l.so; \
	done
	$(Q)install -m 644 $(PKGCONFIG_FILES) $(STAGE_DIR)/lib64/pkgconfig/
	@echo "  STAGE   $(STAGE_DIR)"

$(PKGCONFIG_DIR)/%.pc: packaging/pkgconfig/%.pc.in Makefile | $(PKGCONFIG_DIR)
	$(QUIET_GEN)
	$(Q)sed 's|@LOTA_ABI_VERSION@|$(LOTA_ABI_VERSION)|g' $< > $@

$(SDK_STATIC): $(SDK_OBJS) | $(BUILD_DIR)
	$(QUIET_AR)
	$(Q)$(AR) rcs $@ $^

$(SERVER_SDK_LIB): $(SERVER_SDK_OBJS) $(call SDK_VERSION_SCRIPT,$(SERVER_SDK_LIB)) \
		Makefile | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)rm -f $@ $@.*
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $@).$(LOTA_ABI_MAJOR) \
		$(call VERSION_SCRIPT_LDFLAGS,$@) \
		$(HARDENING_LDFLAGS) -o $@.$(LOTA_ABI_VERSION) $(SERVER_SDK_OBJS) -lcrypto
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@.$(LOTA_ABI_MAJOR)
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@

$(SERVER_SDK_STATIC): $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(QUIET_AR)
	$(Q)$(AR) rcs $@ $^

$(WINE_HOOK_LIB): $(WINE_HOOK_OBJS) Makefile | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)rm -f $@ $@.*
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $@).$(LOTA_ABI_MAJOR) \
		$(HARDENING_LDFLAGS) -o $@.$(LOTA_ABI_VERSION) \
		$(WINE_HOOK_OBJS) -lpthread
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@.$(LOTA_ABI_MAJOR)
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@

# same soname: $$LIB picks the directory, not the name
$(WINE_HOOK_LIB32): $(WINE_HOOK_OBJS32) Makefile | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)mkdir -p $(dir $@)
	$(Q)rm -f $@ $@.*
	$(Q)$(CC) -m32 -shared -Wl,-soname,$(notdir $@).$(LOTA_ABI_MAJOR) \
		$(HARDENING_LDFLAGS) -o $@.$(LOTA_ABI_VERSION) \
		$(WINE_HOOK_OBJS32) -lpthread
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@.$(LOTA_ABI_MAJOR)
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@

$(PROTECT_BIN): $(PROTECT_SRCS) $(SDK_OBJS) include/lota_gaming.h \
		include/lota_wine_hook.h | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $(PROTECT_SRCS) $(SDK_OBJS) \
		-pie $(HARDENING_LDFLAGS)

$(ANTICHEAT_LIB): $(ANTICHEAT_OBJS) $(SDK_OBJS) $(SERVER_SDK_OBJS) \
		$(call SDK_VERSION_SCRIPT,$(ANTICHEAT_LIB)) Makefile | $(BUILD_DIR)
	$(QUIET_LD)
	$(Q)rm -f $@ $@.*
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $@).$(LOTA_ABI_MAJOR) \
		$(call VERSION_SCRIPT_LDFLAGS,$@) \
		$(HARDENING_LDFLAGS) -o $@.$(LOTA_ABI_VERSION) \
		$(ANTICHEAT_OBJS) $(SDK_OBJS) $(SERVER_SDK_OBJS) -lcrypto
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@.$(LOTA_ABI_MAJOR)
	$(Q)ln -sf $(notdir $@).$(LOTA_ABI_VERSION) $@

$(BPF_OBJ): $(BPF_DIR)/lota_lsm.bpf.c $(INC_DIR)/vmlinux.h $(INC_DIR)/lota.h $(INC_DIR)/lota_devt.h | $(BUILD_DIR)
	$(QUIET_CLANG)
	$(Q)$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

# Fixture for the integrity map layout test; nothing loads it.
$(LEGACY_BPF_OBJ): tests/fixtures/legacy_integrity_map.bpf.c $(INC_DIR)/vmlinux.h | $(BUILD_DIR)
	$(QUIET_CLANG)
	$(Q)$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

$(INC_DIR)/vmlinux.h:
	$(QUIET_GEN)
	$(Q)bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@


.PHONY: bpf
bpf: $(BPF_OBJ)

.PHONY: agent
agent: $(AGENT_BIN)

.PHONY: initramfs-lock
initramfs-lock: $(INITRAMFS_LOCK_BIN)

.PHONY: installer
installer: $(INSTALLER_BIN)

.PHONY: lota-bench
lota-bench: $(LOTA_BENCH_BIN)

.PHONY: install-lota-bench
install-lota-bench: $(LOTA_BENCH_BIN)
	install -D -m 755 $(LOTA_BENCH_BIN) $(DESTDIR)$(LOTA_BENCH_PREFIX)/bin/lota-bench

.PHONY: verifier
verifier: $(VERIFIER_BIN)

.PHONY: attest-ca
attest-ca: $(ATTESTCA_BIN)

.PHONY: fleet-cli
fleet-cli: $(FLEETCTL_BIN)

.PHONY: loadgen
loadgen: $(LOADGEN_BIN)

.PHONY: sdk
sdk: $(SDK_LIB) $(SDK_STATIC)

.PHONY: server-sdk
server-sdk: $(SERVER_SDK_LIB) $(SERVER_SDK_STATIC)

.PHONY: wine-hook
wine-hook: $(WINE_HOOK_LIB) $(WINE_HOOK_LIB32)

.PHONY: anticheat
anticheat: $(ANTICHEAT_LIB)

# Not part of all. Each examples/*/Makefile.fragment builds into
# $(BUILD_DIR)/examples.
EXAMPLES_DIR := examples
EXAMPLES_BUILD_DIR := $(BUILD_DIR)/examples
EXAMPLES_FRAGMENTS := $(wildcard $(EXAMPLES_DIR)/*/Makefile.fragment)

$(EXAMPLES_BUILD_DIR): | $(BUILD_DIR)
	$(Q)mkdir -p $@

.PHONY: examples
examples: $(EXAMPLES_BUILD_DIR) sdk-stage
	@for frag in $(EXAMPLES_FRAGMENTS); do \
		dir=$$(dirname $$frag); \
		echo "==> examples: $$dir"; \
		$(MAKE) -C $$dir -f Makefile.fragment \
			TOP_DIR=$(CURDIR) \
			BUILD_DIR=$(abspath $(EXAMPLES_BUILD_DIR)) \
			INC_DIR=$(CURDIR)/$(INC_DIR) \
			SDK_BUILD_DIR=$(abspath $(BUILD_DIR)) \
			STAGE_DIR=$(abspath $(STAGE_DIR)) || exit $$?; \
	done
	@if command -v go >/dev/null 2>&1 && [ -f $(EXAMPLES_DIR)/demo_server/main.go ]; then \
		echo "==> examples: $(EXAMPLES_DIR)/demo_server"; \
		cd $(EXAMPLES_DIR)/demo_server && \
			go build -o $(abspath $(EXAMPLES_BUILD_DIR))/demo_server . ; \
	else \
		echo "SKIP: demo_server (go not installed or stub absent)"; \
	fi

.PHONY: examples-clean
examples-clean:
	rm -rf $(EXAMPLES_BUILD_DIR)
	@for frag in $(EXAMPLES_FRAGMENTS); do \
		dir=$$(dirname $$frag); \
		$(MAKE) -C $$dir -f Makefile.fragment clean \
			BUILD_DIR=$(abspath $(EXAMPLES_BUILD_DIR)) 2>/dev/null || true; \
	done

# sign-bpf writes $(BPF_OBJ).sig with SIGNING_KEY and copies SIGNING_PUBKEY
# into the build directory for packaging.
SIGNING_KEY ?= /etc/lota/policy.key
SIGNING_PUBKEY ?= $(SIGNING_KEY:.key=.pub)
PKG_ENFORCEMENT_PUB := $(BUILD_DIR)/lota-enforcement.pub

.PHONY: sign-bpf
sign-bpf: $(BPF_OBJ) $(AGENT_BIN)
	@test -r $(SIGNING_KEY) || { \
		echo "sign-bpf: signing key not readable: $(SIGNING_KEY)" >&2; \
		echo "Generate one with: sudo $(AGENT_BIN) --gen-signing-key /etc/lota/policy" >&2; \
		exit 1; \
	}
	@test -r $(SIGNING_PUBKEY) || { \
		echo "sign-bpf: public half not readable: $(SIGNING_PUBKEY)" >&2; \
		echo "The host verifies the object against it, so it ships beside" >&2; \
		echo "the signature; pass SIGNING_PUBKEY=<path>." >&2; \
		exit 1; \
	}
	$(AGENT_BIN) --sign-policy $(BPF_OBJ) --signing-key $(SIGNING_KEY)
	@test -r $(BPF_OBJ).sig
	$(Q)cp $(SIGNING_PUBKEY) $(PKG_ENFORCEMENT_PUB)
	@echo "Signed: $(BPF_OBJ).sig"

$(VERIFIER_BIN): $(wildcard $(SRC_DIR)/verifier/*.go $(SRC_DIR)/verifier/**/*.go $(SRC_DIR)/crl/*.go) | $(BUILD_DIR)
	$(QUIET_GO)
	$(Q)cd $(SRC_DIR)/verifier && env GOCACHE=$(GOCACHE) go build -trimpath -o $(abspath $@) .

# GO_TAGS=pkcs11 builds the CA's HSM signing-key support (needs cgo).
# The stamp is rewritten only when GO_TAGS changes, so a new tag set rebuilds it.
GO_TAGS ?=
ATTESTCA_TAGS_STAMP := $(BUILD_DIR)/.attestca-tags
$(ATTESTCA_TAGS_STAMP): FORCE | $(BUILD_DIR)
	$(Q)printf '%s\n' '$(GO_TAGS)' | cmp -s - $@ 2>/dev/null || printf '%s\n' '$(GO_TAGS)' >$@

.PHONY: FORCE
FORCE:

$(ATTESTCA_BIN): $(wildcard $(SRC_DIR)/attestca/*.go $(SRC_DIR)/attestca/**/*.go $(SRC_DIR)/crl/*.go) $(ATTESTCA_TAGS_STAMP) | $(BUILD_DIR)
	$(QUIET_GO)
	$(Q)cd $(SRC_DIR)/attestca && env GOCACHE=$(GOCACHE) go build -trimpath $(if $(GO_TAGS),-tags $(GO_TAGS),) -o $(abspath $@) .

# CGO_ENABLED=0 keeps the binary static, free of the build host's glibc.
$(FLEETCTL_BIN): $(wildcard $(SRC_DIR)/fleetctl/*.go $(SRC_DIR)/fleetctl/**/*.go) | $(BUILD_DIR)
	$(QUIET_GO)
	$(Q)cd $(SRC_DIR)/fleetctl && env GOCACHE=$(GOCACHE) CGO_ENABLED=0 go build -trimpath -o $(abspath $@) .

$(LOADGEN_BIN): $(wildcard $(SRC_DIR)/verifier/loadgen/*.go $(SRC_DIR)/verifier/loadgen/**/*.go $(SRC_DIR)/verifier/*.go $(SRC_DIR)/verifier/**/*.go) | $(BUILD_DIR)
	$(QUIET_GO)
	$(Q)cd $(SRC_DIR)/verifier && env GOCACHE=$(GOCACHE) go build -trimpath -o $(abspath $@) ./loadgen

# SOURCE_DATE_EPOCH for reproducible-build and the images:
# the HEAD commit time. Without a git checkout, set REPRO_SOURCE_DATE_EPOCH.
REPRO_SOURCE_DATE_EPOCH ?= $(shell git -C $(CURDIR) log -1 --pretty=%ct 2>/dev/null)

define require_source_date_epoch
	@test -n "$(REPRO_SOURCE_DATE_EPOCH)" || { \
		echo "$@: no commit time to read and REPRO_SOURCE_DATE_EPOCH is unset." >&2; \
		echo "  This tree has no git checkout to take the timestamp from." >&2; \
		echo "  Pass the source's own release date, in seconds:" >&2; \
		echo "    make $@ REPRO_SOURCE_DATE_EPOCH=\$$(date -u -d 2026-01-31 +%s)" >&2; \
		exit 1; \
	}
endef

.PHONY: reproducible-build
reproducible-build: export SOURCE_DATE_EPOCH = $(REPRO_SOURCE_DATE_EPOCH)
reproducible-build: export TZ = UTC
reproducible-build: export LC_ALL = C
reproducible-build:
	$(require_source_date_epoch)
	$(Q)$(MAKE) all
	@echo "Reproducible build complete (SOURCE_DATE_EPOCH=$(REPRO_SOURCE_DATE_EPOCH), TZ=UTC, LC_ALL=C)"

# The files of the release manifest, as name=source: release.yml and
# reproducible-builds.yml stage and hash this list.
RELEASE_DIR ?= $(BUILD_DIR)/release
RELEASE_MANIFEST ?= $(BUILD_DIR)/SHA256SUMS
RELEASE_ARTIFACTS := \
	VERSION=VERSION \
	lota-agent=$(AGENT_BIN) \
	lota-install=$(INSTALLER_BIN) \
	lota-verifier=$(VERIFIER_BIN) \
	lota-attest-ca=$(ATTESTCA_BIN) \
	lota-pcr14-lock=$(INITRAMFS_LOCK_BIN) \
	liblotagaming.so=$(SDK_LIB) \
	liblotaserver.so=$(SERVER_SDK_LIB) \
	liblota_wine_hook.so=$(WINE_HOOK_LIB) \
	liblota_wine_hook-i386.so=$(BUILD_DIR)/lib32/liblota_wine_hook.so \
	liblota_anticheat.so=$(ANTICHEAT_LIB) \
	lota_lsm.bpf.o=$(BPF_OBJ)
RELEASE_NAMES := $(sort $(foreach a,$(RELEASE_ARTIFACTS),\
	$(firstword $(subst =, ,$(a)))))

.PHONY: release-stage
release-stage: check-hook32
	$(Q)rm -rf -- '$(RELEASE_DIR)' && mkdir -p -- '$(RELEASE_DIR)'
	$(Q)for a in $(RELEASE_ARTIFACTS); do \
		src=$${a#*=}; \
		test -f "$$src" || { \
			echo "$@: $$src is missing;" \
				"run make reproducible-build first" >&2; \
			exit 1; \
		}; \
		cp -- "$$src" '$(RELEASE_DIR)'/"$${a%%=*}" || exit 1; \
	done

.PHONY: release-manifest
release-manifest: release-stage
	$(Q)cd '$(RELEASE_DIR)' && \
		sha256sum -- $(RELEASE_NAMES) >'$(abspath $(RELEASE_MANIFEST))'

NFPM ?= nfpm
RPMLINT ?= rpmlint
# rpm spelling of the version (- as ~); exact sibling depends need it
RPM_VERSION := $(subst -,~,$(PROJECT_VERSION))
PKG_DIR ?= $(BUILD_DIR)/packages
NFPM_CONFIGS := lota-agent lota-verifier lota-attest-ca lota-sdk lota-sdk-devel
CHANGELOG_TMPL := packaging/nfpm/changelog.yaml
CHANGELOG_GEN := $(BUILD_DIR)/changelog.gen.yaml

SELINUX_PP := selinux/lota.pp
SELINUX_IF := selinux/lota.if
# Must match both package manifests and lota-install's SELinux stage default.
SELINUX_DATA_DIR := /usr/share/lota/selinux
$(SELINUX_PP): selinux/lota.te selinux/lota.if selinux/lota.fc
	$(Q)$(MAKE) -C selinux lota.pp

.PHONY: selinux-pp
selinux-pp: $(SELINUX_PP)

# An unsigned enforcement object is one the agent refuses to load, so packages
# refuses to build without $(BPF_OBJ).sig and SIGNING_PUBKEY.
# The nfpm configs take every file from ./build.
ifneq ($(filter packages,$(MAKECMDGOALS)),)
ifneq ($(abspath $(BUILD_DIR)),$(abspath build))
$(error packages builds from ./build; BUILD_DIR=$(BUILD_DIR) is not supported)
endif
endif
.PHONY: packages
packages: all selinux-pp
	$(Q)test -r $(BPF_OBJ).sig || { \
		echo "packages: $(BPF_OBJ).sig is missing." >&2; \
		echo "  The enforcement object must be signed by whoever builds" >&2; \
		echo "  the package: make sign-bpf SIGNING_KEY=<release key>" >&2; \
		exit 1; \
	}
	$(Q)test -r $(SIGNING_PUBKEY) || { \
		echo "packages: $(SIGNING_PUBKEY) is missing." >&2; \
		echo "  The public half of the signing key ships with the object" >&2; \
		echo "  so the host can verify it; pass SIGNING_PUBKEY=<path>." >&2; \
		exit 1; \
	}
	$(Q)cp $(SIGNING_PUBKEY) $(PKG_ENFORCEMENT_PUB)
	$(Q)mkdir -p $(PKG_DIR)
	$(Q)sed 's/@LOTA_VERSION@/$(PROJECT_VERSION)/g' $(CHANGELOG_TMPL) > $(CHANGELOG_GEN)
	$(Q)for c in $(NFPM_CONFIGS); do \
		echo "  NFPM    $$c"; \
		LOTA_VERSION=$(PROJECT_VERSION) \
		LOTA_RPM_VERSION=$(RPM_VERSION) $(NFPM) pkg \
			-f packaging/nfpm/$$c.yaml -p rpm -t $(PKG_DIR)/ || exit 1; \
	done
	@echo "RPMs written to $(PKG_DIR)"
	$(Q)$(MAKE) package-lint

# Skipped when rpmlint is missing.
.PHONY: package-lint
package-lint:
	$(Q)ls $(PKG_DIR)/*.rpm >/dev/null 2>&1 || { \
		echo "package-lint: no RPMs in $(PKG_DIR); run make packages first" >&2; \
		exit 1; \
	}
	$(Q)if command -v $(RPMLINT) >/dev/null 2>&1; then \
		echo "  RPMLINT $(PKG_DIR)"; \
		$(RPMLINT) --ignore-unused-rpmlintrc \
			-r packaging/nfpm/lota.rpmlintrc $(PKG_DIR)/*.rpm; \
	else \
		echo "  RPMLINT skipped ($(RPMLINT) not installed)"; \
	fi

KO ?= ko
KO_DOCKER_REPO ?= ghcr.io/szymonwilczek/lota
KO_IMAGE_TAGS ?= $(PROJECT_VERSION),latest
KO_PLATFORMS ?= linux/amd64,linux/arm64
KO_LABELS := \
	--image-label org.opencontainers.image.version=$(PROJECT_VERSION) \
	--image-label org.opencontainers.image.source=https://github.com/szymonwilczek/lota \
	--image-label org.opencontainers.image.licenses=MIT
KO_BUILD = env KO_DOCKER_REPO=$(KO_DOCKER_REPO) SOURCE_DATE_EPOCH=$(REPRO_SOURCE_DATE_EPOCH) \
	$(KO) build -B --sbom=spdx --platform=$(KO_PLATFORMS) --tags=$(KO_IMAGE_TAGS) $(KO_LABELS)

# amd64 only: cgo does not cross-compile here
KO_HSM_CONFIG := $(CURDIR)/packaging/ko/attestca-hsm
KO_HSM_PLATFORMS ?= linux/amd64
KO_HSM_TAG_SUFFIX ?= -hsm
KO_COMMA := ,
KO_HSM_IMAGE_TAGS ?= $(subst $(KO_COMMA),$(KO_HSM_TAG_SUFFIX)$(KO_COMMA),$(KO_IMAGE_TAGS))$(KO_HSM_TAG_SUFFIX)
KO_BUILD_HSM = env KO_CONFIG_PATH=$(KO_HSM_CONFIG) KO_DOCKER_REPO=$(KO_DOCKER_REPO) \
	SOURCE_DATE_EPOCH=$(REPRO_SOURCE_DATE_EPOCH) \
	$(KO) build -B --sbom=spdx --platform=$(KO_HSM_PLATFORMS) --tags=$(KO_HSM_IMAGE_TAGS) $(KO_LABELS)

.PHONY: container-images
container-images: container-image-verifier container-image-attest-ca container-image-attest-ca-hsm

.PHONY: container-image-verifier
container-image-verifier:
	$(require_source_date_epoch)
	$(Q)cd $(SRC_DIR)/verifier && $(KO_BUILD) .

.PHONY: container-image-attest-ca
container-image-attest-ca:
	$(require_source_date_epoch)
	$(Q)cd $(SRC_DIR)/attestca && $(KO_BUILD) .

.PHONY: container-image-attest-ca-hsm
container-image-attest-ca-hsm:
	$(require_source_date_epoch)
	$(Q)cd $(SRC_DIR)/attestca && $(KO_BUILD_HSM) .

HELM ?= helm
KUBECONFORM ?= kubeconform
HELM_CHART_DIR := deploy/helm/lota-verifier
HELM_CHECK_VALUES := \
	--set aikCA.existingSecret=example-aik-ca \
	--set postgres.existingSecret=example-pg \
	--set policy.enabled=true \
	--set policy.existingSecret=example-policy

.PHONY: check-helm-chart
check-helm-chart:
	@scripts/check-helm-chart.sh

.PHONY: check-container-images
check-container-images:
	@scripts/check-container-images.sh

HELM_PACKAGE_DIR ?= $(BUILD_DIR)/helm
HELM_PACKAGE := $(HELM_PACKAGE_DIR)/lota-verifier-$(PROJECT_VERSION).tgz

.PHONY: helm-package
helm-package: check-helm-chart
	$(HELM) package $(HELM_CHART_DIR) --version $(PROJECT_VERSION) \
		--app-version $(PROJECT_VERSION) -d $(HELM_PACKAGE_DIR)

.PHONY: helm-lint
helm-lint:
	$(HELM) lint $(HELM_CHART_DIR) $(HELM_CHECK_VALUES)

.PHONY: helm-template
helm-template: helm-package
	$(HELM) template lota-verifier $(HELM_PACKAGE) $(HELM_CHECK_VALUES) | $(KUBECONFORM) -strict -summary -

# --syntax-only: the scrape config names a credentials file only a deployed
# host has. It skips rule_files, so the rules are checked on their own.
PROMTOOL ?= promtool
JQ ?= jq
OBSERVABILITY_DIR := deploy/observability

.PHONY: observability-lint
observability-lint:
	$(PROMTOOL) check config --syntax-only $(OBSERVABILITY_DIR)/prometheus.yml
	$(PROMTOOL) check rules $(OBSERVABILITY_DIR)/alerts/lota-verifier-alerts.yaml
	$(JQ) empty $(OBSERVABILITY_DIR)/grafana/lota-verifier-dashboard.json

# @VERSION@ and @CHANGELOG@ in the spec are filled from VERSION; a changelog
# entry is added unless the spec holds one for this version and release.
SRPM_TREE := $(BUILD_DIR)/srpmtree
SRPM_SPEC := $(SRPM_TREE)/SPECS/lota.spec
OUTDIR ?= $(BUILD_DIR)/srpm

.PHONY: srpm
srpm: check-package-manifests
	$(Q)rm -rf $(SRPM_TREE)
	$(Q)mkdir -p $(SRPM_TREE)/SOURCES $(SRPM_TREE)/SPECS $(OUTDIR)
	$(Q)git archive --format=tar.gz --prefix=lota-$(RPM_VERSION)/ \
		-o $(SRPM_TREE)/SOURCES/lota-$(RPM_VERSION).tar.gz HEAD
	$(Q)awk -v ver='$(RPM_VERSION)' -v src='$(PROJECT_VERSION)' \
		-v date="$$(LC_ALL=C git log -1 --format=%cd --date=format:'%a %b %d %Y')" ' \
	NR == FNR { \
		if ($$1 == "Release:") { rel = $$2; sub(/%.*/, "", rel) } \
		if (inlog && /^\* / && !who) { \
			who = $$0; \
			sub(/^\* [^ ]+ [^ ]+ [^ ]+ [^ ]+ /, "", who); \
			sub(/ - [^ ]+$$/, "", who); \
		} \
		if (inlog && /^\* / && $$NF == ver "-" rel) released = 1; \
		if (/^%changelog/) inlog = 1; \
		next; \
	} \
	{ gsub(/@VERSION@/, ver) } \
	$$0 == "@CHANGELOG@" { \
		if (!released) { \
			print "* " date " " who " - " ver "-" rel; \
			print "- Packaged from the tree at " src "."; \
			print ""; \
		} \
		next; \
	} \
	{ print }' packaging/rpm/lota.spec packaging/rpm/lota.spec > $(SRPM_SPEC)
	$(Q)rpmbuild -bs $(SRPM_SPEC) \
		--define "_topdir $(abspath $(SRPM_TREE))" \
		--define "_srcrpmdir $(abspath $(OUTDIR))" \
		--define "_sourcedir $(abspath $(SRPM_TREE)/SOURCES)"
	@echo "SRPM written to $(OUTDIR)"

REPO_DIR ?= $(BUILD_DIR)/dnf-repo
LOTA_RPM_GPG_NAME ?=
LOTA_REPO_BASEURL ?= https://lota.szymon-wilczek.me/rpm

.PHONY: rpm-sign
rpm-sign:
	@test -n "$(LOTA_RPM_GPG_NAME)" || { \
		echo "rpm-sign: set LOTA_RPM_GPG_NAME to the signing key uid/id" >&2; exit 1; }
	$(Q)rpmsign --define "_gpg_name $(LOTA_RPM_GPG_NAME)" --addsign $(PKG_DIR)/*.rpm
	@echo "Signed RPMs in $(PKG_DIR)"

.PHONY: dnf-repo
dnf-repo: rpm-sign
	$(Q)rm -rf $(REPO_DIR)
	$(Q)mkdir -p $(REPO_DIR)
	$(Q)cp $(PKG_DIR)/*.rpm $(REPO_DIR)/
	$(Q)createrepo_c --quiet $(REPO_DIR)
	$(Q)gpg --batch --yes --armor -u "$(LOTA_RPM_GPG_NAME)" \
		--detach-sign $(REPO_DIR)/repodata/repomd.xml
	$(Q)gpg --export --armor "$(LOTA_RPM_GPG_NAME)" >$(REPO_DIR)/RPM-GPG-KEY-lota
	$(Q)sed 's,@BASEURL@,$(LOTA_REPO_BASEURL),g' \
		packaging/repo/lota.repo.in >$(REPO_DIR)/lota.repo
	@echo "Signed dnf repo in $(REPO_DIR) (baseurl $(LOTA_REPO_BASEURL))"

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

.PHONY: htmldocs
htmldocs:
	$(MAKE) -C Documentation html
.PHONY: docs-lint
docs-lint:
	$(MAKE) -C Documentation lint
.PHONY: docs-linkcheck
docs-linkcheck:
	$(MAKE) -C Documentation linkcheck
.PHONY: docs-serve
docs-serve:
	$(MAKE) -C Documentation serve
.PHONY: cleandocs
cleandocs:
	$(MAKE) -C Documentation clean

# A full build into a scratch tree: an incremental one skips unchanged sources.
.PHONY: check-docs-strict
check-docs-strict:
	$(Q)command -v sphinx-build >/dev/null 2>&1 || { \
		echo "check-docs-strict: sphinx-build not found; install sphinx to build the documentation" >&2; \
		exit 1; \
	}
	$(Q)scripts/check-license-boundary.sh --doc-packages >/dev/null
	$(Q)tests/integration/test_kerneldoc_warnings.sh >/dev/null
	$(Q)tmp=$$(mktemp -d) && \
	trap 'rm -rf "$$tmp"' EXIT && \
	$(MAKE) -C Documentation html BUILDDIR="$$tmp" \
		&& echo "check-docs-strict: clean"

.PHONY: check-version-tag
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

$(BUILD_DIR)/check-doc-references: scripts/check-doc-references.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $<

.PHONY: check-doc-references
check-doc-references: $(BUILD_DIR)/check-doc-references
	@$<

.PHONY: check-package-manifests
check-package-manifests:
	@scripts/check-package-manifests.sh

.PHONY: check-includes
check-includes:
	@scripts/check-includes.sh

.PHONY: check-player-build
check-player-build:
	@scripts/check-player-build.sh

.PHONY: check-license-boundary
check-license-boundary:
	@scripts/check-license-boundary.sh

.PHONY: check-test-build-dir
check-test-build-dir:
	@scripts/check-test-build-dir.sh

.PHONY: check-doc-diagnostics
check-doc-diagnostics:
	$(Q)tests/integration/test_doc_diagnostics.sh >/dev/null
	@scripts/check-doc-diagnostics.sh

.PHONY: check-config-commands
check-config-commands:
	@scripts/check-config-commands.sh

.PHONY: check-stack-frames
check-stack-frames:
	@scripts/check-stack-frames.sh

.PHONY: check-private-errno
check-private-errno:
	@scripts/check-private-errno.sh

.PHONY: check-abi
check-abi:
	@scripts/check-abi.sh

.PHONY: abi-baseline
abi-baseline:
	@scripts/check-abi.sh --update

CLANG_FORMAT ?= $(shell command -v clang-format-22 2>/dev/null || \
	command -v clang-format 2>/dev/null)
GOLANGCI_LINT ?= golangci-lint
# Must precede LINT_GO_MODULES, which := expands in place.
SERVER_SDK_MODULE := $(if $(wildcard sdk/server/go.mod),sdk/server,src/sdk/server)
LINT_GO_MODULES := src/verifier src/attestca src/crl src/fleetctl \
	$(SERVER_SDK_MODULE) examples/demo_server examples/ci-gate/gate

.PHONY: lint
lint: lint-c lint-go

.PHONY: lint-c
lint-c:
	@test -n "$(CLANG_FORMAT)" || { \
		echo "lint-c: clang-format not found (install clang-tools / clang-format-22)" >&2; \
		exit 1; }
	@files=$$(git ls-files '*.c' '*.h' | grep -v '^include/vmlinux.h$$'); \
		$(CLANG_FORMAT) --dry-run --Werror $$files
	@echo "lint-c: clean"

# check-patch reads this list.
.PHONY: print-lint-go-modules
print-lint-go-modules:
	@printf '%s\n' $(LINT_GO_MODULES)

.PHONY: lint-go
lint-go:
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "lint-go: golangci-lint not found" >&2; exit 1; }
	@for m in $(LINT_GO_MODULES); do \
		echo "==> golangci-lint $$m"; \
		( cd $$m && $(GOLANGCI_LINT) run --config $(CURDIR)/.golangci.yml ./... ) \
			|| exit $$?; \
	done
	@echo "lint-go: clean"

# sparse, smatch and Coccinelle get the include paths and the feature macro
# only, not CFLAGS, and skip src/bpf.
SPARSE ?= sparse
SMATCH ?= smatch
SPATCH ?= spatch
CHECK_PKG_CFLAGS := $(foreach p,libsystemd libseccomp dbus-1 sdl2 libcurl libbpf openssl tss2-esys tss2-mu tss2-tctildr,$(shell pkg-config --cflags $(p) 2>/dev/null))
CHECK_CPPFLAGS := -I$(INC_DIR) -I$(SRC_DIR) -D_GNU_SOURCE $(CHECK_PKG_CFLAGS)

# sparse and smatch: a finding outside /usr headers, or a non-zero exit, fails
# the file. sparse exemptions are per file, in scripts/sparse-exemptions.txt.
# The lota/ symlink gives <lota/...> includes the installed layout.
#
#   CURL_DISABLE_TYPECHECK -- smatch segfaults walking the curl_easy_setopt
#     type-check macro.
#   __glibc_has_open_how -- the checkers do not resolve glibc's
#     __has_include("linux/openat2.h"), so <fcntl.h> defines its own struct
#     open_how and <linux/openat2.h> then redefines it.
CHECKER_INC_DIR := $(BUILD_DIR)/checker-include
CHECKER_CPPFLAGS := $(CHECK_CPPFLAGS) -I$(CHECKER_INC_DIR) -Ibenchmarks/include \
	-DLOTA_INTERNAL_TESTS $(SDK_VERSION_CFLAGS) \
	-DCURL_DISABLE_TYPECHECK -D__glibc_has_open_how=1
SPARSE_FLAGS := -D__CHECKER__ -Wsparse-all -Wno-declaration-after-statement
SPARSE_EXEMPTIONS := scripts/sparse-exemptions.txt

.PHONY: sparse
sparse:
	@command -v $(SPARSE) >/dev/null 2>&1 || { \
		echo "sparse: $(SPARSE) not found (install 'sparse'); skipping" >&2; \
		exit 0; }
	$(Q)mkdir -p $(CHECKER_INC_DIR)
	$(Q)ln -sfn $(abspath $(INC_DIR)) $(CHECKER_INC_DIR)/lota
	$(Q)awk -F'|' '/^[^#]/ && NF >= 2 { \
		gsub(/\./, "\\.", $$1); \
		printf "(^|/)%s:[0-9]+:[0-9]+: (warning|error): %s\n", $$1, $$2; \
	}' $(SPARSE_EXEMPTIONS) > $(CHECKER_INC_DIR)/exempt.ere
	@echo "sparse: checking C sources"; \
	srcs=$$(git ls-files '*.c' | grep -v '^src/bpf/' | grep -v '\.bpf\.c$$'); \
	raw=$$(mktemp); \
	n=0; \
	for f in $$srcs; do \
		if $(SPARSE) $(CHECKER_CPPFLAGS) $(SPARSE_FLAGS) $$f >$$raw 2>&1; \
		then rc=0; else rc=$$?; fi; \
		out=$$(grep -vE '^/usr/|note: in included file' $$raw \
			| grep -E ':[0-9]+:[0-9]+: (warning|error)' \
			| grep -vE -f $(CHECKER_INC_DIR)/exempt.ere) || true; \
		if [ $$rc -ne 0 ]; then \
			echo "== $$f =="; \
			echo "sparse exited $$rc; this file was not analysed"; \
			[ -n "$$out" ] && echo "$$out"; \
			n=$$((n + 1)); \
		elif [ -n "$$out" ]; then \
			echo "== $$f =="; \
			echo "$$out"; \
			n=$$((n + 1)); \
		fi; \
	done; \
	rm -f $$raw; \
	echo "sparse: $$n file(s) with findings"; \
	if [ "$$n" -gt 0 ]; then \
		echo "sparse: findings above must be fixed" >&2; exit 1; \
	fi

# Skipped when smatch is missing; CI builds SMATCH_REV from
# c-static-analysis.yml. smatch's own findings carry no column
# ("file.c:LINE func() warn:"); its front-end errors do.
SMATCH_FINDING_RE := ^[^ ]+:[0-9]+ .*\(\) (warn|error|info|warning):
SMATCH_PARSE_RE := :[0-9]+:[0-9]+: (error|warning):

.PHONY: smatch
smatch:
	@command -v $(SMATCH) >/dev/null 2>&1 || { \
		echo "smatch: $(SMATCH) not found; build it from https://repo.or.cz/smatch.git and pass SMATCH=/path/to/smatch; skipping" >&2; \
		exit 0; }
	$(Q)mkdir -p $(CHECKER_INC_DIR)
	$(Q)ln -sfn $(abspath $(INC_DIR)) $(CHECKER_INC_DIR)/lota
	@echo "smatch: checking C sources"; \
	srcs=$$(git ls-files '*.c' | grep -v '^src/bpf/' | grep -v '\.bpf\.c$$'); \
	raw=$$(mktemp); \
	n=0; \
	for f in $$srcs; do \
		if $(SMATCH) $(CHECKER_CPPFLAGS) $$f >$$raw 2>&1; then \
			rc=0; \
		else \
			rc=$$?; \
		fi; \
		out=$$(grep -v '^/usr/' $$raw \
			| grep -E '$(SMATCH_FINDING_RE)|$(SMATCH_PARSE_RE)') \
			|| true; \
		if [ $$rc -ne 0 ]; then \
			echo "== $$f =="; \
			echo "smatch exited $$rc; this file was not analysed"; \
			[ -n "$$out" ] && echo "$$out"; \
			n=$$((n + 1)); \
		elif [ -n "$$out" ]; then \
			echo "== $$f =="; \
			echo "$$out"; \
			n=$$((n + 1)); \
		fi; \
	done; \
	rm -f $$raw; \
	echo "smatch: $$n file(s) with findings"; \
	if [ "$$n" -gt 0 ]; then \
		echo "smatch: findings above must be fixed" >&2; exit 1; \
	fi

# Any match of a scripts/coccinelle/ rule fails.
.PHONY: coccicheck
coccicheck:
	@command -v $(SPATCH) >/dev/null 2>&1 || { \
		echo "coccicheck: $(SPATCH) not found (install 'coccinelle'); skipping" >&2; \
		exit 0; }
	@echo "coccicheck: running Coccinelle semantic patches"; \
	srcs=$$(git ls-files '*.c' | grep -v '^src/bpf/' | grep -v '\.bpf\.c$$'); \
	rc=0; \
	for cocci in scripts/coccinelle/*.cocci; do \
		[ -e "$$cocci" ] || continue; \
		out=$$($(SPATCH) --very-quiet --no-show-diff --sp-file $$cocci $$srcs 2>/dev/null) || true; \
		if [ -n "$$out" ]; then \
			echo "== $$cocci =="; \
			echo "$$out"; \
			rc=1; \
		fi; \
	done; \
	if [ "$$rc" -ne 0 ]; then \
		echo "coccicheck: matches found (see above)" >&2; exit 1; \
	fi; \
	echo "coccicheck: clean"

# x86_64 installs need the 32-bit Wine hook
.PHONY: check-hook32
check-hook32:
ifeq ($(ARCH),x86_64)
ifneq ($(LOTA_HOOK32),1)
	@echo "$@: $(HOOK32_MISSING)" >&2
	@false
endif
endif

# selinux-pp is required: lota-install's SELinux stage loads the module.
.PHONY: install
install: check-version-tag check-hook32 all selinux-pp
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib/lota
	install -d $(DESTDIR)/usr/lib/dracut/modules.d/90lota
	install -d $(DESTDIR)/usr/lib64
	install -d $(DESTDIR)/usr/include/lota
	install -d $(DESTDIR)/usr/share/lota
	install -d -m 755 $(DESTDIR)/etc/lota
	install -d -m 700 $(DESTDIR)/var/lib/lota
	install -d -m 700 $(DESTDIR)/var/lib/lota/profiles
	install -m 755 $(AGENT_BIN) $(DESTDIR)/usr/bin/
	install -m 755 $(INSTALLER_BIN) $(DESTDIR)/usr/bin/
	install -m 755 $(INITRAMFS_LOCK_BIN) $(DESTDIR)/usr/lib/lota/
	install -m 755 $(VERIFIER_BIN) $(DESTDIR)/usr/bin/
	install -m 755 $(ATTESTCA_BIN) $(DESTDIR)/usr/bin/
	install -m 644 $(BPF_OBJ) $(DESTDIR)/usr/lib/lota/
	@# The agent reads <obj>.sig beside the object; without one it
	@# refuses the object.
	@if [ -f $(BPF_OBJ).sig ]; then \
		install -m 644 $(BPF_OBJ).sig $(DESTDIR)/usr/lib/lota/; \
	fi
	@if [ -f $(PKG_ENFORCEMENT_PUB) ]; then \
		install -m 644 $(PKG_ENFORCEMENT_PUB) \
			$(DESTDIR)/usr/lib/lota/enforcement.pub; \
	fi
	install -m 644 $(VERSION_FILE) $(DESTDIR)/usr/share/lota/VERSION
	for l in liblotagaming liblotaserver liblota_wine_hook liblota_anticheat; do \
		install -m 755 $(BUILD_DIR)/$$l.so.$(LOTA_ABI_VERSION) \
			$(DESTDIR)/usr/lib64/; \
		ln -sf $$l.so.$(LOTA_ABI_VERSION) \
			$(DESTDIR)/usr/lib64/$$l.so.$(LOTA_ABI_MAJOR); \
		ln -sf $$l.so.$(LOTA_ABI_VERSION) $(DESTDIR)/usr/lib64/$$l.so; \
	done
ifeq ($(LOTA_HOOK32),1)
	@# no linker symlink: the loader opens it by soname, nothing links it
	install -d $(DESTDIR)/usr/lib
	install -m 755 $(BUILD_DIR)/lib32/liblota_wine_hook.so.$(LOTA_ABI_VERSION) \
		$(DESTDIR)/usr/lib/
	ln -sf liblota_wine_hook.so.$(LOTA_ABI_VERSION) \
		$(DESTDIR)/usr/lib/liblota_wine_hook.so.$(LOTA_ABI_MAJOR)
endif
	install -m 755 $(PROTECT_BIN) $(DESTDIR)/usr/bin/
	install -m 755 scripts/lota-proton-hook $(DESTDIR)/usr/bin/
	install -m 755 scripts/lota-steam-setup $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/usr/share/lota/ima
	install -m 644 configs/ima/lota-ima-policy \
		$(DESTDIR)/usr/share/lota/ima/lota-ima-policy
	install -d $(DESTDIR)$(SELINUX_DATA_DIR)
	install -m 644 $(SELINUX_PP) $(DESTDIR)$(SELINUX_DATA_DIR)/lota.pp
	@# lota.if ships for policies that call its interfaces.
	install -m 644 $(SELINUX_IF) $(DESTDIR)$(SELINUX_DATA_DIR)/lota.if
	install -d $(DESTDIR)/etc/dbus-1/system.d
	install -m 644 dbus/org.lota.Agent1.conf $(DESTDIR)/etc/dbus-1/system.d/
	install -d $(DESTDIR)/usr/lib/sysusers.d
	install -m 644 systemd/lota-sysusers.conf \
		$(DESTDIR)/usr/lib/sysusers.d/lota-agent.conf
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 644 systemd/lota-agent.service $(DESTDIR)/usr/lib/systemd/system/
	install -m 644 systemd/lota-attest.service $(DESTDIR)/usr/lib/systemd/system/
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
	install -m 644 $(INC_DIR)/lota_anticheat.h $(DESTDIR)/usr/include/lota/
	install -m 644 $(INC_DIR)/lota_token.h $(DESTDIR)/usr/include/lota/
	install -m 644 $(INC_DIR)/lota_snapshot.h $(DESTDIR)/usr/include/lota/
	install -d $(DESTDIR)/usr/lib64/pkgconfig
	install -m 644 $(PKGCONFIG_FILES) $(DESTDIR)/usr/lib64/pkgconfig/
	@echo "Installed to $(DESTDIR)/usr"

# tests/test_*.c is picked up automatically. A test that links more than its
# own source declares the extra prerequisites and flags below.
TEST_SDK_BIN := $(BUILD_DIR)/test_sdk_ipc

TEST_BINS := $(patsubst tests/%.c,$(BUILD_DIR)/%,$(wildcard tests/test_*.c))
TEST_BINS += $(BUILD_DIR)/hook_preload_target
TEST_BINS += $(BUILD_DIR)/demo_sdk
TEST_BINS += $(BUILD_DIR)/test_cross_lang_report_gen
TEST_BINS += $(BUILD_DIR)/test_cross_lang_verify

# Left out of the test loop.
TEST_MANUAL := \
	$(BUILD_DIR)/demo_sdk \
	$(BUILD_DIR)/hook_preload_target \
	$(BUILD_DIR)/test_cross_lang_report_gen \
	$(BUILD_DIR)/test_cross_lang_verify \
	$(BUILD_DIR)/test_ipc_client \
	$(BUILD_DIR)/test_ipc_dos \
	$(BUILD_DIR)/test_sdk_ipc \
	$(BUILD_DIR)/test_tls_verify

TEST_RUN := $(filter-out $(TEST_MANUAL),$(TEST_BINS))

$(BUILD_DIR)/%: tests/%.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) $(TEST_CFLAGS) -o $@ $(filter %.c,$^) $(TEST_LDLIBS)

TEST_LIBBPF := -lbpf -lsystemd -lcrypto
TEST_LIBNET := -lssl -lcrypto -lsystemd
TEST_LIBSSL := -lcrypto -lsystemd
TEST_LIBTSS := -ltss2-esys -ltss2-mu -ltss2-tcti-device -ltss2-tctildr -lcrypto -lssl
TEST_LIBSDK := -L$(BUILD_DIR) -llotagaming -Wl,-rpath,$(abspath $(BUILD_DIR))

TEST_ATTEST_SRCS := $(addprefix $(AGENT_DIR)/,attest_targets.c profile.c config.c io_utils.c pin.c)
TEST_CONFIG_SRCS := $(addprefix $(AGENT_DIR)/,config.c io_utils.c pin.c)
TEST_IPC_SRCS := $(addprefix $(AGENT_DIR)/,ipc.c journal.c profile.c token_gate.c \
	hardening.c)
TEST_LOADER_SRCS := $(addprefix $(AGENT_DIR)/,bpf_loader.c journal.c policy_sign.c \
	sb_dev.c cgroup_guard.c)
TEST_NET_SRCS := $(addprefix $(AGENT_DIR)/,net.c journal.c pin.c)
TEST_SDK_SRCS := $(addprefix $(SDK_DIR)/,lota_anticheat.c lota_gaming.c lota_server.c)
TEST_STARTUP_SRCS := $(AGENT_DIR)/startup_policy.c $(TEST_LOADER_SRCS) $(TEST_CONFIG_SRCS) \
	$(AGENT_DIR)/policy_pubkey.c $(AGENT_DIR)/exit_status.c
TEST_TPM_SRCS := $(addprefix $(AGENT_DIR)/,tpm.c tpm_errno.c seal_envelope.c profile.c)
TEST_INSTALLER_SRCS := installer/stages.c installer/probe.c installer/run.c installer/ui.c \
	$(AGENT_DIR)/config.c $(AGENT_DIR)/io_utils.c $(AGENT_DIR)/pin.c \
	$(AGENT_DIR)/policy_pubkey.c $(AGENT_DIR)/profile.c

$(BUILD_DIR)/test_agent_bench_file: $(AGENT_DIR)/bench.c $(AGENT_DIR)/io_utils.c
$(BUILD_DIR)/test_agent_bench_file: TEST_CFLAGS := -DLOTA_INTERNAL_TESTS
$(BUILD_DIR)/test_status_cmd: $(AGENT_DIR)/status_cmd.c $(AGENT_DIR)/io_utils.c

$(BUILD_DIR)/test_agent_bench_snapshot: $(AGENT_DIR)/bench_snapshot.c \
	$(AGENT_DIR)/bench_proc.c $(AGENT_DIR)/bench_protected.c \
	$(AGENT_DIR)/bench.c $(AGENT_DIR)/bench_bpf.c $(AGENT_DIR)/io_utils.c

TEST_ATTEST := $(addprefix $(BUILD_DIR)/test_, \
	attest_aggregate \
	attest_reload \
	attest_targets \
)
$(TEST_ATTEST): $(TEST_ATTEST_SRCS)
$(TEST_ATTEST): TEST_LDLIBS := -lcrypto

TEST_HOOK := $(addprefix $(BUILD_DIR)/test_, \
	wine_hook_events \
	wine_hook_publisher \
	wine_hook_slow_agent \
)
$(TEST_HOOK): $(WINE_HOOK_LIB)
$(TEST_HOOK): TEST_CFLAGS := -DLOTA_HOOK_LIB_PATH='"$(WINE_HOOK_LIB)"'
$(TEST_HOOK): TEST_LDLIBS := -ldl

TEST_INSTALLER := $(addprefix $(BUILD_DIR)/test_, \
	installer_checkpoint \
	installer_fleet_profile \
	installer_trust_key \
)
$(TEST_INSTALLER): $(TEST_INSTALLER_SRCS)
$(TEST_INSTALLER): TEST_LDLIBS := -lbpf -lcrypto

TEST_IPC := $(addprefix $(BUILD_DIR)/test_, \
	ipc_attest_time \
	ipc_coverage_cost \
	ipc_extra_listener \
	ipc_lockout_sync \
	ipc_notify \
	ipc_reload_binding \
	ipc_token_no_tpm \
)
$(TEST_IPC): $(TEST_IPC_SRCS)
$(TEST_IPC): TEST_LDLIBS := $(TEST_LIBSSL) -lseccomp

TEST_LOADER := $(addprefix $(BUILD_DIR)/test_, \
	bpf_loader_load_source \
	bpf_loader_open_fails_closed \
	bpf_object_preflight \
	ima_policy_scope \
	integrity_baseline \
	loader_attach \
)
$(TEST_LOADER): $(TEST_LOADER_SRCS)
$(TEST_LOADER): TEST_LDLIBS := $(TEST_LIBBPF)

TEST_NET := $(addprefix $(BUILD_DIR)/test_, \
	connect_hint \
	tls_verify \
	verify_result_str \
)
$(TEST_NET): $(TEST_NET_SRCS)
$(TEST_NET): TEST_LDLIBS := $(TEST_LIBNET)

TEST_RUNTIME_IMAGE := $(addprefix $(BUILD_DIR)/test_, \
	runtime_identity_road \
	runtime_image_collect \
	runtime_mapping_identity \
	runtime_measure_failure \
	runtime_measure_pid \
)
$(TEST_RUNTIME_IMAGE): $(AGENT_DIR)/runtime_image_measure.c
$(TEST_RUNTIME_IMAGE): TEST_LDLIBS := -lcrypto
$(BUILD_DIR)/test_runtime_measure_pid: TEST_LDLIBS += -Wl,--wrap=fopen \
	-Wl,--wrap=openat -Wl,--wrap=stat

TEST_STARTUP := $(addprefix $(BUILD_DIR)/test_, \
	protect_pid_validation \
	startup_refusal_status \
)
$(TEST_STARTUP): $(TEST_STARTUP_SRCS)
$(TEST_STARTUP): TEST_LDLIBS := $(TEST_LIBBPF) \
	-Wl,--wrap=bpf_loader_verify_kernel_runtime_hardening

TEST_TPM := $(addprefix $(BUILD_DIR)/test_, \
	aik_rotation \
	credential_activation \
	pcr14_verdict \
	seal_aik \
)
$(TEST_TPM): $(TEST_TPM_SRCS)
$(TEST_TPM): TEST_CFLAGS := -DLOTA_INTERNAL_TESTS
$(TEST_TPM): TEST_LDLIBS := $(TEST_LIBTSS)
$(BUILD_DIR)/test_aik_rotation: TEST_LDLIBS += -Wl,--wrap=Esys_PCR_Read \
	-Wl,--wrap=Esys_Initialize -Wl,--wrap=Esys_Finalize \
	-Wl,--wrap=Esys_GetCapability -Wl,--wrap=Esys_TR_FromTPMPublic \
	-Wl,--wrap=Esys_TR_GetName -Wl,--wrap=Esys_TR_SetAuth \
	-Wl,--wrap=Esys_TR_Close -Wl,--wrap=Esys_Quote

# Interpose libbpf's open calls and the signature verify so the loader's
# verify-then-load path is testable without a key or a live kernel
$(BUILD_DIR)/test_bpf_loader_load_source: TEST_LDLIBS += \
	-Wl,--wrap=policy_verify_buffer \
	-Wl,--wrap=bpf_object__open_file \
	-Wl,--wrap=bpf_object__open_mem

# The open and attach wraps return NULL with errno clear; the map calls run
# over a table in memory.
$(BUILD_DIR)/test_bpf_loader_open_fails_closed: TEST_LDLIBS += \
	-Wl,--wrap=policy_verify_buffer \
	-Wl,--wrap=bpf_object__open_mem \
	-Wl,--wrap=bpf_object__next_program \
	-Wl,--wrap=bpf_program__type \
	-Wl,--wrap=bpf_program__name \
	-Wl,--wrap=bpf_program__attach \
	-Wl,--wrap=ring_buffer__new \
	-Wl,--wrap=bpf_map_get_next_key \
	-Wl,--wrap=bpf_map_lookup_elem \
	-Wl,--wrap=bpf_map_lookup_elem_flags \
	-Wl,--wrap=bpf_map_delete_elem \
	-Wl,--wrap=bpf_map_update_elem

$(BUILD_DIR)/test_bpf_object_preflight: TEST_LDLIBS += -Wl,--wrap=policy_verify_buffer

$(BUILD_DIR)/test_aik_cert_renew: $(AGENT_DIR)/aik_cert.c $(AGENT_DIR)/io_utils.c
$(BUILD_DIR)/test_aik_cert_renew: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_anticheat: tests/token_forge.c $(TEST_SDK_SRCS) $(VERSION_FILE)
$(BUILD_DIR)/test_anticheat: $(SDK_LIB)
$(BUILD_DIR)/test_anticheat: TEST_CFLAGS := $(SDK_VERSION_CFLAGS) \
	-DLOTA_SDK_LIB_PATH='"$(SDK_LIB)"'
$(BUILD_DIR)/test_anticheat: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_attest_stage: $(addprefix $(AGENT_DIR)/,attest_stage.c net_errno.c tpm_errno.c)

$(BUILD_DIR)/test_bench_cgroup: $(LOTA_BENCH_DIR)/cgroup.c $(LOTA_BENCH_DIR)/cgroup.h
$(BUILD_DIR)/test_bench_result: $(addprefix $(LOTA_BENCH_DIR)/,result.c result.h cgroup.c cgroup.h \
	machine.c machine.h field.c field.h)
$(BUILD_DIR)/test_bench_validate: $(addprefix $(LOTA_BENCH_DIR)/,validate.c validate.h \
	json.c json.h result.c result.h cgroup.c cgroup.h machine.c machine.h field.c field.h)
$(BUILD_DIR)/test_bench_run: $(addprefix $(LOTA_BENCH_DIR)/,run.c run.h validate.c \
	validate.h json.c json.h result.c result.h cgroup.c cgroup.h machine.c \
	machine.h field.c field.h frames.c frames.h agentsnap.c agentsnap.h) \
	$(AGENT_DIR)/status_cmd.c $(AGENT_DIR)/io_utils.c
$(BUILD_DIR)/test_bench_report: $(addprefix $(LOTA_BENCH_DIR)/,report.c report.h \
	validate.c validate.h json.c json.h result.c result.h cgroup.c cgroup.h \
	machine.c machine.h field.c field.h)
$(BUILD_DIR)/test_bench_frames: $(addprefix $(LOTA_BENCH_DIR)/,frames.c frames.h)
$(BUILD_DIR)/test_bench_field: $(addprefix $(LOTA_BENCH_DIR)/,field.c field.h)
$(BUILD_DIR)/test_bench_machine: $(addprefix $(LOTA_BENCH_DIR)/,machine.c machine.h \
	field.c field.h)
$(BUILD_DIR)/test_bench_agentsnap: $(addprefix $(LOTA_BENCH_DIR)/,agentsnap.c agentsnap.h \
	json.c json.h)

$(BUILD_DIR)/test_bpf_kill_guard: $(BPF_OBJ)
$(BUILD_DIR)/test_bpf_kill_guard: TEST_CFLAGS := -DBPF_OBJ_PATH='"$(BPF_OBJ)"'
$(BUILD_DIR)/test_bpf_kill_guard: TEST_LDLIBS := -lbpf

$(BUILD_DIR)/test_bpf_mount_hooks: $(BPF_OBJ)
$(BUILD_DIR)/test_bpf_mount_hooks: TEST_CFLAGS := -DBPF_OBJ_PATH='"$(BPF_OBJ)"'
$(BUILD_DIR)/test_bpf_mount_hooks: TEST_LDLIBS := -lelf

$(BUILD_DIR)/test_cgroup_guard: $(AGENT_DIR)/cgroup_guard.c $(AGENT_DIR)/sb_dev.c \
	$(INC_DIR)/lota.h

$(BUILD_DIR)/test_config: $(TEST_CONFIG_SRCS) $(AGENT_DIR)/policy_pubkey.c \
	$(AGENT_DIR)/cli.c
$(BUILD_DIR)/test_config_add_profile: $(TEST_CONFIG_SRCS)
$(BUILD_DIR)/test_config_alloc: $(TEST_CONFIG_SRCS)
$(BUILD_DIR)/test_config_alloc: TEST_CFLAGS := -pthread

$(BUILD_DIR)/test_constant_time: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_container_watch: $(AGENT_DIR)/container_watch.c

$(BUILD_DIR)/test_daemon: $(AGENT_DIR)/daemon.c
$(BUILD_DIR)/test_daemon_exit_status: $(AGENT_DIR)/exit_status.c
$(BUILD_DIR)/test_daemon_loop: $(AGENT_DIR)/daemon_loop_telemetry.c \
	$(AGENT_DIR)/daemon_loop.c

$(BUILD_DIR)/test_daemon_start_status: $(AGENT_BIN)
$(BUILD_DIR)/test_daemon_start_status: TEST_CFLAGS := -DAGENT_BIN_PATH='"$(AGENT_BIN)"'

$(BUILD_DIR)/test_dbus: $(AGENT_DIR)/dbus.c $(AGENT_DIR)/journal.c $(VERSION_FILE)
$(BUILD_DIR)/test_dbus: TEST_CFLAGS := $(SDK_VERSION_CFLAGS)
$(BUILD_DIR)/test_dbus: TEST_LDLIBS := -lsystemd

$(BUILD_DIR)/test_devt: $(INC_DIR)/lota_devt.h
$(BUILD_DIR)/test_enroll_state: $(AGENT_DIR)/enroll_state.c
$(BUILD_DIR)/test_enroll_status: $(AGENT_DIR)/enroll.c
$(BUILD_DIR)/test_enroll_wire: $(AGENT_DIR)/enroll.c
$(BUILD_DIR)/test_esrt: $(AGENT_DIR)/esrt.c $(AGENT_DIR)/moklist.c
$(BUILD_DIR)/test_event_budget: $(INC_DIR)/lota_event_budget.h

$(BUILD_DIR)/test_flag_names: $(SDK_LIB)
$(BUILD_DIR)/test_flag_names: TEST_LDLIBS := $(TEST_LIBSDK)

$(BUILD_DIR)/test_hardening: $(AGENT_DIR)/hardening.c $(AGENT_DIR)/journal.c
$(BUILD_DIR)/test_hardening: TEST_LDLIBS := -lseccomp -lsystemd -pthread

$(BUILD_DIR)/test_ima_xattr: $(INC_DIR)/lota_ima_xattr.h

$(BUILD_DIR)/test_initramfs_lock: src/initramfs/lota-pcr14-lock.c
$(BUILD_DIR)/test_initramfs_lock: TEST_CFLAGS := -DLOTA_INITRAMFS_LOCK_NO_MAIN
$(BUILD_DIR)/test_initramfs_lock: TEST_LDLIBS := -ltss2-esys -ltss2-mu -ltss2-tcti-device -lcrypto

$(BUILD_DIR)/test_installer_confirm: installer/ui.c

$(BUILD_DIR)/test_installer_named_paths: $(INSTALLER_BIN)
$(BUILD_DIR)/test_installer_named_paths: TEST_CFLAGS := -DLOTA_INSTALL_BIN='"$(INSTALLER_BIN)"'

$(BUILD_DIR)/test_installer_probe: installer/probe.c
$(BUILD_DIR)/test_installer_probe: TEST_LDLIBS := -lbpf -lcrypto

$(BUILD_DIR)/test_installer_service: installer/probe.c
$(BUILD_DIR)/test_installer_service: TEST_LDLIBS := -lbpf -lcrypto

$(BUILD_DIR)/test_integrity_map_layout: $(TEST_LOADER_SRCS) $(BPF_OBJ) $(LEGACY_BPF_OBJ)
$(BUILD_DIR)/test_integrity_map_layout: TEST_CFLAGS := -DTREE_BPF_OBJ='"$(BPF_OBJ)"' \
	-DLEGACY_BPF_OBJ='"$(LEGACY_BPF_OBJ)"'
$(BUILD_DIR)/test_integrity_map_layout: TEST_LDLIBS := $(TEST_LIBBPF)

$(BUILD_DIR)/test_io_read_file: $(AGENT_DIR)/io_utils.c
$(BUILD_DIR)/test_iommu_evidence: $(AGENT_DIR)/iommu.c

$(BUILD_DIR)/test_ipc_client: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_ipc_dos: $(SDK_LIB)
$(BUILD_DIR)/test_ipc_dos: TEST_LDLIBS := $(TEST_LIBSDK)

$(BUILD_DIR)/test_ipc_payload_len: $(AGENT_DIR)/ipc_payload.h $(INC_DIR)/lota_ipc.h
$(BUILD_DIR)/test_ipc_privilege: $(AGENT_DIR)/ipc_privilege.h
$(BUILD_DIR)/test_ipc_token_cap: $(INC_DIR)/lota_ipc.h $(INC_DIR)/lota_token.h

$(BUILD_DIR)/test_ipc_token_refusal: $(addprefix $(AGENT_DIR)/,ipc.c profile.c token_gate.c \
	hardening.c)
$(BUILD_DIR)/test_ipc_token_refusal: TEST_LDLIBS := $(TEST_LIBSSL) -lseccomp

$(BUILD_DIR)/test_kernel_floor_hint: $(AGENT_DIR)/kernel_floor_hint.h
$(BUILD_DIR)/test_kernel_image: $(addprefix $(AGENT_DIR)/,kernel_image.c tcg_log.c \
	boot_evidence.c)
$(BUILD_DIR)/test_kernel_measure: $(AGENT_DIR)/kernel_measure.c
$(BUILD_DIR)/test_kill_report: $(AGENT_DIR)/kill_report.h
$(BUILD_DIR)/test_mapped_pins: $(AGENT_DIR)/mapped_pins.h
$(BUILD_DIR)/test_measure_report: $(AGENT_DIR)/measure_report.h
$(BUILD_DIR)/test_module_purpose: $(INC_DIR)/lota.h

$(BUILD_DIR)/test_net_errors: $(addprefix $(AGENT_DIR)/,net.c net_errno.c journal.c pin.c \
	attest_stage.c tpm_errno.c)
$(BUILD_DIR)/test_net_errors: TEST_LDLIBS := $(TEST_LIBNET)

$(BUILD_DIR)/test_path_sanitize: $(AGENT_DIR)/path_validate.h
$(BUILD_DIR)/test_policy_export: $(AGENT_DIR)/policy.c

$(BUILD_DIR)/test_policy_sign: $(AGENT_DIR)/policy_sign.c
$(BUILD_DIR)/test_policy_sign: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_profile_id: $(addprefix $(AGENT_DIR)/,profile.c publishers.c enroll_state.c \
	aik_cert.c io_utils.c)
$(BUILD_DIR)/test_profile_id: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_protect_pids: $(AGENT_DIR)/protect_pids.h
$(BUILD_DIR)/test_ptrace_policy: $(INC_DIR)/lota.h

$(BUILD_DIR)/test_publisher_profile: $(SDK_DIR)/lota_gaming.c $(VERSION_FILE)
$(BUILD_DIR)/test_publisher_profile: TEST_CFLAGS := $(SDK_VERSION_CFLAGS)

$(BUILD_DIR)/test_reload_enforcement_state: $(addprefix $(AGENT_DIR)/,reload.c config.c journal.c \
	policy_sign.c io_utils.c pin.c)
$(BUILD_DIR)/test_reload_enforcement_state: TEST_LDLIBS := $(TEST_LIBSSL)

$(BUILD_DIR)/test_rt_verity_cache: $(AGENT_DIR)/rt_verity_cache.h

$(BUILD_DIR)/test_runtime_image_measure: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_runtime_measure: $(TEST_SDK_SRCS) $(VERSION_FILE)
$(BUILD_DIR)/test_runtime_measure: TEST_CFLAGS := $(SDK_VERSION_CFLAGS)
$(BUILD_DIR)/test_runtime_measure: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_runtime_protect_digest: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_sb_dev: $(AGENT_DIR)/sb_dev.c $(INC_DIR)/lota_devt.h
$(BUILD_DIR)/test_seal_blob: $(INC_DIR)/lota_seal.h

$(BUILD_DIR)/test_seal_envelope: $(AGENT_DIR)/seal_envelope.c
$(BUILD_DIR)/test_seal_envelope: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_sdk_ipc: $(SDK_LIB)
$(BUILD_DIR)/test_sdk_ipc: TEST_CFLAGS := -DAGENT_BIN_PATH='"$(AGENT_BIN)"'
$(BUILD_DIR)/test_sdk_ipc: TEST_LDLIBS := $(TEST_LIBSDK)

$(BUILD_DIR)/test_server_sdk: tests/token_forge.c $(SDK_DIR)/lota_server.c \
	$(SDK_DIR)/lota_gaming.c $(VERSION_FILE)
$(BUILD_DIR)/test_server_sdk: TEST_CFLAGS := $(SDK_VERSION_CFLAGS)
$(BUILD_DIR)/test_server_sdk: TEST_LDLIBS := -lcrypto

$(BUILD_DIR)/test_signal_policy: $(INC_DIR)/lota.h

$(BUILD_DIR)/test_signal_shutdown: $(AGENT_DIR)/daemon.c $(AGENT_DIR)/shutdown.c
$(BUILD_DIR)/test_signal_shutdown: TEST_LDLIBS := -pthread

$(BUILD_DIR)/test_standing_answer: $(AGENT_DIR)/standing_answer.h
$(BUILD_DIR)/test_startup_hint: $(AGENT_DIR)/startup_hint.h
$(BUILD_DIR)/test_status_flags: $(AGENT_DIR)/status_flags.h $(INC_DIR)/lota_ipc.h
$(BUILD_DIR)/test_report_flags: $(AGENT_DIR)/report_flags.h $(INC_DIR)/attestation.h $(INC_DIR)/lota_ipc.h

$(BUILD_DIR)/test_steam_runtime: $(AGENT_DIR)/steam_runtime.c $(AGENT_DIR)/journal.c
$(BUILD_DIR)/test_steam_runtime: TEST_LDLIBS := -lsystemd

$(BUILD_DIR)/test_subscribe: $(SDK_DIR)/lota_gaming.c $(VERSION_FILE)
$(BUILD_DIR)/test_subscribe: TEST_CFLAGS := $(SDK_VERSION_CFLAGS)

$(BUILD_DIR)/test_systemd: $(AGENT_DIR)/sdnotify.c $(AGENT_DIR)/journal.c
$(BUILD_DIR)/test_systemd: TEST_LDLIBS := -lsystemd

$(BUILD_DIR)/test_terminate_policy: $(AGENT_DIR)/terminate_policy.h
$(BUILD_DIR)/test_terminate_report: $(AGENT_DIR)/terminate_report.h

$(BUILD_DIR)/test_test_servers_order: $(AGENT_DIR)/test_servers.c $(AGENT_DIR)/journal.c
$(BUILD_DIR)/test_test_servers_order: TEST_LDLIBS := -lsystemd

$(BUILD_DIR)/test_tls_anchor: $(addprefix $(AGENT_DIR)/,net.c net_errno.c journal.c pin.c)
$(BUILD_DIR)/test_tls_anchor: TEST_LDLIBS := $(TEST_LIBNET)

$(BUILD_DIR)/test_token_gate: $(AGENT_DIR)/token_gate.c
$(BUILD_DIR)/test_tpm_nv_chunk: $(INC_DIR)/lota_tpm_nv.h
$(BUILD_DIR)/test_verity_digest_key: $(INC_DIR)/lota.h

# forks a child that the supervisor really kills: thread and signal under test
$(BUILD_DIR)/test_watchdog_supervisor: $(addprefix $(AGENT_DIR)/,watchdog.c sdnotify.c journal.c)
$(BUILD_DIR)/test_watchdog_supervisor: TEST_CFLAGS := -pthread
$(BUILD_DIR)/test_watchdog_supervisor: TEST_LDLIBS := -lsystemd

$(BUILD_DIR)/test_watchdog_pace: $(AGENT_DIR)/watchdog_pace.h
$(BUILD_DIR)/test_xattr_carry: $(AGENT_DIR)/io_utils.c

$(BUILD_DIR)/demo_sdk: $(SDK_DIR)/lota_gaming.c $(VERSION_FILE)
$(BUILD_DIR)/demo_sdk: TEST_CFLAGS := $(SDK_VERSION_CFLAGS)

# the test #includes lota_wine_hook.c; list it so a hook edit rebuilds
$(BUILD_DIR)/test_wine_hook: tests/test_wine_hook.c $(SDK_DIR)/lota_gaming.c \
		$(SDK_DIR)/lota_wine_hook.c $(PROTECT_SRCS) $(VERSION_FILE) \
		| $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) $(SDK_VERSION_CFLAGS) -DLOTA_HOOK_TESTING \
		-o $@ $(filter-out $(VERSION_FILE) $(SDK_DIR)/lota_wine_hook.c \
		$(PROTECT_SRCS),$^) \
		-lpthread

# C half of the report layout cross-check:
# serializes fully patterned report with the production serializer
# for report_verify.go to parse
$(BUILD_DIR)/test_cross_lang_report_gen: tests/cross_lang/report_gen.c src/agent/report.c \
		$(INC_DIR)/lota.h $(INC_DIR)/attestation.h | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

$(BUILD_DIR)/test_cross_lang_verify: tests/cross_lang/test_verify.c $(SERVER_SDK_LIB) | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -llotaserver -Wl,-rpath,$(abspath $(BUILD_DIR)) -lcrypto

# Used by the include-hygiene gate.
.PHONY: test-bins
test-bins: $(TEST_BINS)

.PHONY: test
test: test-unit

.PHONY: test-unit
test-unit: all $(TEST_BINS)
	@echo "=== Running unit tests ==="
	@set -e; for t in $(TEST_RUN); do $$t; done
	@echo ""
	@echo "=== Running integration tests (best effort) ==="
	@if [ -x $(AGENT_BIN) ] && command -v openssl >/dev/null 2>&1; then \
		tests/integration/test_add_publisher_profile.sh; \
	else \
		echo "SKIP: test_add_publisher_profile.sh (no agent binary or openssl)"; \
	fi
	@if command -v openssl >/dev/null 2>&1; then \
		tests/integration/test_enrollment_ca_material.sh; \
	else \
		echo "SKIP: test_enrollment_ca_material.sh (no openssl)"; \
	fi
	@tests/integration/test_enrollment_example_ports.sh
	@if command -v openssl >/dev/null 2>&1; then \
		tests/integration/test_enrollment_example_teardown.sh; \
	else \
		echo "SKIP: test_enrollment_example_teardown.sh (no openssl)"; \
	fi
	@if command -v openssl >/dev/null 2>&1; then \
		tests/integration/test_ek_root_pin_nv_chain.sh; \
	else \
		echo "SKIP: test_ek_root_pin_nv_chain.sh (no openssl)"; \
	fi
	@if command -v openssl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then \
		tests/integration/test_ek_root_pin_bundle_lines.sh; \
	else \
		echo "SKIP: test_ek_root_pin_bundle_lines.sh (no openssl or python3)"; \
	fi
	@if command -v openssl >/dev/null 2>&1; then \
		tests/integration/test_ek_roots_update_bundle.sh; \
	else \
		echo "SKIP: test_ek_roots_update_bundle.sh (no openssl)"; \
	fi
	@tests/integration/test_steam_setup_dropin.sh
	@tests/integration/test_steam_setup_no_session.sh
	@tests/integration/test_steam_setup_unopenable.sh
	@tests/integration/test_steam_setup_no_agent.sh
	@tests/integration/test_steam_setup_register_uid.sh
	@tests/integration/test_proton_hook_disable.sh
	@tests/integration/test_proton_hook_shares.sh
	@tests/integration/test_proton_hook_abi.sh
	@tests/integration/test_proton_hook_activation.sh
	@tests/integration/test_hook_container_report.sh
	@tests/integration/test_report_wire_sizes.sh
	@tests/integration/test_dev_bringup_idempotent.sh
	@tests/integration/test_demo_setup.sh
	@tests/integration/test_installer_status_stages.sh
	@tests/integration/test_package_manifest_lists.sh
	@tests/integration/test_pr_quality_skipped_range.sh
	@if command -v python3 >/dev/null 2>&1; then \
		tests/integration/test_license_boundary_scripts.sh; \
	else \
		echo "SKIP: test_license_boundary_scripts.sh (no python3)"; \
	fi
	@if command -v sphinx-build >/dev/null 2>&1; then \
		tests/integration/test_kerneldoc_warnings.sh; \
	else \
		echo "SKIP: test_kerneldoc_warnings.sh (no sphinx-build)"; \
	fi
	@if command -v pkg-config >/dev/null 2>&1; then \
		tests/integration/test_examples_optional_deps.sh; \
	else \
		echo "SKIP: test_examples_optional_deps.sh (no pkg-config)"; \
	fi
	@if [ -x $(EXAMPLES_BUILD_DIR)/demo_anticheat ] && \
	    [ -x $(EXAMPLES_BUILD_DIR)/lota-ci-attest ] && \
	    [ -x $(EXAMPLES_BUILD_DIR)/demo_server ] && \
	    [ -x $(EXAMPLES_BUILD_DIR)/lota-release-gate ] && \
	    [ -x $(BUILD_DIR)/lota-agent ] && \
	    [ -x $(EXAMPLES_BUILD_DIR)/runtime_remeasure ]; then \
		tests/integration/test_examples_cli.sh; \
	else \
		echo "SKIP: test_examples_cli.sh (run 'make examples')"; \
	fi
	@if [ -x $(EXAMPLES_BUILD_DIR)/trust_pong ] && command -v python3 >/dev/null 2>&1; then \
		tests/integration/test_trust_pong_freeze_streak.sh; \
	else \
		echo "SKIP: test_trust_pong_freeze_streak.sh (run 'make examples', needs python3)"; \
	fi
	@if command -v go >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then \
		tests/integration/test_attestca_build_tags.sh; \
	else \
		echo "SKIP: test_attestca_build_tags.sh (no go or C compiler)"; \
	fi
	@if command -v clang >/dev/null 2>&1; then \
		tests/integration/test_fuzz_leak_detection.sh; \
	else \
		echo "SKIP: test_fuzz_leak_detection.sh (no clang)"; \
	fi
	@if command -v go >/dev/null 2>&1; then \
		tests/integration/test_bench_targets.sh; \
	else \
		echo "SKIP: test_bench_targets.sh (no go)"; \
	fi
	@tests/integration/test_veristat_gate.sh
	@if command -v softhsm2-util >/dev/null 2>&1 && command -v pkcs11-tool >/dev/null 2>&1 && \
		command -v openssl >/dev/null 2>&1; then \
		tests/integration/test_hsm_ca_example.sh; \
	else \
		echo "SKIP: test_hsm_ca_example.sh (no softhsm2-util, pkcs11-tool or openssl)"; \
	fi
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
		cd sdk/server && go run ../../tests/cross_lang/test_gen.go && \
		cd $(CURDIR) && $(BUILD_DIR)/test_cross_lang_verify; \
	else \
		echo "SKIP: test_gen.go (go not installed)"; \
	fi
	@echo ""
	@$(BUILD_DIR)/test_cross_lang_report_gen
	@if command -v go >/dev/null 2>&1; then \
		cd $(SRC_DIR)/verifier && \
		go run ../../tests/cross_lang/report_verify.go; \
	else \
		echo "SKIP: report_verify.go (go not installed)"; \
	fi
	@echo ""
	@echo "Tests complete. Run 'make test-hardware' (as root) for hardware tests."

.PHONY: test-hardware
test-hardware: $(AGENT_BIN)
	@echo "=== Agent hardware tests (require root) ==="
	$(AGENT_BIN) --test-iommu
	@echo ""
	$(AGENT_BIN) --test-tpm
	@echo ""

.PHONY: test-sdk
test-sdk: $(TEST_SDK_BIN) $(SDK_LIB) $(AGENT_BIN)
	@echo "=== SDK Integration Test ==="
	@echo "Start agent in another terminal: sudo $(BUILD_DIR)/lota-agent --test-ipc"
	@echo "Then run: $(BUILD_DIR)/test_sdk_ipc"

# Builds under ASan/UBSan without running anything; SANITIZE=address,undefined
# test-unit runs the unit tests under them.
SANITIZER_BUILD_TARGETS = all examples $(BENCH_C_BIN) $(LOTA_BENCH_BIN) \
	syzkaller-fuzz-loader
.PHONY: sanitizer-build
sanitizer-build:
	$(MAKE) SANITIZE=address,undefined $(SANITIZER_BUILD_TARGETS)

# test_hardening is left out: valgrind cannot run its seccomp filters.
VALGRIND ?= valgrind
VALGRIND_FLAGS := --error-exitcode=1 --leak-check=full \
	--errors-for-leak-kinds=definite,indirect --track-origins=yes -q
VALGRIND_UNIT_BINS := \
	test_dbus test_systemd test_packaging \
	test_steam_runtime test_container_watch test_token_gate test_wine_hook \
	test_daemon test_daemon_start_status test_signal_shutdown \
	test_daemon_loop test_config test_config_alloc test_subscribe \
	test_policy_sign \
	test_policy_export test_aik_rotation test_initramfs_lock \
	test_installer_probe test_devt test_sb_dev test_cgroup_guard test_kernel_measure test_kernel_image test_event_budget \
	test_ptrace_policy test_signal_policy test_kill_report test_measure_report \
	test_standing_answer \
	test_module_purpose \
	test_server_sdk test_anticheat test_loader_attach test_enroll_state \
	test_profile_id test_attest_targets test_attest_reload test_attest_aggregate \
	test_status_flags test_report_flags test_iommu_evidence \
	test_terminate_policy \
	test_publisher_profile test_verify_result_str test_connect_hint \
	test_net_errors test_tls_anchor \
	test_xattr_carry test_ima_policy_scope test_kernel_floor_hint \
	test_integrity_baseline \
	test_daemon_exit_status test_integrity_map_layout \
	test_installer_confirm test_bench_cgroup test_bench_result \
	test_bench_validate test_bench_run test_bench_report \
	test_bench_frames test_bench_field \
	test_bench_machine test_bench_agentsnap test_agent_bench_file \
	test_agent_bench_snapshot test_socket_watch test_status_cmd

.PHONY: valgrind-unit
valgrind-unit: $(TEST_BINS)
	@echo "=== Running unit tests under valgrind memcheck ==="
	@for b in $(VALGRIND_UNIT_BINS); do \
		echo "--> $$b"; \
		$(VALGRIND) $(VALGRIND_FLAGS) $(BUILD_DIR)/$$b || exit 1; \
	done
	@echo "valgrind-unit: clean"

# CLI paths that run without a TPM, BPF or root.
VALGRIND_SMOKE_CONFIG := $(BUILD_DIR)/valgrind-smoke.conf
.PHONY: valgrind-smoke
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

FUZZ_CFLAGS := $(CFLAGS) -fsanitize=fuzzer,address -g -O1

# Linked into every fuzz target: disables LSan where ptrace attach is refused
FUZZ_LSAN_OBJ := $(BUILD_DIR)/fuzz/lsan_options.o

FUZZ_AGENT_OBJS := $(filter-out $(BUILD_DIR)/agent/main.o $(BUILD_DIR)/agent/ipc.o $(BUILD_DIR)/agent/reload.o $(BUILD_DIR)/agent/test_servers.o $(BUILD_DIR)/agent/startup_policy.o $(BUILD_DIR)/agent/daemon_loop.o, $(AGENT_OBJS))
FUZZ_AGENT_OBJS += $(BUILD_DIR)/fuzz/fuzz_ipc.o $(FUZZ_LSAN_OBJ)

$(FUZZ_LSAN_OBJ): fuzz/lsan_options.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

$(BUILD_DIR)/fuzz/fuzz_ipc.o: fuzz/fuzz_ipc.c src/agent/ipc.c src/agent/ipc.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz:
	$(Q)mkdir -p $@

.PHONY: fuzz-agent
fuzz-agent: $(FUZZ_AGENT_OBJS)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-agent $(FUZZ_AGENT_OBJS) $(LDFLAGS)

FUZZ_CONFIG_SRCS := src/agent/config.c src/agent/pin.c src/agent/io_utils.c
FUZZ_CONFIG_OBJS := $(patsubst src/agent/%.c,$(BUILD_DIR)/fuzz/config_%.o,$(FUZZ_CONFIG_SRCS))

$(BUILD_DIR)/fuzz/fuzz_config.o: fuzz/fuzz_config.c src/agent/config.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz/config_%.o: src/agent/%.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -MMD -MP -c $< -o $@

.PHONY: fuzz-config
fuzz-config: $(BUILD_DIR)/fuzz/fuzz_config.o $(FUZZ_CONFIG_OBJS) $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-config $^

FUZZ_BENCH_SRCS := fuzz/fuzz_bench_result.c \
	$(addprefix $(LOTA_BENCH_DIR)/,validate.c json.c result.c cgroup.c machine.c field.c)

.PHONY: fuzz-bench-result
fuzz-bench-result: $(FUZZ_BENCH_SRCS) $(wildcard $(LOTA_BENCH_DIR)/*.h) $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-bench-result \
		$(FUZZ_BENCH_SRCS) $(FUZZ_LSAN_OBJ)

FUZZ_BENCH_FRAMES_SRCS := fuzz/fuzz_bench_frames.c $(LOTA_BENCH_DIR)/frames.c

.PHONY: fuzz-bench-frames
fuzz-bench-frames: $(FUZZ_BENCH_FRAMES_SRCS) $(LOTA_BENCH_DIR)/frames.h $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-bench-frames \
		$(FUZZ_BENCH_FRAMES_SRCS) $(FUZZ_LSAN_OBJ)

$(BUILD_DIR)/fuzz/fuzz_enroll.o: fuzz/fuzz_enroll.c src/agent/enroll.c src/agent/enroll.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

.PHONY: fuzz-enroll
fuzz-enroll: $(BUILD_DIR)/fuzz/fuzz_enroll.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-enroll $^

$(BUILD_DIR)/fuzz/fuzz_seal_envelope.o: fuzz/fuzz_seal_envelope.c include/lota_envelope.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz/seal_envelope_obj.o: src/agent/seal_envelope.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

.PHONY: fuzz-seal-envelope
fuzz-seal-envelope: $(BUILD_DIR)/fuzz/fuzz_seal_envelope.o $(BUILD_DIR)/fuzz/seal_envelope_obj.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-seal-envelope $^ -lcrypto

$(BUILD_DIR)/fuzz/fuzz_tpm_attest.o: fuzz/fuzz_tpm_attest.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

.PHONY: fuzz-tpm-attest
fuzz-tpm-attest: $(BUILD_DIR)/fuzz/fuzz_tpm_attest.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-tpm-attest $^ -ltss2-mu

$(BUILD_DIR)/fuzz/fuzz_policy_sign.o: fuzz/fuzz_policy_sign.c src/agent/policy_sign.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz/policy_sign_obj.o: src/agent/policy_sign.c src/agent/policy_sign.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

.PHONY: fuzz-policy-sign
fuzz-policy-sign: $(BUILD_DIR)/fuzz/fuzz_policy_sign.o $(BUILD_DIR)/fuzz/policy_sign_obj.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-policy-sign $^ -lcrypto

$(BUILD_DIR)/fuzz/fuzz_server_sdk.o: fuzz/fuzz_server_sdk.c include/lota_server.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/fuzz/server_sdk_obj.o: src/sdk/lota_server.c $(VERSION_FILE) | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) $(SDK_VERSION_CFLAGS) -I$(INC_DIR) -c $< -o $@

.PHONY: fuzz-server-sdk
fuzz-server-sdk: $(BUILD_DIR)/fuzz/fuzz_server_sdk.o $(BUILD_DIR)/fuzz/server_sdk_obj.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-server-sdk $^ -lcrypto

$(BUILD_DIR)/fuzz/fuzz_tpm_resp.o: fuzz/fuzz_tpm_resp.c | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -c $< -o $@

.PHONY: fuzz-tpm-resp
fuzz-tpm-resp: $(BUILD_DIR)/fuzz/fuzz_tpm_resp.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-tpm-resp $^ -ltss2-mu

# fuzz-bpf-devt and fuzz-bpf-event-budget run the headers the BPF LSM
# includes; the other oracles run mirrors of helpers in
# src/bpf/lota_lsm.bpf.c.
BPF_ORACLE_CFLAGS := $(FUZZ_CFLAGS) -I$(INC_DIR) -Ifuzz/bpf_oracle

$(BUILD_DIR)/fuzz/fuzz_devt.o: fuzz/bpf_oracle/fuzz_devt.c include/lota_devt.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(BPF_ORACLE_CFLAGS) -c $< -o $@

.PHONY: fuzz-bpf-devt
fuzz-bpf-devt: $(BUILD_DIR)/fuzz/fuzz_devt.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-bpf-devt $^

$(BUILD_DIR)/fuzz/fuzz_open_flags.o: fuzz/bpf_oracle/fuzz_open_flags.c fuzz/bpf_oracle/lota_lsm_logic.h fuzz/bpf_oracle/reference.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(BPF_ORACLE_CFLAGS) -c $< -o $@

.PHONY: fuzz-bpf-open-flags
fuzz-bpf-open-flags: $(BUILD_DIR)/fuzz/fuzz_open_flags.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-bpf-open-flags $^

$(BUILD_DIR)/fuzz/fuzz_kmem_device.o: fuzz/bpf_oracle/fuzz_kmem_device.c fuzz/bpf_oracle/lota_lsm_logic.h fuzz/bpf_oracle/reference.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(BPF_ORACLE_CFLAGS) -c $< -o $@

.PHONY: fuzz-bpf-kmem-device
fuzz-bpf-kmem-device: $(BUILD_DIR)/fuzz/fuzz_kmem_device.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-bpf-kmem-device $^

$(BUILD_DIR)/fuzz/fuzz_event_budget.o: fuzz/bpf_oracle/fuzz_event_budget.c include/lota_event_budget.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(BPF_ORACLE_CFLAGS) -c $< -o $@

.PHONY: fuzz-bpf-event-budget
fuzz-bpf-event-budget: $(BUILD_DIR)/fuzz/fuzz_event_budget.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-bpf-event-budget $^

$(BUILD_DIR)/fuzz/fuzz_inaccessible_exec.o: fuzz/bpf_oracle/fuzz_inaccessible_exec.c fuzz/bpf_oracle/lota_lsm_logic.h fuzz/bpf_oracle/reference.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(BPF_ORACLE_CFLAGS) -c $< -o $@

.PHONY: fuzz-bpf-inaccessible-exec
fuzz-bpf-inaccessible-exec: $(BUILD_DIR)/fuzz/fuzz_inaccessible_exec.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-bpf-inaccessible-exec $^

$(BUILD_DIR)/fuzz/fuzz_shebang.o: fuzz/bpf_oracle/fuzz_shebang.c fuzz/bpf_oracle/lota_lsm_logic.h fuzz/bpf_oracle/reference.h | $(BUILD_DIR)/fuzz
	$(QUIET_CLANG)
	$(Q)clang $(BPF_ORACLE_CFLAGS) -c $< -o $@

.PHONY: fuzz-bpf-shebang
fuzz-bpf-shebang: $(BUILD_DIR)/fuzz/fuzz_shebang.o $(FUZZ_LSAN_OBJ)
	$(QUIET_CLANG)
	$(Q)clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-bpf-shebang $^

.PHONY: fuzz-bpf-all
fuzz-bpf-all: fuzz-bpf-devt fuzz-bpf-open-flags fuzz-bpf-kmem-device \
	fuzz-bpf-event-budget fuzz-bpf-inaccessible-exec fuzz-bpf-shebang

# mirror.lock pins the mirrored helpers by hash and the macros by definition.
# check-bpf-mirror fails when they change, or when fuzz/bpf_oracle cites the
# source by line.
BPF_MIRROR_SRC := src/bpf/lota_lsm.bpf.c
BPF_MIRROR_DIR := fuzz/bpf_oracle
BPF_MIRROR_LOCK := $(BPF_MIRROR_DIR)/mirror.lock
BPF_MIRROR_FUNCS := is_write_open_flags is_kernel_mem_device is_shebang_binprm is_inaccessible_exec_path
BPF_MIRROR_MACROS := LOTA_O_ACCMODE LOTA_O_WRONLY LOTA_O_RDWR LOTA_O_TRUNC S_IFMT S_IFCHR BINPRM_FLAGS_PATH_INACCESSIBLE

define BPF_MIRROR_GEN
	for fn in $(BPF_MIRROR_FUNCS); do \
		h=$$(awk -v fn="$$fn" '$$0 ~ ("(^|[^A-Za-z_])" fn "\\(") && /^static/ {inf=1} inf{print} inf && /^}/{exit}' $(BPF_MIRROR_SRC) | sha256sum | cut -d" " -f1); \
		echo "func $$fn $$h"; \
	done; \
	for m in $(BPF_MIRROR_MACROS); do \
		grep -E "^#define $$m " $(BPF_MIRROR_SRC) | head -1 | sed "s/^/macro $$m /"; \
	done
endef

.PHONY: check-bpf-mirror update-bpf-mirror
check-bpf-mirror:
	$(Q)cur=$$(mktemp); lck=$$(mktemp); \
	{ $(BPF_MIRROR_GEN); } > $$cur; \
	grep -vE '^#' $(BPF_MIRROR_LOCK) | grep -vE '^[[:space:]]*$$' > $$lck; \
	rc=0; \
	if ! diff -u $$lck $$cur >/dev/null; then \
		echo "ERROR: $(BPF_MIRROR_SRC) mirrored logic changed:"; \
		diff -u $$lck $$cur || true; \
		echo "Re-verify $(BPF_MIRROR_DIR)/lota_lsm_logic.h, then: make update-bpf-mirror"; \
		rc=1; \
	fi; \
	rm -f $$cur $$lck; \
	lines=$$(grep -rnE 'lota_lsm\.bpf\.c:[0-9]' $(BPF_MIRROR_DIR) || true); \
	if [ -n "$$lines" ]; then \
		echo "ERROR: $(BPF_MIRROR_DIR) cites $(BPF_MIRROR_SRC) by line, which the lock does not pin:"; \
		echo "$$lines"; \
		echo "Cite the helper or macro by name."; \
		rc=1; \
	fi; \
	[ $$rc = 0 ] && echo "bpf-mirror: in sync"; \
	exit $$rc

update-bpf-mirror:
	$(Q)sed -n '1,/do not hand-edit\./p' $(BPF_MIRROR_LOCK) > $(BPF_MIRROR_LOCK).new; \
	{ $(BPF_MIRROR_GEN); } >> $(BPF_MIRROR_LOCK).new; \
	mv $(BPF_MIRROR_LOCK).new $(BPF_MIRROR_LOCK); \
	echo "bpf-mirror: lock refreshed"

FUZZ_TARGETS := fuzz-agent fuzz-config fuzz-enroll \
	fuzz-seal-envelope fuzz-tpm-attest fuzz-policy-sign fuzz-server-sdk \
	fuzz-tpm-resp fuzz-bpf-devt fuzz-bpf-open-flags fuzz-bpf-kmem-device \
	fuzz-bpf-event-budget fuzz-bpf-inaccessible-exec fuzz-bpf-shebang \
	fuzz-bench-result fuzz-bench-frames

.PHONY: fuzz-all
fuzz-all: $(FUZZ_TARGETS)

# Replay fuzz/regressions/<target>/ against each target; any target that
# still fails fails the run. New artifacts go to the build dir, not the tree.
FUZZ_REGRESS_DIR := fuzz/regressions

.PHONY: fuzz-regress
fuzz-regress: fuzz-all
	@rc=0; \
	for t in $(FUZZ_TARGETS); do \
		d=$(FUZZ_REGRESS_DIR)/$$t; \
		[ -d $$d ] || continue; \
		set -- $$(find $$d -type f ! -name '*.rst' | sort); \
		[ $$# -gt 0 ] || continue; \
		echo "== $$t: $$# reproducer(s)"; \
		if ! $(BUILD_DIR)/$$t \
			-artifact_prefix=$(BUILD_DIR)/fuzz/regress-$$t- "$$@" \
			>$(BUILD_DIR)/fuzz/regress-$$t.log 2>&1; then \
			grep -E 'ERROR|SUMMARY|Running:|in LLVMFuzzerTestOneInput' \
				$(BUILD_DIR)/fuzz/regress-$$t.log | tail -20 >&2; \
			echo "fuzz-regress: $$t still fails on a committed reproducer," \
				"log in $(BUILD_DIR)/fuzz/regress-$$t.log" >&2; \
			rc=1; \
		fi; \
	done; \
	exit $$rc

SYZ_FUZZ_LOADER := $(BUILD_DIR)/lota_bpf_fuzz

.PHONY: syzkaller-fuzz-loader
syzkaller-fuzz-loader: $(SYZ_FUZZ_LOADER)

$(SYZ_FUZZ_LOADER): syzkaller/lota_bpf_fuzz.c | $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) -o $@ $< -lbpf

# Hook matrix guard: one README row per LSM program, naming only programs the
# object defines and syscalls lota.cfg.example enables, as ``literals``
SYZ_MATRIX_DOC := syzkaller/README.rst
SYZ_MATRIX_CFG := syzkaller/lota.cfg.example

define SYZ_MATRIX_CELLS
awk -v col=$(1) ' \
	/^Hook coverage matrix$$/ { inm = 1; next } \
	inm && /^[+|]/ { intab = 1 } \
	inm && intab && !/^[+|]/ { exit } \
	inm && /^\+=/ { body = 1 } \
	body && /^\|/ { \
		split($$0, c, "|"); cell = c[col + 1]; \
		while (match(cell, /``[^`]+``/)) { \
			print substr(cell, RSTART + 2, RLENGTH - 4); \
			cell = substr(cell, RSTART + RLENGTH); \
		} \
	}' $(SYZ_MATRIX_DOC)
endef

.PHONY: check-syzkaller-matrix
check-syzkaller-matrix:
	$(Q)rc=0; \
	progs=$$(sed -n 's/^SEC("lsm\(\.s\)\{0,1\}\/\([a-z_]*\)")$$/\2/p' $(BPF_MIRROR_SRC) | sort -u); \
	rows=$$($(call SYZ_MATRIX_CELLS,1) | grep -E '^[a-z_]+$$' | sort -u); \
	calls=$$($(call SYZ_MATRIX_CELLS,2) | grep -E '^[a-z0-9_]+(\$$[A-Za-z0-9_]+)?$$' | sort -u); \
	enabled=$$(sed -n '/"enable_syscalls"/,/\]/s/^ *"\([^"]*\)",\{0,1\}$$/\1/p' $(SYZ_MATRIX_CFG) | sort -u); \
	if [ -z "$$progs" ] || [ -z "$$rows" ]; then \
		echo "ERROR: no LSM programs in $(BPF_MIRROR_SRC) or no matrix in $(SYZ_MATRIX_DOC)"; \
		exit 1; \
	fi; \
	missing=$$(printf '%s\n' $$progs | while read -r p; do \
		printf '%s\n' $$rows | grep -qx "$$p" || echo "$$p"; done); \
	stale=$$(printf '%s\n' $$rows | while read -r p; do \
		printf '%s\n' $$progs | grep -qx "$$p" || echo "$$p"; done); \
	unlisted=$$(printf '%s\n' $$calls | while read -r c; do \
		[ -z "$$c" ] || printf '%s\n' $$enabled | grep -qxF "$$c" || echo "$$c"; done); \
	if [ -n "$$missing" ]; then \
		echo "ERROR: $(SYZ_MATRIX_DOC) hook matrix has no row for:" $$missing; rc=1; \
	fi; \
	if [ -n "$$stale" ]; then \
		echo "ERROR: $(SYZ_MATRIX_DOC) hook matrix names programs $(BPF_MIRROR_SRC) lacks:" $$stale; rc=1; \
	fi; \
	if [ -n "$$unlisted" ]; then \
		echo "ERROR: $(SYZ_MATRIX_DOC) hook matrix names calls $(SYZ_MATRIX_CFG) does not enable:" $$unlisted; rc=1; \
	fi; \
	if [ $$rc = 0 ]; then \
		echo "syzkaller-matrix: $$(printf '%s\n' $$progs | wc -l) programs, each with a row"; \
	fi; \
	exit $$rc

# Every tree path an installed header names must resolve;
# include/linux/ paths name the kernel tree and are skipped
.PHONY: check-header-paths
check-header-paths:
	$(Q)rc=0; \
	dirs=$$(git ls-files | sed -n 's,^\([^./][^/]*\)/.*,\1,p' | sort -u | paste -sd'|'); \
	if [ -z "$$dirs" ]; then \
		echo "ERROR: no tracked directories - run from a git checkout"; \
		exit 1; \
	fi; \
	refs=$$(grep -onE "($$dirs)/[A-Za-z0-9_./-]+" $(wildcard include/*.h) | \
		sed 's/\.$$//' | grep -v ':include/linux/' | sort -u); \
	for ref in $$refs; do \
		path=$$(printf '%s' "$$ref" | cut -d: -f3-); \
		[ -e "$$path" ] || { \
			echo "ERROR: $$(printf '%s' "$$ref" | cut -d: -f1,2) points at $$path, which is not in the tree"; \
			rc=1; \
		}; \
	done; \
	if [ $$rc = 0 ]; then \
		echo "header-paths: $$(printf '%s\n' $$refs | wc -l) pointers, each resolving"; \
	fi; \
	exit $$rc

HELP_ROW = printf '  %-29s  %s\n'
HELP_EXAMPLE = printf '  %-41s  %s\n'

.PHONY: help
help:
	@echo "LOTA $(PROJECT_VERSION)"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build targets:"
	@$(HELP_ROW) all "Build agent, verifier, SDKs, initramfs, BPF"
	@$(HELP_ROW) agent "Build user-space agent only"
	@$(HELP_ROW) bpf "Build BPF LSM object only"
	@$(HELP_ROW) initramfs-lock "Build PCR14 initramfs lock helper only"
	@$(HELP_ROW) verifier "Build Go verifier only"
	@$(HELP_ROW) attest-ca "Build Go attestation CA only"
	@$(HELP_ROW) fleet-cli "Build lota-fleet operator CLI only"
	@$(HELP_ROW) loadgen "Build lota-loadgen synthetic fleet driver only"
	@$(HELP_ROW) sdk "Build gaming SDK shared/static libraries"
	@$(HELP_ROW) server-sdk "Build server SDK shared/static libraries"
	@$(HELP_ROW) wine-hook "Build Wine/Proton LD_PRELOAD hook"
	@$(HELP_ROW) anticheat "Build anti-cheat compatibility layer"
	@$(HELP_ROW) lota-bench "Build the game cost meter (not packaged)"
	@$(HELP_ROW) install-lota-bench "Install lota-bench under LOTA_BENCH_PREFIX"
	@$(HELP_ROW) packages "Build native RPMs via nfpm"
	@$(HELP_ROW) package-lint "rpmlint the built RPMs (gating)"
	@$(HELP_ROW) container-images "Build distroless verifier + attest-CA images"
	@$(HELP_ROW) container-image-attest-ca-hsm "Build the PKCS#11 (HSM) attest-CA image"
	@$(HELP_ROW) srpm "Build a source RPM from HEAD (COPR / rpmbuild)"
	@$(HELP_ROW) rpm-sign "GPG-sign RPMs in PKG_DIR (LOTA_RPM_GPG_NAME)"
	@$(HELP_ROW) dnf-repo "Build a signed dnf repository under REPO_DIR"
	@$(HELP_ROW) examples "Build end-to-end demo material under examples/"
	@$(HELP_ROW) examples-clean "Remove demo artifacts under build/examples"
	@echo ""
	@echo "Test targets:"
	@$(HELP_ROW) test "Run unit and best-effort integration tests"
	@$(HELP_ROW) test-unit "Same as test; builds required artifacts first"
	@$(HELP_ROW) test-sdk "Print SDK integration-test instructions"
	@$(HELP_ROW) test-hardware "Run IOMMU/TPM hardware tests (root required)"
	@$(HELP_ROW) sanitizer-build "Build CI-safe userspace under ASan/UBSan"
	@$(HELP_ROW) valgrind-unit "Run unit tests under valgrind memcheck"
	@$(HELP_ROW) valgrind-smoke "Run CLI smoke paths under valgrind memcheck"
	@$(HELP_ROW) check-includes "Fail on unused #includes"
	@$(HELP_ROW) check-player-build "Run the player build+install in clean Fedora"
	@$(HELP_ROW) check-abi "Fail on public SDK symbol/header/layout drift"
	@$(HELP_ROW) check-stack-frames "Fail on an oversized stack frame in a binary"
	@$(HELP_ROW) check-doc-diagnostics "Fail on a quoted message no program can print"
	@$(HELP_ROW) check-config-commands "Fail on a shipped config's unresolved command"
	@$(HELP_ROW) check-test-build-dir "Fail on test/demo naming default build dir"
	@$(HELP_ROW) check-syzkaller-matrix "Fail on an LSM program missing from the matrix"
	@$(HELP_ROW) check-header-paths "Fail on an installed header's dangling path"
	@$(HELP_ROW) abi-baseline "Rewrite packaging/abi for a deliberate change"
	@$(HELP_ROW) sdk-stage "Lay out the installed SDK under build/stage"
	@$(HELP_ROW) lint "clang-format (C) + golangci-lint (Go) checks"
	@$(HELP_ROW) sparse "sparse semantic check over C sources"
	@$(HELP_ROW) smatch "smatch flow analysis over C sources"
	@$(HELP_ROW) coccicheck "Coccinelle semantic-patch rules over C sources"
	@$(HELP_ROW) check-helm-chart "Hold the chart to its version and pod"
	@$(HELP_ROW) check-container-images "Hold the images to the key roads they offer"
	@$(HELP_ROW) helm-package "Package the verifier chart at the tree version"
	@$(HELP_ROW) helm-lint "Lint the verifier Helm chart"
	@$(HELP_ROW) helm-template "Render chart and schema-check with kubeconform"
	@$(HELP_ROW) observability-lint "Validate Prometheus/Grafana reference configs"
	@echo ""
	@echo "Fuzz targets:"
	@$(HELP_ROW) fuzz-all "Build every fuzz target"
	@$(HELP_ROW) fuzz-regress "Replay the committed C fuzz reproducers"
	@$(HELP_ROW) fuzz-agent "Build IPC/agent fuzz target"
	@$(HELP_ROW) fuzz-config "Build config parser fuzz target"
	@$(HELP_ROW) fuzz-enroll "Build enrollment reply decoder fuzz target"
	@$(HELP_ROW) fuzz-seal-envelope "Build sealed-envelope parser/AEAD fuzz target"
	@$(HELP_ROW) fuzz-tpm-attest "Build TPM attestation-structure fuzz target"
	@$(HELP_ROW) fuzz-policy-sign "Build policy signature-verify fuzz target"
	@$(HELP_ROW) fuzz-server-sdk "Build server SDK token-verify fuzz target"
	@$(HELP_ROW) fuzz-tpm-resp "Build TPM2B response/credential fuzz target"
	@$(HELP_ROW) fuzz-bench-result "Build lota-bench session file fuzz target"
	@$(HELP_ROW) fuzz-bench-frames "Build lota-bench MangoHud log fuzz target"
	@$(HELP_ROW) fuzz-bpf-all "Build all BPF LSM oracle fuzz targets"
	@$(HELP_ROW) syzkaller-fuzz-loader "Build the syzkaller BPF LSM bring-up harness"
	@echo ""
	@echo "Benchmark targets (see benchmarks/README.rst):"
	@$(HELP_ROW) bench "Run L1 C + Go micro-benchmarks"
	@$(HELP_ROW) bench-go "Run Go benchmarks (verifier, sdk, attestca)"
	@$(HELP_ROW) bench-c "Build and run C SDK micro-benchmarks"
	@$(HELP_ROW) bench-clean "Remove benchmark binaries and raw results"
	@echo ""
	@echo "Release targets:"
	@$(HELP_ROW) reproducible-build "Build all with pinned timestamp/TZ/locale"
	@$(HELP_ROW) release-stage "Copy the manifest's files into RELEASE_DIR"
	@$(HELP_ROW) release-manifest "Stage and hash into RELEASE_MANIFEST"
	@echo ""
	@echo "Documentation targets (Sphinx, see Documentation/conf.py):"
	@$(HELP_ROW) htmldocs "Build HTML docs (-W) into Documentation/_build"
	@$(HELP_ROW) docs-lint "Lint reStructuredText sources (sphinx-lint)"
	@$(HELP_ROW) docs-linkcheck "Verify documentation links resolve"
	@$(HELP_ROW) docs-serve "Build then serve docs at http://localhost:8000"
	@$(HELP_ROW) cleandocs "Remove built documentation"
	@echo ""
	@echo "Install/cleanup targets:"
	@$(HELP_ROW) install "Install to DESTDIR/usr (root without DESTDIR)"
	@$(HELP_ROW) clean "Remove build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make all"
	@echo "  make test-unit"
	@echo "  sudo make install"
	@$(HELP_EXAMPLE) "SANITIZE=address,undefined make test-unit" "Build and run under ASan/UBSan"
	@$(HELP_EXAMPLE) "BENCH_COUNT=10 make bench-go" "More samples for benchstat"

.PHONY: bench bench-go bench-c bench-clean

BENCH_DIR := benchmarks
BENCH_RESULTS := $(BENCH_DIR)/results
BENCH_C_BIN := $(BUILD_DIR)/bench_sdk
GO_BENCH_MODULES := $(SRC_DIR)/verifier sdk/server $(SRC_DIR)/attestca
# -count feeds benchstat
BENCH_COUNT ?= 6
BENCH_TIME ?= 1s

bench: bench-c bench-go
	@echo "Benchmarks complete. Raw output under $(BENCH_RESULTS)/"

# /bin/sh has no pipefail: a pipe into tee reports tee's status,
# so the runner's own status goes through a file.
bench-go:
	@mkdir -p $(BENCH_RESULTS)
	@rc=0; \
	for m in $(GO_BENCH_MODULES); do \
		name=$$(echo $$m | tr '/' '-'); \
		out=$(abspath $(BENCH_RESULTS))/go-$$name.txt; \
		echo "== go bench: $$m =="; \
		( cd $$m && go test -run '^$$' -bench=. -benchmem \
			-count=$(BENCH_COUNT) -benchtime=$(BENCH_TIME) ./...; \
			echo $$? >$$out.status ) | tee $$out; \
		s=$$(cat $$out.status); rm -f $$out.status; \
		if [ "$$s" != 0 ]; then \
			echo "bench-go: $$m exited $$s, $$out is not a measurement" >&2; \
			rc=$$s; \
		fi; \
	done; \
	exit $$rc

bench-c: $(BENCH_C_BIN)
	@mkdir -p $(BENCH_RESULTS)
	@rm -f $(BENCH_RESULTS)/c-sdk.json
	@out=$(BENCH_RESULTS)/c-sdk.txt; \
	( BENCH_JSON=$(abspath $(BENCH_RESULTS))/c-sdk.json $(BENCH_C_BIN); \
		echo $$? >$$out.status ) | tee $$out; \
	s=$$(cat $$out.status); rm -f $$out.status; \
	if [ "$$s" != 0 ]; then \
		echo "bench-c: $(BENCH_C_BIN) exited $$s, $$out is not a measurement" >&2; \
		exit $$s; \
	fi

$(BENCH_C_BIN): $(BENCH_DIR)/c/bench_sdk.c $(ANTICHEAT_SRCS) \
		$(SDK_DIR)/lota_gaming.c $(SERVER_SDK_SRCS) $(VERSION_FILE) \
		| $(BUILD_DIR)
	$(QUIET_CC)
	$(Q)$(CC) $(CFLAGS) $(SDK_VERSION_CFLAGS) -I$(BENCH_DIR)/include \
		-o $@ $(filter-out $(VERSION_FILE),$^) -lcrypto -lm

bench-clean:
	rm -rf $(BENCH_RESULTS)/*.txt $(BENCH_RESULTS)/*.json $(BENCH_C_BIN)

-include $(AGENT_OBJS:.o=.d)
-include $(SDK_OBJS:.o=.d)
-include $(SERVER_SDK_OBJS:.o=.d)
-include $(WINE_HOOK_OBJS:.o=.d)
-include $(ANTICHEAT_OBJS:.o=.d)
-include $(FUZZ_CONFIG_OBJS:.o=.d)
