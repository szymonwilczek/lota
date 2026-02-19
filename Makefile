# SPDX-License-Identifier: MIT
#
# LOTA - Linux Open Trusted Attestation
# Master Makefile
#
# Targets:
#   all       - Build agent and BPF program
#   bpf       - Build only BPF program
#   agent     - Build only user-space agent
#   clean     - Remove build artifacts
#   install   - Install to system
#   test      - Run basic tests
#
# Requirements:
#   - clang, llvm (for BPF compilation)
#   - gcc (for user-space)
#   - libbpf-devel
#   - tpm2-tss-devel
#   - openssl-devel (for SHA-256)
#

# Compiler settings
CC := gcc
CLANG := clang
LLC := llc

# Directories
SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
AGENT_DIR := $(SRC_DIR)/agent
INC_DIR := include
BUILD_DIR := build

# Output files
AGENT_BIN := $(BUILD_DIR)/lota-agent
VERIFIER_BIN := $(BUILD_DIR)/lota-verifier
BPF_OBJ := $(BUILD_DIR)/lota_lsm.bpf.o
SDK_LIB := $(BUILD_DIR)/liblotagaming.so
SDK_STATIC := $(BUILD_DIR)/liblotagaming.a
SERVER_SDK_LIB := $(BUILD_DIR)/liblotaserver.so
SERVER_SDK_STATIC := $(BUILD_DIR)/liblotaserver.a

# Compiler flags
CFLAGS := -Wall -Wextra -Werror -O2 -g
CFLAGS += -I$(INC_DIR)
CFLAGS += -D_GNU_SOURCE
CFLAGS += -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fPIE
CFLAGS += -Wformat -Wformat-security

# Linker hardening
HARDENING_LDFLAGS := -Wl,-z,relro,-z,now

# Agent link flags
LDFLAGS := -pie $(HARDENING_LDFLAGS)
LDFLAGS += -lbpf -ltss2-esys -ltss2-tcti-device -lcrypto -lssl -lsystemd

# Detect architecture from compiler if not specified
ifndef ARCH
	HOST_ARCH := $(shell $(CC) -dumpmachine | cut -d- -f1)
	ARCH := $(HOST_ARCH)
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
BPF_CFLAGS := -target bpf -g -O2
BPF_CFLAGS += -D__TARGET_ARCH_$(BPF_ARCH)
BPF_CFLAGS += -D__BPF_PROGRAM__
BPF_CFLAGS += -I$(INC_DIR)

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
              $(AGENT_DIR)/policy.c \
              $(AGENT_DIR)/policy_sign.c \

# Agent main source files
AGENT_SRCS := $(AGENT_DIR)/main.c \
			  $(AGENT_DIR)/main_utils.c \
			  $(AGENT_DIR)/reload.c \
			  $(AGENT_DIR)/test_servers.c \
              $(AGENT_DIR)/tpm.c \
              $(AGENT_DIR)/iommu.c \
              $(AGENT_DIR)/bpf_loader.c \
              $(AGENT_DIR)/net.c \
              $(AGENT_DIR)/ipc.c \
              $(AGENT_DIR)/report.c \
              $(AGENT_DIR)/hash_verify.c \
              $(AGENT_DIR)/daemon.c \
              $(AGENT_DIR)/policy.c \
              $(AGENT_DIR)/policy_sign.c \
              $(AGENT_DIR)/config.c \
              $(AGENT_DIR)/steam_runtime.c \
              $(AGENT_DIR)/dbus.c \
              $(AGENT_DIR)/sdnotify.c \
              $(AGENT_DIR)/journal.c \
              $(AGENT_DIR)/selftest.c \
              $(AGENT_DIR)/event.c \
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
all: $(AGENT_BIN) $(BPF_OBJ) $(VERIFIER_BIN) $(SDK_LIB) $(SERVER_SDK_LIB) $(WINE_HOOK_LIB) $(ANTICHEAT_LIB)

# build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/agent

# build agent binary
$(AGENT_BIN): $(AGENT_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built: $@"

# compile agent
$(BUILD_DIR)/agent/%.o: $(AGENT_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# compile SDK
$(BUILD_DIR)/sdk/%.o: $(SDK_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

# build SDK shared library
$(SDK_LIB): $(SDK_OBJS) | $(BUILD_DIR)
	$(CC) -shared -Wl,-soname,$(notdir $@) $(HARDENING_LDFLAGS) -o $@ $^
	@echo "Built: $@"

# build SDK static library
$(SDK_STATIC): $(SDK_OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $^
	@echo "Built: $@"

# build server SDK shared library
$(SERVER_SDK_LIB): $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(CC) -shared -Wl,-soname,$(notdir $@) $(HARDENING_LDFLAGS) -o $@ $^ -lcrypto
	@echo "Built: $@"

# build server SDK static library
$(SERVER_SDK_STATIC): $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $^
	@echo "Built: $@"

# build Wine/Proton hook (self-contained: includes gaming SDK)
$(WINE_HOOK_LIB): $(WINE_HOOK_OBJS) $(SDK_OBJS) | $(BUILD_DIR)
	$(CC) -shared -Wl,-soname,$(notdir $@) $(HARDENING_LDFLAGS) -o $@ $^ -lpthread
	@echo "Built: $@"

# build anti-cheat compatibility layer (includes gaming + server SDK)
$(ANTICHEAT_LIB): $(ANTICHEAT_OBJS) $(SDK_OBJS) $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(CC) -shared -Wl,-soname,$(notdir $@) $(HARDENING_LDFLAGS) -o $@ $^ -lcrypto
	@echo "Built: $@"

# build bpf program
$(BPF_OBJ): $(BPF_DIR)/lota_lsm.bpf.c $(INC_DIR)/vmlinux.h $(INC_DIR)/lota.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<
	@echo "Built: $@"

# generate vmlinux.h from running kernel btf
$(INC_DIR)/vmlinux.h:
	@echo "Generating vmlinux.h from kernel BTF..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "Generated: $@"

# Phony targets
.PHONY: bpf agent verifier sdk server-sdk wine-hook anticheat clean install test

bpf: $(BPF_OBJ)

agent: $(AGENT_BIN)

verifier: $(VERIFIER_BIN)

sdk: $(SDK_LIB) $(SDK_STATIC)

server-sdk: $(SERVER_SDK_LIB) $(SERVER_SDK_STATIC)

wine-hook: $(WINE_HOOK_LIB)

anticheat: $(ANTICHEAT_LIB)

# Go verifier
$(VERIFIER_BIN): $(wildcard $(SRC_DIR)/verifier/*.go $(SRC_DIR)/verifier/**/*.go) | $(BUILD_DIR)
	cd $(SRC_DIR)/verifier && go build -o ../../$@ .
	@echo "Built: $@"

clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

# Install to system (requires root)
install: all
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib/lota
	install -d $(DESTDIR)/usr/lib64
	install -d $(DESTDIR)/usr/include/lota
	install -d $(DESTDIR)/var/lib/lota/aiks
	install -m 755 $(AGENT_BIN) $(DESTDIR)/usr/bin/
	install -m 755 $(VERIFIER_BIN) $(DESTDIR)/usr/bin/
	install -m 644 $(BPF_OBJ) $(DESTDIR)/usr/lib/lota/
	install -m 755 $(SDK_LIB) $(DESTDIR)/usr/lib64/
	install -m 755 $(SERVER_SDK_LIB) $(DESTDIR)/usr/lib64/
	install -m 755 $(WINE_HOOK_LIB) $(DESTDIR)/usr/lib64/
	install -m 755 $(ANTICHEAT_LIB) $(DESTDIR)/usr/lib64/
	install -m 755 scripts/lota-proton-hook $(DESTDIR)/usr/bin/
	install -m 755 scripts/lota-steam-setup $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/etc/dbus-1/system.d
	install -m 644 dbus/org.lota.Agent1.conf $(DESTDIR)/etc/dbus-1/system.d/
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 644 systemd/lota-agent.service $(DESTDIR)/usr/lib/systemd/system/
	install -m 644 systemd/lota-agent.socket $(DESTDIR)/usr/lib/systemd/system/
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
	$(TEST_BIN_DIR)/test_steam_runtime \
	$(TEST_BIN_DIR)/test_wine_hook \
	$(TEST_BIN_DIR)/test_daemon \
	$(TEST_BIN_DIR)/test_tls_verify \
	$(TEST_BIN_DIR)/test_config \
	$(TEST_BIN_DIR)/test_subscribe \
	$(TEST_BIN_DIR)/test_policy_sign \
	$(TEST_BIN_DIR)/test_policy_export \
	$(TEST_BIN_DIR)/test_aik_rotation \
	$(TEST_BIN_DIR)/test_server_sdk \
	$(TEST_BIN_DIR)/sdk_demo \
	$(TEST_BIN_DIR)/lota_ipc_test \
	$(TEST_BIN_DIR)/cross_lang_verify \
	$(TEST_BIN_DIR)/test_anticheat \
	$(TEST_BIN_DIR)/test_ipc_dos \
	$(TEST_BIN_DIR)/test_loader_symbols \
	$(TEST_SDK_BIN)

$(TEST_SDK_BIN): tests/test_sdk_ipc.c $(SDK_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -llotagaming -Wl,-rpath,$(CURDIR)/$(BUILD_DIR)
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_hash_verify: tests/test_hash_verify.c $(AGENT_DIR)/hash_verify.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_dbus: tests/test_dbus.c $(AGENT_DIR)/dbus.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lsystemd
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_systemd: tests/test_systemd.c $(AGENT_DIR)/sdnotify.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lsystemd
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_steam_runtime: tests/test_steam_runtime.c $(AGENT_DIR)/steam_runtime.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lsystemd
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_wine_hook: tests/test_wine_hook.c $(SDK_DIR)/lota_gaming.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DLOTA_HOOK_TESTING -o $@ $^ -lpthread
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_daemon: tests/test_daemon.c $(AGENT_DIR)/daemon.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_tls_verify: tests/test_tls_verify.c $(AGENT_DIR)/net.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -lsystemd
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_config: tests/test_config.c $(AGENT_DIR)/config.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_subscribe: tests/test_subscribe.c $(SDK_DIR)/lota_gaming.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_policy_sign: tests/test_policy_sign.c $(AGENT_DIR)/policy_sign.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_policy_export: tests/test_policy_export.c $(AGENT_DIR)/policy.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_aik_rotation: tests/test_aik_rotation.c $(AGENT_DIR)/tpm.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -ltss2-esys -ltss2-tcti-device -lcrypto -lssl
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_server_sdk: tests/test_server_sdk.c $(SDK_DIR)/lota_server.c $(SDK_DIR)/lota_gaming.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
	@echo "Built: $@"

$(TEST_BIN_DIR)/sdk_demo: tests/sdk_demo.c $(SDK_DIR)/lota_gaming.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_anticheat: tests/test_anticheat.c $(SDK_DIR)/lota_anticheat.c $(SDK_DIR)/lota_gaming.c $(SDK_DIR)/lota_server.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
	@echo "Built: $@"

$(TEST_BIN_DIR)/lota_ipc_test: tests/lota_ipc_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
	@echo "Built: $@"

$(TEST_BIN_DIR)/cross_lang_verify: tests/cross_lang_verify.c $(SERVER_SDK_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -llotaserver -Wl,-rpath,$(CURDIR)/$(BUILD_DIR) -lcrypto
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_ipc_dos: tests/test_ipc_dos.c $(SDK_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -llotagaming -Wl,-rpath,$(CURDIR)/$(BUILD_DIR)
	@echo "Built: $@"

$(TEST_BIN_DIR)/test_loader_symbols: tests/test_loader_symbols.c $(AGENT_DIR)/bpf_loader.c $(AGENT_DIR)/journal.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^ -lbpf -lsystemd
	@echo "Built: $@"

# Full test suite (unit + integration + hardware)
# Note: hardware tests require root. Run 'sudo make test-hardware' for them.
test: test-unit

test-unit: all $(TEST_BINS)
	@echo "=== Running unit tests ==="
	@./build/test_hash_verify
	@./build/test_dbus
	@./build/test_systemd
	@./build/test_steam_runtime
	@./build/test_wine_hook
	@./build/test_daemon
	@./build/test_config
	@./build/test_subscribe
	@./build/test_policy_sign
	@./build/test_policy_export
	@./build/test_aik_rotation
	@./build/test_server_sdk
	@./build/test_anticheat
	@./build/test_loader_symbols
	@echo ""
	@echo "=== Running integration tests (best effort) ==="
	@if [ -S /run/lota/lota.sock ]; then \
		./build/test_sdk_ipc; \
		./build/lota_ipc_test status; \
		./build/sdk_demo; \
	else \
		echo "SKIP: SDK/IPC tests (agent socket not found)"; \
	fi
	@if [ -n "$$LOTA_RUN_TLS_TESTS" ]; then \
		./build/test_tls_verify; \
	elif [ -f /tmp/lota-tls-test/ca.pem ]; then \
		if command -v ss >/dev/null 2>&1; then \
			if ss -lnt | grep -q ":9443 "; then ./build/test_tls_verify /tmp/lota-tls-test/ca.pem; else echo "SKIP: test_tls_verify (no server on 9443)"; fi; \
		elif command -v nc >/dev/null 2>&1; then \
			if nc -z 127.0.0.1 9443; then ./build/test_tls_verify /tmp/lota-tls-test/ca.pem; else echo "SKIP: test_tls_verify (no server on 9443)"; fi; \
		else \
			echo "SKIP: test_tls_verify (no ss/nc to check server)"; \
		fi; \
	else \
		echo "SKIP: test_tls_verify (missing /tmp/lota-tls-test/ca.pem)"; \
	fi
	@if command -v go >/dev/null 2>&1; then \
		cd $(SRC_DIR)/sdk/server && go run ../../../tests/cross_lang_gen.go && \
		cd $(CURDIR) && ./build/cross_lang_verify; \
	else \
		echo "SKIP: cross_lang_gen (go not installed)"; \
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
	@echo "Start agent in another terminal: sudo ./build/lota-agent --test-ipc"
	@echo "Then run: ./build/test_sdk_ipc"

# Fuzzing
FUZZ_CFLAGS := $(CFLAGS) -fsanitize=fuzzer,address -g -O1
FUZZ_LDFLAGS := $(LDFLAGS) -fsanitize=fuzzer,address

FUZZ_AGENT_OBJS := $(filter-out $(BUILD_DIR)/agent/main.o $(BUILD_DIR)/agent/ipc.o $(BUILD_DIR)/agent/reload.o $(BUILD_DIR)/agent/test_servers.o, $(AGENT_OBJS))
FUZZ_AGENT_OBJS += $(BUILD_DIR)/agent/fuzz/ipc_fuzz.o

$(BUILD_DIR)/agent/fuzz/ipc_fuzz.o: src/agent/fuzz/ipc_fuzz.c | $(BUILD_DIR)/agent/fuzz
	clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/agent/fuzz:
	mkdir -p $@

fuzz-agent: $(FUZZ_AGENT_OBJS)
	clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-agent $(FUZZ_AGENT_OBJS) $(LDFLAGS)

# Config parser fuzz (standalone, libc only)
$(BUILD_DIR)/agent/fuzz/config_fuzz.o: src/agent/fuzz/config_fuzz.c src/agent/config.h | $(BUILD_DIR)/agent/fuzz
	clang $(FUZZ_CFLAGS) -I$(INC_DIR) -c $< -o $@

$(BUILD_DIR)/agent/fuzz/config_obj.o: src/agent/config.c src/agent/config.h | $(BUILD_DIR)/agent/fuzz
	clang $(FUZZ_CFLAGS) -I$(INC_DIR) -DLOTA_TPM_H -DTPM_AIK_HANDLE=0x81010002 -c $< -o $@

fuzz-config: $(BUILD_DIR)/agent/fuzz/config_fuzz.o $(BUILD_DIR)/agent/fuzz/config_obj.o
	clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-config $^

# Net pin SHA-256 parser fuzz (standalone, libc only)
$(BUILD_DIR)/agent/fuzz/net_pin_fuzz.o: src/agent/fuzz/net_pin_fuzz.c | $(BUILD_DIR)/agent/fuzz
	clang $(FUZZ_CFLAGS) -c $< -o $@

fuzz-net-pin: $(BUILD_DIR)/agent/fuzz/net_pin_fuzz.o
	clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-net-pin $^

# Net wire protocol parser fuzz (standalone, libc only)
$(BUILD_DIR)/agent/fuzz/net_wire_fuzz.o: src/agent/fuzz/net_wire_fuzz.c | $(BUILD_DIR)/agent/fuzz
	clang $(FUZZ_CFLAGS) -c $< -o $@

fuzz-net-wire: $(BUILD_DIR)/agent/fuzz/net_wire_fuzz.o
	clang $(FUZZ_CFLAGS) -o $(BUILD_DIR)/fuzz-net-wire $^

# Build all fuzz targets
.PHONY: fuzz-all
fuzz-all: fuzz-agent fuzz-config fuzz-net-pin fuzz-net-wire

# Help target
.PHONY: help
help:
	@echo "LOTA Makefile targets:"
	@echo "  all        - Build agent, verifier, SDKs and BPF program (default)"
	@echo "  bpf        - Build only BPF program"
	@echo "  agent      - Build only user-space agent"
	@echo "  verifier   - Build only Go verifier"
	@echo "  sdk        - Build only gaming SDK library"
	@echo "  server-sdk - Build only server-side verification SDK"
	@echo "  wine-hook  - Build only Wine/Proton LD_PRELOAD hook"
	@echo "  anticheat  - Build only anti-cheat compatibility layer"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to /usr (requires root)"
	@echo "  test       - Run basic unit tests"
	@echo "  test-hardware - Run hardware tests (requires root/sudo)"
	@echo ""
	@echo "Prerequisites (Fedora):"
	@echo "  sudo dnf install clang llvm libbpf-devel tpm2-tss-devel openssl-devel bpftool golang"
