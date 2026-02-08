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

# Libraries for agent
LDFLAGS := -lbpf -ltss2-esys -ltss2-tcti-device -lcrypto -lssl

# BPF compilation flags
# -target bpf: Generate BPF bytecode
# -g: Include debug info
# -O2: Optimization level (for BPF verifier)
BPF_CFLAGS := -target bpf -g -O2
BPF_CFLAGS += -D__TARGET_ARCH_x86
BPF_CFLAGS += -D__BPF_PROGRAM__
BPF_CFLAGS += -I$(INC_DIR)

# Detect kernel architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Agent source files
AGENT_SRCS := $(AGENT_DIR)/main.c \
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
              $(AGENT_DIR)/config.c

AGENT_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(AGENT_SRCS))

# SDK source files
SDK_DIR := $(SRC_DIR)/sdk
SDK_SRCS := $(SDK_DIR)/lota_gaming.c
SDK_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SDK_SRCS))

# Server SDK source files
SERVER_SDK_SRCS := $(SDK_DIR)/lota_server.c
SERVER_SDK_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SERVER_SDK_SRCS))

# Default target
.PHONY: all
all: $(AGENT_BIN) $(BPF_OBJ) $(VERIFIER_BIN) $(SDK_LIB) $(SERVER_SDK_LIB)

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
	$(CC) -shared -o $@ $^
	@echo "Built: $@"

# build SDK static library
$(SDK_STATIC): $(SDK_OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $^
	@echo "Built: $@"

# build server SDK shared library
$(SERVER_SDK_LIB): $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(CC) -shared -o $@ $^ -lcrypto
	@echo "Built: $@"

# build server SDK static library
$(SERVER_SDK_STATIC): $(SERVER_SDK_OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $^
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
.PHONY: bpf agent verifier sdk server-sdk clean install test

bpf: $(BPF_OBJ)

agent: $(AGENT_BIN)

verifier: $(VERIFIER_BIN)

sdk: $(SDK_LIB) $(SDK_STATIC)

server-sdk: $(SERVER_SDK_LIB) $(SERVER_SDK_STATIC)

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
	install -m 644 $(INC_DIR)/lota_gaming.h $(DESTDIR)/usr/include/lota/
	install -m 644 $(INC_DIR)/lota_server.h $(DESTDIR)/usr/include/lota/
	install -m 644 $(INC_DIR)/lota_ipc.h $(DESTDIR)/usr/include/lota/
	@echo "Installed to $(DESTDIR)/usr"

# Build test binary
TEST_SDK_BIN := $(BUILD_DIR)/test_sdk_ipc

$(TEST_SDK_BIN): tests/test_sdk_ipc.c $(SDK_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -llotagaming -Wl,-rpath,$(CURDIR)/$(BUILD_DIR)
	@echo "Built: $@"

# Basic tests (requires root for TPM/BPF)
test: all $(TEST_SDK_BIN)
	@echo "=== Testing IOMMU verification ==="
	sudo $(AGENT_BIN) --test-iommu
	@echo ""
	@echo "=== Testing TPM operations ==="
	sudo $(AGENT_BIN) --test-tpm
	@echo ""
	@echo "Tests complete"

test-sdk: $(TEST_SDK_BIN) $(SDK_LIB) $(AGENT_BIN)
	@echo "=== SDK Integration Test ==="
	@echo "Start agent in another terminal: sudo ./build/lota-agent --test-ipc"
	@echo "Then run: ./build/test_sdk_ipc"

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
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install to /usr (requires sudo)"
	@echo "  test       - Run basic tests (requires sudo)"
	@echo ""
	@echo "Prerequisites (Fedora):"
	@echo "  sudo dnf install clang llvm libbpf-devel tpm2-tss-devel openssl-devel bpftool golang"
