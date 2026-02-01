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
BPF_OBJ := $(BUILD_DIR)/lota_lsm.bpf.o

# Compiler flags
CFLAGS := -Wall -Wextra -Werror -O2 -g
CFLAGS += -I$(INC_DIR)
CFLAGS += -D_GNU_SOURCE

# Libraries for agent
LDFLAGS := -lbpf -ltss2-esys -ltss2-tcti-device -lcrypto

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
              $(AGENT_DIR)/bpf_loader.c

AGENT_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(AGENT_SRCS))

# Default target
.PHONY: all
all: $(AGENT_BIN) $(BPF_OBJ)

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
.PHONY: bpf agent clean install test

bpf: $(BPF_OBJ)

agent: $(AGENT_BIN)

clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts"

# Install to system (requires root)
install: all
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib/lota
	install -m 755 $(AGENT_BIN) $(DESTDIR)/usr/bin/
	install -m 644 $(BPF_OBJ) $(DESTDIR)/usr/lib/lota/
	@echo "Installed to $(DESTDIR)/usr"

# Basic tests (requires root for TPM/BPF)
test: all
	@echo "=== Testing IOMMU verification ==="
	sudo $(AGENT_BIN) --test-iommu
	@echo ""
	@echo "=== Testing TPM operations ==="
	sudo $(AGENT_BIN) --test-tpm
	@echo ""
	@echo "Tests complete"

# Help target
.PHONY: help
help:
	@echo "LOTA Makefile targets:"
	@echo "  all      - Build agent and BPF program (default)"
	@echo "  bpf      - Build only BPF program"
	@echo "  agent    - Build only user-space agent"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr (requires sudo)"
	@echo "  test     - Run basic tests (requires sudo)"
	@echo ""
	@echo "Prerequisites (Fedora):"
	@echo "  sudo dnf install clang llvm libbpf-devel tpm2-tss-devel openssl-devel bpftool"
