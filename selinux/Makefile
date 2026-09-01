# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Szymon Wilczek
#
# LOTA SELinux policy build system
#

SHELL := /bin/bash

# Policy modules
MODULES := lota lota_gaming

# Derived file lists
TE_FILES := $(addsuffix .te,$(MODULES))
IF_FILES := $(addsuffix .if,$(filter lota,$(MODULES)))
FC_FILES := $(addsuffix .fc,$(filter lota,$(MODULES)))
PP_FILES := $(addsuffix .pp,$(MODULES))

# SELinux development paths (Fedora/RHEL currently)
SELINUX_DEVEL := /usr/share/selinux/devel
SELINUX_MAKEFILE := $(SELINUX_DEVEL)/Makefile

# Installation paths
SELINUX_MODULE_DIR := /usr/share/selinux/packages

# Port to label lota_port_t. Empty by default: only the fleet knows which
# port its CA or verifier answers on. lota-install labels the endpoints it
# is given, and the agent prints the semanage command for one added later.
#
#   sudo make install LOTA_PORT=8573
#
# A port the base policy names by number (8443 is http_port_t) is left
# alone: a local record would take it from every confined service.
LOTA_PORT :=
LOTA_PORT_PROTO := tcp

# File paths for restorecon
LOTA_PATHS := \
	/usr/bin/lota-agent \
	/usr/sbin/lota-agent \
	/usr/lib/lota \
	/usr/lib64/lota \
	/etc/lota \
	/var/lib/lota \
	/var/log/lota \
	/run/lota

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

#
# Default target: build policy modules
#
.PHONY: all
all: check-deps $(PP_FILES)
	@echo -e "$(GREEN)Build complete.$(NC)"
	@echo "Run 'sudo make install' to install the policy."

#
# Check for required tools
#
.PHONY: check-deps
check-deps:
	@echo -e "$(BLUE)Checking dependencies...$(NC)"
	@test -f $(SELINUX_MAKEFILE) || \
		(echo -e "$(RED)Error: SELinux development files not found.$(NC)"; \
		 echo "Install with: sudo dnf install selinux-policy-devel"; \
		 exit 1)
	@command -v semodule >/dev/null || \
		(echo -e "$(RED)Error: semodule not found.$(NC)"; \
		 echo "Install with: sudo dnf install policycoreutils"; \
		 exit 1)
	@command -v restorecon >/dev/null || \
		(echo -e "$(RED)Error: restorecon not found.$(NC)"; \
		 echo "Install with: sudo dnf install policycoreutils"; \
		 exit 1)
	@echo -e "$(GREEN)Dependencies OK.$(NC)"

#
# Build policy modules using SELinux devel Makefile
#
%.pp: %.te
	@echo -e "$(BLUE)Building $@...$(NC)"
	$(MAKE) -f $(SELINUX_MAKEFILE) $@

#
# lota_gaming depends on lota
#
lota_gaming.pp: lota.pp

#
# Install policy modules
#
.PHONY: install
install: all
	@echo -e "$(BLUE)Installing LOTA SELinux policy...$(NC)"
	@test $$(id -u) -eq 0 || \
		(echo -e "$(RED)Error: Must run as root.$(NC)"; exit 1)

	@echo "Installing policy modules..."
	semodule -i lota.pp
	semodule -i lota_gaming.pp

	@# semanage port -a accepts a port another type owns and shadows it for
	@# every domain, so look up the owner first. A record naming this port
	@# (8443 is http_port_t) is left alone; a span such as unreserved_port_t
	@# is labelled out of, and the message names the span.
	@if [ -z "$(LOTA_PORT)" ]; then \
		echo "No port to label (pass LOTA_PORT=<port> to label one)."; \
	else \
		owner=$$(semanage port -l | awk -v p='$(LOTA_PORT)' -v pr='$(LOTA_PORT_PROTO)' \
			'$$2 == pr { \
				for (i = 3; i <= NF; i++) { \
					gsub(/,/, "", $$i); \
					if ($$i == p) { print "named", $$1; exit } \
					n = split($$i, r, "-"); \
					if (n == 2 && p >= r[1] && p <= r[2]) { \
						span = "range " $$1; \
					} \
				} \
			} \
			END { if (span != "") print span }'); \
		kind=$${owner%% *}; type=$${owner##* }; \
		if [ "$$type" = "lota_port_t" ] && [ "$$kind" = "named" ]; then \
			echo "Port $(LOTA_PORT)/$(LOTA_PORT_PROTO) already carries lota_port_t."; \
		elif [ "$$kind" = "named" ]; then \
			echo -e "$(YELLOW)Port $(LOTA_PORT)/$(LOTA_PORT_PROTO) is defined as $$type. Leaving it alone: a local record would shadow that for every domain on this host, not only for LOTA. lota_agent_t may be allowed to reach $$type already; where it may not, choose a port no type names.$(NC)"; \
		elif semanage port -a -t lota_port_t -p $(LOTA_PORT_PROTO) $(LOTA_PORT); then \
			echo "Labelled $(LOTA_PORT)/$(LOTA_PORT_PROTO) lota_port_t$${type:+ (out of the $$type range)}."; \
		fi; \
	fi

	@echo "Creating directories..."
	mkdir -p /etc/lota/policies
	mkdir -p /etc/lota/ca
	mkdir -p /var/lib/lota/aik
	mkdir -p /var/lib/lota/baseline
	mkdir -p /var/log/lota
	mkdir -p /run/lota
	mkdir -p /usr/lib/lota

	@echo "Applying file contexts..."
	@for path in $(LOTA_PATHS); do \
		if [ -e "$$path" ]; then \
			restorecon -Rv "$$path"; \
		fi; \
	done

	@echo -e "$(GREEN)Installation complete.$(NC)"
	@echo ""
	@echo "LOTA SELinux policy installed. Next steps:"
	@echo "  1. Copy lota-agent binary to /usr/bin/"
	@echo "  2. Copy BPF object to /usr/lib/lota/"
	@echo "  3. Create config in /etc/lota/"
	@echo "  4. Run: restorecon -Rv /usr/bin/lota-agent /usr/lib/lota /etc/lota"
	@echo ""
	@echo "Tunables (adjust with setsebool):"
	@echo "  lota_network_attest   - Network attestation (default: on)"
	@echo "  lota_bpf_load         - BPF program loading (default: on)"
	@echo "  lota_module_enforce   - Module enforcement (default: off)"
	@echo "  lota_steam_attest     - Steam integration (default: on)"
	@echo "  lota_wine_attest      - Wine/Proton integration (default: on)"

#
# Uninstall policy modules
#
.PHONY: uninstall
uninstall:
	@echo -e "$(BLUE)Uninstalling LOTA SELinux policy...$(NC)"
	@test $$(id -u) -eq 0 || \
		(echo -e "$(RED)Error: Must run as root.$(NC)"; exit 1)

	@# modules
	-semodule -r lota_gaming 2>/dev/null || true
	-semodule -r lota 2>/dev/null || true

	@# remove port definition
	@if [ -n "$(LOTA_PORT)" ]; then \
		semanage port -d -t lota_port_t -p $(LOTA_PORT_PROTO) $(LOTA_PORT) 2>/dev/null || true; \
	fi

	@echo -e "$(GREEN)Uninstall complete.$(NC)"

#
# Reload (uninstall + install)
#
.PHONY: reload
reload: uninstall install

#
# Check policy syntax
#
.PHONY: check
check: check-deps
	@echo -e "$(BLUE)Checking policy syntax...$(NC)"
	@for te in $(TE_FILES); do \
		echo "  Checking $$te..."; \
		$(MAKE) -f $(SELINUX_MAKEFILE) $$te 2>&1 | head -20 || exit 1; \
	done
	@echo -e "$(GREEN)Syntax check passed.$(NC)"

#
# Verify installed policy
#
.PHONY: verify
verify:
	@echo -e "$(BLUE)Verifying installed policy...$(NC)"
	@semodule -l | grep -q "^lota" && \
		echo -e "$(GREEN)lota module: installed$(NC)" || \
		echo -e "$(RED)lota module: NOT installed$(NC)"
	@semodule -l | grep -q "^lota_gaming" && \
		echo -e "$(GREEN)lota_gaming module: installed$(NC)" || \
		echo -e "$(RED)lota_gaming module: NOT installed$(NC)"
	@semanage port -l | grep -q "lota_port_t" && \
		echo -e "$(GREEN)lota_port_t: configured$(NC)" || \
		echo -e "$(YELLOW)lota_port_t: not configured$(NC)"
	@echo ""
	@echo "Tunables status:"
	@getsebool lota_network_attest 2>/dev/null || echo "  lota_network_attest: (not available)"
	@getsebool lota_bpf_load 2>/dev/null || echo "  lota_bpf_load: (not available)"
	@getsebool lota_module_enforce 2>/dev/null || echo "  lota_module_enforce: (not available)"
	@getsebool lota_steam_attest 2>/dev/null || echo "  lota_steam_attest: (not available)"
	@getsebool lota_wine_attest 2>/dev/null || echo "  lota_wine_attest: (not available)"

#
# Show AVC denials related to LOTA
#
.PHONY: audit
audit:
	@echo -e "$(BLUE)Recent LOTA-related AVC denials:$(NC)"
	@ausearch -m avc -ts recent 2>/dev/null | grep -E 'lota|steam|wine|games' || \
		echo "No recent denials found."

#
# Generate audit2allow suggestions
#
.PHONY: suggest
suggest:
	@echo -e "$(BLUE)Generating policy suggestions from audit log...$(NC)"
	@ausearch -m avc -ts today 2>/dev/null | grep -E 'lota|steam|wine|games' | \
		audit2allow -m lota_local 2>/dev/null || \
		echo "No suggestions (no denials found)."

#
# Clean build artifacts
#
.PHONY: clean
clean:
	@echo -e "$(BLUE)Cleaning build artifacts...$(NC)"
	rm -f *.pp
	rm -f tmp/*.mod tmp/*.mod.fc
	rm -rf tmp/
	@echo -e "$(GREEN)Clean complete.$(NC)"

#
# Help
#
.PHONY: help
help:
	@echo "LOTA SELinux Policy Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build policy modules (default)"
	@echo "  install    - Install modules (requires root)"
	@echo "  uninstall  - Remove modules (requires root)"
	@echo "  reload     - Reinstall modules"
	@echo "  check      - Verify policy syntax"
	@echo "  verify     - Check installation status"
	@echo "  audit      - Show recent AVC denials"
	@echo "  suggest    - Generate policy suggestions from audit"
	@echo "  clean      - Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  LOTA_PORT  - port for install to label lota_port_t (default: none)"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build policy"
	@echo "  sudo make install       # Install policy"
	@echo "  sudo make reload        # Reinstall after changes"
	@echo "  sudo make audit         # Debug denials"
