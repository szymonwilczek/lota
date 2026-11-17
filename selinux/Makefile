# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Szymon Wilczek

SHELL := /bin/bash

MODULES := lota

TE_FILES := $(addsuffix .te,$(MODULES))
IF_FILES := $(addsuffix .if,$(filter lota,$(MODULES)))
FC_FILES := $(addsuffix .fc,$(filter lota,$(MODULES)))
PP_FILES := $(addsuffix .pp,$(MODULES))

# '.' matches gen_tunable's '(': a bare one would close $(shell ...) early.
TUNABLES := $(shell sed -n 's/^gen_tunable.\([a-z_]*\),.*/\1/p' $(TE_FILES))

SELINUX_DEVEL := /usr/share/selinux/devel
SELINUX_MAKEFILE := $(SELINUX_DEVEL)/Makefile

# lota.if goes where the devel Makefile resolves interfaces for other modules
SELINUX_MODULE_DIR := /usr/share/selinux/packages
SELINUX_INTERFACE_DIR := $(SELINUX_DEVEL)/include/contrib

# Port install labels lota_port_t; none by default:
#
#   sudo make install LOTA_PORT=8573
LOTA_PORT :=
LOTA_PORT_PROTO := tcp

LOTA_PATHS := \
	/usr/bin/lota-agent \
	/usr/sbin/lota-agent \
	/usr/lib/lota \
	/usr/lib64/lota \
	/etc/lota \
	/var/lib/lota \
	/run/lota

RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

.PHONY: all
all: check-deps $(PP_FILES)
	@echo -e "$(GREEN)Build complete.$(NC)"
	@echo "Run 'sudo make install' to install the policy."

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

%.pp: %.te
	@echo -e "$(BLUE)Building $@...$(NC)"
	$(MAKE) -f $(SELINUX_MAKEFILE) $@

.PHONY: install
install: all
	@echo -e "$(BLUE)Installing LOTA SELinux policy...$(NC)"
	@test $$(id -u) -eq 0 || \
		(echo -e "$(RED)Error: Must run as root.$(NC)"; exit 1)

	@echo "Installing policy modules..."
	semodule -i lota.pp

	@echo "Installing policy packages and interfaces..."
	install -d $(SELINUX_MODULE_DIR)
	install -m 0644 $(PP_FILES) $(SELINUX_MODULE_DIR)/
	@# other modules find lota.if only in the devel include tree
	@if [ -d $(SELINUX_DEVEL)/include ]; then \
		install -d $(SELINUX_INTERFACE_DIR); \
		install -m 0644 $(IF_FILES) $(SELINUX_INTERFACE_DIR)/; \
		echo "  interfaces: $(SELINUX_INTERFACE_DIR)/$(IF_FILES)"; \
	else \
		echo -e "$(YELLOW)  interfaces: $(SELINUX_DEVEL)/include is absent, so lota.if was not installed. A module calling lota_query_status() and the other documented interfaces needs it: install selinux-policy-devel and re-run, or copy lota.if there by hand.$(NC)"; \
	fi

	@# semanage port -a would shadow another type's port for every domain:
	@# a port a type names is left alone, one inside a range is labelled.
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
	@for bool in $(TUNABLES); do \
		echo "  $$(getsebool $$bool)"; \
	done

.PHONY: uninstall
uninstall:
	@echo -e "$(BLUE)Uninstalling LOTA SELinux policy...$(NC)"
	@test $$(id -u) -eq 0 || \
		(echo -e "$(RED)Error: Must run as root.$(NC)"; exit 1)

	@# Drop the local lota_port_t records while the type still exists:
	@# left behind, they name a missing type and return on reinstall.
	@if command -v semanage >/dev/null 2>&1; then \
		semanage port -l -C 2>/dev/null | \
		awk '$$1 == "lota_port_t" { \
			proto = $$2; \
			for (i = 3; i <= NF; i++) { \
				gsub(/,/, "", $$i); \
				if ($$i != "") print proto, $$i; \
			} \
		}' | \
		while read -r proto port; do \
			echo "  unlabelling $$port/$$proto"; \
			semanage port -d -t lota_port_t -p "$$proto" "$$port" \
				2>/dev/null || true; \
		done; \
	fi

	-semodule -r lota 2>/dev/null || true

	rm -f $(addprefix $(SELINUX_MODULE_DIR)/,$(PP_FILES))
	rm -f $(addprefix $(SELINUX_INTERFACE_DIR)/,$(IF_FILES))

	@echo -e "$(GREEN)Uninstall complete.$(NC)"

.PHONY: reload
reload: uninstall install

.PHONY: check
check: check-deps
	@echo -e "$(BLUE)Checking policy syntax...$(NC)"
	@# Build each .pp: asking for the .te is a no-op that always passes.
	@# Output is captured first so the build's status, not tail's, decides.
	@rc=0; \
	for te in $(TE_FILES); do \
		echo "  Checking $$te..."; \
		if ! out=$$($(MAKE) -f $(SELINUX_MAKEFILE) $${te%.te}.pp 2>&1); then \
			printf '%s\n' "$$out" | tail -20; \
			rc=1; \
		fi; \
	done; \
	if [ $$rc -ne 0 ]; then \
		echo -e "$(RED)Syntax check failed.$(NC)"; \
		exit 1; \
	fi
	@echo -e "$(GREEN)Syntax check passed.$(NC)"

.PHONY: verify
verify:
	@echo -e "$(BLUE)Verifying installed policy...$(NC)"
	@semodule -l | grep -qx lota && \
		echo -e "$(GREEN)lota module: installed$(NC)" || \
		echo -e "$(RED)lota module: NOT installed$(NC)"
	@semanage port -l | grep -q "lota_port_t" && \
		echo -e "$(GREEN)lota_port_t: configured$(NC)" || \
		echo -e "$(YELLOW)lota_port_t: not configured$(NC)"
	@echo ""
	@echo "Tunables status:"
	@for bool in $(TUNABLES); do \
		getsebool $$bool 2>/dev/null || \
			echo "  $$bool: (not available)"; \
	done

.PHONY: audit
audit:
	@echo -e "$(BLUE)Recent LOTA-related AVC denials:$(NC)"
	@ausearch -m avc -ts recent 2>/dev/null | grep -E 'lota|steam|wine|games' || \
		echo "No recent denials found."

.PHONY: suggest
suggest:
	@echo -e "$(BLUE)Generating policy suggestions from audit log...$(NC)"
	@# Branch on the grep: audit2allow exits 0 even with nothing to suggest.
	@denials=$$(ausearch -m avc -ts today 2>/dev/null | \
		grep -E 'lota|steam|wine|games'); \
	if [ -n "$$denials" ]; then \
		printf '%s\n' "$$denials" | audit2allow -m lota_local; \
	else \
		echo "No suggestions (no denials found)."; \
	fi

.PHONY: clean
clean:
	@echo -e "$(BLUE)Cleaning build artifacts...$(NC)"
	rm -f *.pp
	rm -f tmp/*.mod tmp/*.mod.fc
	rm -rf tmp/
	@echo -e "$(GREEN)Clean complete.$(NC)"

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
