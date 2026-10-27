# SPDX-License-Identifier: MIT
#
# Optional system dependencies (SDL2, libcurl) for the reference builds.
# `make examples` stops at the first failing fragment, so a fragment must
# skip itself when its packages are missing. It sets LOTA_OPTIONAL_PKGS,
# includes this file and reads LOTA_OPTIONAL_OK:
#
#	LOTA_OPTIONAL_PKGS := libcurl
#	include ../optional-deps.mk
#
#	ifeq ($(LOTA_OPTIONAL_OK),yes)
#	...build...
#	else
#	all:
#		@echo "SKIP: thing (install libcurl-devel)"
#	endif
#
# Enforced by tests/integration/test_examples_optional_deps.sh.

LOTA_OPTIONAL_OK := $(shell pkg-config --exists $(LOTA_OPTIONAL_PKGS) && echo yes)
