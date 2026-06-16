# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Makefile for Sphinx documentation

# Warnings are promoted to errors so a broken cross-reference, malformed
# directive, or document missing from the toctree fails the build.
# --keep-going reports every problem in one pass
SPHINXOPTS    ?= -W --keep-going
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

SERVE_PORT    ?= 8000

.PHONY: help html linkcheck lint serve clean Makefile

help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# build the HTML documentation (strict)
html:
	@$(SPHINXBUILD) -b html $(SPHINXOPTS) "$(SOURCEDIR)" "$(BUILDDIR)/html" $(O)
	@echo "Built HTML docs in $(BUILDDIR)/html/index.html"

# verify every external and internal link resolves
linkcheck:
	@$(SPHINXBUILD) -b linkcheck $(SPHINXOPTS) "$(SOURCEDIR)" "$(BUILDDIR)/linkcheck" $(O)

# style/markup lint over the reStructuredText sources (requires sphinx-lint)
# scan sources only; generated _build/ tree is not reStructuredText
lint:
	@find . -name '*.rst' -not -path './_build/*' -print0 \
		| xargs -0 python3 -m sphinxlint --enable all --disable line-too-long

# build, then serve the HTML locally for preview
# override with SERVE_PORT=NNNN
serve: html
	@echo "Serving docs at http://localhost:$(SERVE_PORT)/ (Ctrl-C to stop)"
	@python3 -m http.server "$(SERVE_PORT)" --directory "$(BUILDDIR)/html"

clean:
	@rm -rf "$(BUILDDIR)"

# catch-all: route any other target to sphinx-build's -M dispatcher
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
