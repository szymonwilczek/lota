# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Configuration for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html
#
# Build locally with:  make -C Documentation html
# CI builds with warnings promoted to errors (see SPHINXOPTS in the Makefile)

import os
import pathlib

# -- Project information ------------------------------------------------------

project = "LOTA"
author = "Szymon Wilczek"
copyright = "2026, Szymon Wilczek"  # noqa: A001 - Sphinx-reserved name

# Version shown on the site
# Deploy workflow passes the current release tag through LOTA_DOCS_VERSION
# so the hosted documentation states which tag it was built from.
# Local build falls back to the repository VERSION file.
_tag = os.environ.get("LOTA_DOCS_VERSION", "").strip()
if _tag:
    release = _tag.lstrip("v")
else:
    _version_file = pathlib.Path(__file__).resolve().parent.parent / "VERSION"
    release = (
        _version_file.read_text(encoding="utf-8").strip()
        if _version_file.is_file()
        else "0.0.0"
    )
version = release.split("-", 1)[0]  # X.Y.Z without any pre-release suffix

# -- General configuration ----------------------------------------------------

extensions: list[str] = []
source_suffix = {".rst": "restructuredtext"}
root_doc = "index"
language = "en"

# Documentation tree is Documentation/ only
# Component READMEs live next to the code they describe and are not
# part of this Sphinx project
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Technical documentation quotes shell commands and CLI flags verbatim
# Leave "--flag", "---", and quotes untouched so an option never renders
# as an en- or em-dash.
smartquotes = False

# Treat every reStructuredText problem as worth fixing
# Build itself is run with -W --keep-going (Makefile / CI) so these surface
# as hard failures.
nitpicky = False  # cross-file :doc: refs are validated, symbol nitpicking is noise here

# -- HTML output --------------------------------------------------------------

# Prefer the Read the Docs theme when it is installed
# (CI pins it in Documentation/requirements.txt)
try:
    import sphinx_rtd_theme  # noqa: F401

    html_theme = "sphinx_rtd_theme"
except ImportError:
    html_theme = "alabaster"

html_title = f"LOTA {release}"
html_static_path: list[str] = []
html_show_sourcelink = True

# Canonical URL of the hosted site (GitHub Pages on a custom subdomain).
html_baseurl = "https://lota.szymon-wilczek.me/"

# _extra/ is copied verbatim to the site root:
# it carries the GitHub Pages CNAME file that pins the custom domain on every deploy
html_extra_path = ["_extra"]

# -- Link checking ------------------------------------------------------------

# Source-tree links resolve to github.com/szymonwilczek/lota/blob/<ref>/...
# Their existence is owned by the repository itself and the internal :doc:/:ref: graph
# is already validated by the strict HTML build, so leave these out of the link check
linkcheck_ignore = [r"https://github\.com/szymonwilczek/lota/blob/"]
linkcheck_retries = 2
linkcheck_timeout = 15
