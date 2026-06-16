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

# Channel this build serves
# LOTA_DOCS_CHANNEL selects the site:
#   stable -> released docs at the site root (tracks main)
#   dev    -> in-progress docs under /lota-next/ (tracks lota-next)
# Default: stable
channel = os.environ.get("LOTA_DOCS_CHANNEL", "").strip() or "stable"

# Version shown on the site
# Deploy workflow passes the label through LOTA_DOCS_VERSION: the release tag on
# the stable channel, "lota-next (<short-sha>)" on the development channel.
# Local build falls back to the repository VERSION file.
_tag = os.environ.get("LOTA_DOCS_VERSION", "").strip()
if _tag:
    release = _tag[1:] if _tag.startswith("v") else _tag
else:
    _version_file = pathlib.Path(__file__).resolve().parent.parent / "VERSION"
    release = (
        _version_file.read_text(encoding="utf-8").strip()
        if _version_file.is_file()
        else "0.0.0"
    )
# stable carries a semantic version
# dev label is free-form, keep it whole
version = release if channel == "dev" else release.split("-", 1)[0]

# Branch this build documents
# Deploy workflow sets LOTA_DOCS_REF per channel
# (main for the stable site, lota-next for the development site)
# so a source-tree link resolves against the branch the page is built from.
# Local builds default to main.
ref = os.environ.get("LOTA_DOCS_REF", "").strip() or "main"

# -- General configuration ----------------------------------------------------

extensions: list[str] = ["sphinx.ext.extlinks"]

# :ghsrc:`path/to/file` links a repository-relative path to its source on
# GitHub, pinned to the branch this build documents (see ref above)
# Detecting hardcoded blob links keeps a raw URL from slipping past the role
# under the strict build
extlinks = {
    "ghsrc": (f"https://github.com/szymonwilczek/lota/blob/{ref}/%s", "%s"),
}
extlinks_detect_hardcoded_links = True

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
templates_path = ["_templates"]

# Canonical URL of the hosted site (GitHub Pages on custom subdomain)
# Both channels point canonical at the stable root so the development pages
# under /lota-next/ defer to their released counterpart for search
html_baseurl = "https://lota.szymon-wilczek.me/"

# Channel context for the switcher, banner, and noindex (see _templates/layout.html)
_site = "https://lota.szymon-wilczek.me"
html_context = {
    "lota_channel": channel,
    "lota_stable_url": f"{_site}/",
    "lota_dev_url": f"{_site}/lota-next/",
}

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
