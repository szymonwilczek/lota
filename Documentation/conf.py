# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Configuration for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html
#
# Build locally with:  make -C Documentation html
# CI builds with warnings promoted to errors (see SPHINXOPTS in the Makefile)

import pathlib

# -- Project information ------------------------------------------------------

project = "LOTA"
author = "Szymon Wilczek"
copyright = "2026, Szymon Wilczek"  # noqa: A001 - Sphinx-reserved name

# single source of truth for the version: repository VERSION file
_version_file = pathlib.Path(__file__).resolve().parent.parent / "VERSION"
release = (
    _version_file.read_text(encoding="utf-8").strip()
    if _version_file.is_file()
    else "0.0.0"
)
version = release.split("-", 1)[0]  # X.Y.Z without the -rcN suffix

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
