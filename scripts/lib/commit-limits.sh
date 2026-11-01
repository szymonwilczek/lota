# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
# Commit message limits, shared by format-patch and check-pr-quality.

export COMMIT_COLUMNS=75

# Body lines that keep their length: a trailer, a URL, a merge line, a diffstat
# line, or a line led by a file path. ERE, read by awk and perl.
export COMMIT_LINE_EXEMPT='^[[:space:]]*([A-Za-z0-9-]+-by:|Fixes:|Link:|Closes:|Docs-Not-Needed:|Merge branch |[^[:space:]]+[[:space:]]+[|][[:space:]]+[0-9]|[^[:space:]]*/[^[:space:]]*:)|[a-z][a-z0-9+.-]*://[^[:space:]]'
