#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/lib/skip.sh GROUP PATH REASON
#
# Reports GROUP, which lives in PATH, as one skipped test:
# what the make target prints for a test it cannot run on this host.

set -euo pipefail

. "$(dirname "$0")/test.sh"
test_begin "$1" "$2"
SKIP "%s" "$3"
test_end
