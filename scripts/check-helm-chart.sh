#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Check what the verifier Helm chart deploys; helm lint and kubeconform pass
# on a chart that pulls an image tag no build produces. Offline, no helm.

set -euo pipefail

cd "$(dirname "$0")/.."

CHART_DIR=deploy/helm/lota-verifier

fail=0

# values.yaml ships an empty image.tag, so a default install pulls appVersion;
# images are tagged with the project version, which make helm-package writes
# over the placeholder. A spelled-out version falls behind at the next bump.
chart_version=$(awk '$1 == "appVersion:" { gsub(/"/, "", $2); print $2; exit }' \
	"$CHART_DIR/Chart.yaml")

if [ "$chart_version" != "@VERSION@" ]; then
	fail=1
	echo "FAIL: ${CHART_DIR}/Chart.yaml says appVersion ${chart_version}, not @VERSION@"
	echo "  a default install pulls <repository>:${chart_version} after the next VERSION bump"
fi

if [ "$fail" -ne 0 ]; then
	echo
	echo "The chart must take its version from VERSION through make helm-package."
	exit 1
fi

echo "check-helm-chart: clean"
