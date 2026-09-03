#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Check what the verifier Helm chart deploys; helm lint and kubeconform pass
# on a chart that pulls an image tag no build produces. Offline, no cluster.

set -euo pipefail

cd "$(dirname "$0")/.."

CHART_DIR=deploy/helm/lota-verifier
VERSION_FILE=VERSION
HELM=${HELM:-helm}
# Chart-derived names (<release>-<chart>-*) never clash with operator values
RELEASE=gate
CHART_FULLNAME=gate-lota-verifier

fail=0

# Inputs the chart refuses to render without: AIK root and policy choice
BASE_VALUES=(
	--set "aikCA.existingSecret=example-aik-ca"
	--set "policy.enabled=true"
	--set "policy.existingSecret=example-policy"
)

# The chart directory refuses @VERSION@; render the package make helm-package
# would write
render() {
	"$HELM" template "$RELEASE" "$CHART_PACKAGE" "${BASE_VALUES[@]}" "$@"
}

# Print release-named Secrets/ConfigMaps a pod references but the release does
# not create; such a pod stays in CreateContainerConfigError
dangling_release_refs() {
	awk -v prefix="${CHART_FULLNAME}-" '
		/^kind: / { kind = $2; next }
		/^metadata:/ { in_meta = 1; next }
		in_meta && /^  name: / {
			created[kind ":" $2] = 1
			in_meta = 0
			next
		}
		/^[^ ]/ { in_meta = 0 }

		/secretKeyRef:|secretName:|configMapKeyRef:/ {
			ref_kind = ($0 ~ /configMap/) ? "ConfigMap" : "Secret"
			if (match($0, /secretName:[ \t]*/)) {
				refs[ref_kind ":" $2] = 1
				next
			}
			want_name = 1
			next
		}
		want_name && /name:/ {
			sub(/^.*name:[ \t]*/, "")
			refs[ref_kind ":" $0] = 1
			want_name = 0
		}

		END {
			for (r in refs) {
				name = r
				sub(/^[^:]*:/, "", name)
				if (index(name, prefix) != 1)
					continue
				if (!(r in created))
					print r
			}
		}
	'
}

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

if ! command -v "$HELM" >/dev/null 2>&1; then
	echo "check-helm-chart: $HELM not installed, rendering checks skipped"
else
	tree_version=$(tr -d '[:space:]' <"$VERSION_FILE")
	package_dir=$(mktemp -d)
	trap 'rm -rf "$package_dir"' EXIT
	"$HELM" package "$CHART_DIR" --version "$tree_version" \
		--app-version "$tree_version" -d "$package_dir" >/dev/null
	CHART_PACKAGE="$package_dir/lota-verifier-${tree_version}.tgz"

	# Single instance needs no shared backend; all it references must exist
	dangling=$(render --set replicaCount=1 | dangling_release_refs)
	if [ -n "$dangling" ]; then
		fail=1
		echo "FAIL: a single-instance install references objects it does not create:"
		printf '  %s\n' $dangling
		echo "  the pods stop at CreateContainerConfigError while helm install reports success"
	fi

	# Replicas without a shared backend split enforcement state; must be refused
	if render --set replicaCount=3 >/dev/null 2>&1; then
		fail=1
		echo "FAIL: replicaCount 3 with no shared backend renders instead of being refused"
		echo "  each replica would keep enforcement state the others cannot see"
	fi
fi

if [ "$fail" -ne 0 ]; then
	echo
	echo "The chart must take its version from VERSION and render a pod that can start."
	exit 1
fi

echo "check-helm-chart: clean"
