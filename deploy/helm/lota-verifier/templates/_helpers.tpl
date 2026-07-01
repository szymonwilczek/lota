{{/* SPDX-License-Identifier: MIT */}}
{{/* Copyright (C) 2026 Szymon Wilczek */}}

{{- define "lota-verifier.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "lota-verifier.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "lota-verifier.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "lota-verifier.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "lota-verifier.labels" -}}
helm.sh/chart: {{ include "lota-verifier.chart" . }}
app.kubernetes.io/name: {{ include "lota-verifier.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/component: verifier
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "lota-verifier.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lota-verifier.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "lota-verifier.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "lota-verifier.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Secret holding the Postgres DSN: operator-provided one, or the chart's. */}}
{{- define "lota-verifier.pgSecretName" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-pg" (include "lota-verifier.fullname" .) -}}
{{- end -}}
{{- end -}}
