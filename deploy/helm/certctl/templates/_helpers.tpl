{{/* Common naming + labels for the certctl control-plane chart. */}}

{{- define "certctl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "certctl.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "certctl.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "certctl.labels" -}}
helm.sh/chart: {{ include "certctl.chart" . }}
{{ include "certctl.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: certctl
{{- end -}}

{{- define "certctl.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certctl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: control-plane
{{- end -}}

{{- define "certctl.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "certctl.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "certctl.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/* Name of the Secret holding the deployment KEK. */}}
{{- define "certctl.kekSecretName" -}}
{{- if .Values.kek.existingSecret -}}
{{- .Values.kek.existingSecret -}}
{{- else -}}
{{- printf "%s-kek" (include "certctl.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the PostgreSQL DSN. */}}
{{- define "certctl.dbSecretName" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-db" (include "certctl.fullname" .) -}}
{{- end -}}
{{- end -}}
