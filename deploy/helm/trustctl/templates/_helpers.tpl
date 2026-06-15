{{/* Common naming + labels for the trustctl control-plane chart. */}}

{{- define "trustctl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trustctl.fullname" -}}
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

{{- define "trustctl.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trustctl.labels" -}}
helm.sh/chart: {{ include "trustctl.chart" . }}
{{ include "trustctl.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: trustctl
{{- end -}}

{{- define "trustctl.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trustctl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: control-plane
{{- end -}}

{{- define "trustctl.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "trustctl.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the control-plane image reference (OPS-003).

The release pipeline (.github/workflows/release.yml) tags every image `vX.Y.Z`
(from `git describe`) plus `:latest`. Chart.AppVersion follows Helm's
leading-`v`-stripped convention, so when the operator does not override
image.tag we form the tag as `v<appVersion>` — which is exactly a tag the
pipeline publishes — rather than a bare `<appVersion>` that was never pushed and
would ImagePullBackOff. An explicit image.tag (e.g. a digest or a specific
`vX.Y.Z`/`latest`) is honored verbatim.
*/}}
{{- define "trustctl.imageTag" -}}
{{- if .Values.image.tag -}}
{{- .Values.image.tag -}}
{{- else -}}
{{- printf "v%s" .Chart.AppVersion -}}
{{- end -}}
{{- end -}}

{{- define "trustctl.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "trustctl.imageTag" .) -}}
{{- end -}}

{{/*
Validate signer.mode (SIGNER-005 / S15.1).

Two topologies are supported:
  - "sidecar" (default): the signer is co-located with the control plane and
    reached over an in-memory peer-authenticated UDS.
  - "isolated": the signer runs as its OWN pod, reached over a cross-node
    mTLS gRPC channel (TLS 1.3, AEAD-only, the control plane and the signer each
    pinning the other's certificate). This is now implemented — the
    trustctl-signer binary defines --mtls-listen plus the mTLS cert/peer flags,
    and the control plane dials it with signer.mtls_address. When isolated, the
    operator must supply the signer's TLS material (signer.mtls.* values), so the
    guard fails fast on a half-configured isolated install rather than rendering a
    pod that cannot authenticate.

Every signer-topology template includes this first, so any render validates the
mode and an unrecognized value fails with guidance instead of a silent
mis-render.
*/}}
{{- define "trustctl.signer.guardMode" -}}
{{- if eq .Values.signer.mode "isolated" -}}
{{- if not .Values.signer.mtls.serverName -}}
{{- fail "signer.mode=isolated runs the signer as a separate pod over a mutually-pinned mTLS channel (SIGNER-005); you must also set signer.mtls.serverName (the signer certificate SAN) and mount the signer/control-plane certificates (see signer.mtls.* and the chart README). For an evaluation single-pod deployment, use the default signer.mode=sidecar." -}}
{{- end -}}
{{- else if ne .Values.signer.mode "sidecar" -}}
{{- fail (printf "signer.mode=%q is not recognized; supported values are \"sidecar\" (default; co-located signer over an in-memory UDS) and \"isolated\" (separate pod over a mutually-pinned mTLS channel, SIGNER-005)." .Values.signer.mode) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the deployment KEK. */}}
{{- define "trustctl.kekSecretName" -}}
{{- if .Values.kek.existingSecret -}}
{{- .Values.kek.existingSecret -}}
{{- else -}}
{{- printf "%s-kek" (include "trustctl.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the PostgreSQL DSN. */}}
{{- define "trustctl.dbSecretName" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-db" (include "trustctl.fullname" .) -}}
{{- end -}}
{{- end -}}
