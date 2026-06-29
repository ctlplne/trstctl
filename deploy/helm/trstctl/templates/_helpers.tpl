{{/* Common naming + labels for the trstctl control-plane chart. */}}

{{- define "trstctl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trstctl.fullname" -}}
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

{{- define "trstctl.signerCustodyArgs" -}}
{{- if and .Values.externalKMS .Values.externalKMS.enabled }}
- {{ printf "--kms-provider=%s" .Values.externalKMS.provider | quote }}
- {{ printf "--kms-key-ref=%s" .Values.externalKMS.keyRef | quote }}
- {{ printf "--kms-wrap-command=%s" .Values.externalKMS.wrapCommand | quote }}
- {{ printf "--kms-timeout=%s" (.Values.externalKMS.timeout | default "10s") | quote }}
{{- else }}
- "--kek=/etc/trstctl/kek/kek.bin"
{{- end }}
{{- end -}}

{{- define "trstctl.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "trstctl.labels" -}}
helm.sh/chart: {{ include "trstctl.chart" . }}
{{ include "trstctl.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: trstctl
{{- end -}}

{{- define "trstctl.baseSelectorLabels" -}}
app.kubernetes.io/name: {{ include "trstctl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "trstctl.selectorLabels" -}}
{{ include "trstctl.baseSelectorLabels" . }}
app.kubernetes.io/component: control-plane
{{- end -}}

{{- define "trstctl.signerSelectorLabels" -}}
{{ include "trstctl.baseSelectorLabels" . }}
app.kubernetes.io/component: signer
{{- end -}}

{{- define "trstctl.signerLabels" -}}
helm.sh/chart: {{ include "trstctl.chart" . }}
{{ include "trstctl.signerSelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: trstctl
{{- end -}}

{{- define "trstctl.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "trstctl.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the control-plane image reference (OPS-003).

The release pipeline (.github/workflows/release.yml) tags every release image
`vX.Y.Z` (from `git describe`). Chart.AppVersion follows Helm's leading-`v`-
stripped convention, so when the operator does not override image.tag we form the
tag as `v<appVersion>` — which is exactly a tag the pipeline publishes — rather
than a bare `<appVersion>` that was never pushed and would ImagePullBackOff. For
production, set image.digest so the rendered pod specs use
`repository@sha256:...`; when a digest is set, image.tag is ignored. An explicit
image.tag is otherwise honored verbatim for controlled non-production installs.
*/}}
{{- define "trstctl.imageTag" -}}
{{- if .Values.image.tag -}}
{{- .Values.image.tag -}}
{{- else -}}
{{- printf "v%s" .Chart.AppVersion -}}
{{- end -}}
{{- end -}}

{{- define "trstctl.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository (.Values.image.digest | trimPrefix "@") -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (include "trstctl.imageTag" .) -}}
{{- end -}}
{{- end -}}

{{/*
Validate signer.mode (SIGNER-005 / S15.1).

Two topologies are supported:
  - "sidecar" (default): the signer is co-located with the control plane and
    reached over an in-memory peer-authenticated UDS.
  - "isolated": the signer runs as its OWN pod, reached over a cross-node
    mTLS gRPC channel (TLS 1.3, AEAD-only, the control plane and the signer each
    pinning the other's certificate). This is now implemented — the
    trstctl-signer binary defines --mtls-listen plus the mTLS cert/peer flags,
    and the control plane dials it with signer.mtls_address. When isolated, the
    operator must supply the signer's TLS material (signer.mtls.* values), so the
    guard fails fast on a half-configured isolated install rather than rendering a
    pod that cannot authenticate.

Every signer-topology template includes this first, so any render validates the
mode and an unrecognized value fails with guidance instead of a silent
mis-render.
*/}}
{{- define "trstctl.signer.guardMode" -}}
{{- if eq .Values.signer.mode "isolated" -}}
{{- if not .Values.signer.mtls.serverName -}}
{{- fail "signer.mode=isolated runs the signer as a separate pod over a mutually-pinned mTLS channel (SIGNER-005); you must also set signer.mtls.serverName (the signer certificate SAN) and mount the signer/control-plane certificates (see signer.mtls.* and the chart README). For an evaluation single-pod deployment, use the default signer.mode=sidecar." -}}
{{- end -}}
{{- else if ne .Values.signer.mode "sidecar" -}}
{{- fail (printf "signer.mode=%q is not recognized; supported values are \"sidecar\" (default; co-located signer over an in-memory UDS) and \"isolated\" (separate pod over a mutually-pinned mTLS channel, SIGNER-005)." .Values.signer.mode) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the deployment KEK. */}}
{{- define "trstctl.kekSecretName" -}}
{{- if .Values.kek.existingSecret -}}
{{- .Values.kek.existingSecret -}}
{{- else -}}
{{- printf "%s-kek" (include "trstctl.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the signer content-authorization secret. */}}
{{- define "trstctl.signerAuthSecretName" -}}
{{- $existing := "" -}}
{{- with .Values.signer -}}
{{- with .auth -}}
{{- with .existingSecret -}}{{- $existing = . -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- if $existing -}}
{{- $existing -}}
{{- else -}}
{{- printf "%s-signer-auth" (include "trstctl.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding the PostgreSQL DSN. */}}
{{- define "trstctl.dbSecretName" -}}
{{- if .Values.postgres.existingSecret -}}
{{- .Values.postgres.existingSecret -}}
{{- else -}}
{{- printf "%s-db" (include "trstctl.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Fail before rendering a broken Deployment that references missing production
Secrets or empty datastore config (OPS-003).

The chart supports two explicit install shapes:
  - production: supply existing Secrets for the DB DSN and KEK, plus a NATS URL;
  - evaluation: provide inline postgres.dsn and set kek.generate=true, plus NATS.

Default values deliberately do not pick one silently. A plain `helm install` must
stop at template time with actionable text instead of creating pods that fail at
startup because their Secret references were never rendered.
*/}}
{{- define "trstctl.requiredInputs.guard" -}}
{{- if not (or .Values.postgres.dsn .Values.postgres.existingSecret) -}}
{{- fail "OPS-003: postgres.dsn or postgres.existingSecret is required. Set postgres.dsn for an evaluation install, or set postgres.existingSecret to an existing Secret key containing the DSN before installing." -}}
{{- end -}}
{{- if not .Values.nats.url -}}
{{- fail "OPS-003: nats.url is required. Set it to the external NATS JetStream URL before installing." -}}
{{- end -}}
{{- if not (or .Values.kek.existingSecret .Values.kek.generate) -}}
{{- fail "OPS-003: kek.existingSecret or kek.generate=true is required. Use kek.existingSecret for production; set kek.generate=true only for evaluation so Helm creates and preserves a random KEK Secret." -}}
{{- end -}}
{{- $signerMode := "sidecar" -}}
{{- $signerTokenCommand := "" -}}
{{- $signerAllowCoResident := false -}}
{{- with .Values.signer -}}
{{- with .mode -}}{{- $signerMode = . -}}{{- end -}}
{{- with .auth -}}
{{- with .tokenCommand -}}{{- $signerTokenCommand = . -}}{{- end -}}
{{- if .allowCoResidentAuthorizer -}}{{- $signerAllowCoResident = true -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- if and $signerTokenCommand $signerAllowCoResident -}}
{{- fail "CRYPTO-001: signer.auth.tokenCommand and signer.auth.allowCoResidentAuthorizer are mutually exclusive. Production must use the independent token command; evaluation may explicitly choose the co-resident authorizer." -}}
{{- end -}}
{{- if and $signerAllowCoResident (ne $signerMode "sidecar") -}}
{{- fail "CRYPTO-001: signer.auth.allowCoResidentAuthorizer is only supported for single-pod sidecar evaluation. Isolated signer deployments must use signer.auth.tokenCommand." -}}
{{- end -}}
{{- if and (not .Values.nats.allowSingleReplica) $signerAllowCoResident -}}
{{- fail "CRYPTO-001: signer.auth.allowCoResidentAuthorizer is evaluation-only. Production-style external NATS values (nats.allowSingleReplica=false) must use signer.auth.tokenCommand." -}}
{{- end -}}
{{- if and (not .Values.nats.allowSingleReplica) (not $signerTokenCommand) -}}
{{- fail "CRYPTO-001: signer.auth.tokenCommand is required for production-style external NATS values so privileged CA handles use an independent signer authorization token provider. For a single-node evaluation, set nats.allowSingleReplica=true and signer.auth.allowCoResidentAuthorizer=true." -}}
{{- end -}}
{{- include "trstctl.externalKMS.guard" . -}}
{{- end -}}

{{/*
Validate external KMS / HSM signer-keystore custody (CRYPTO-002).

When externalKMS.enabled=true, the signer no longer receives --kek for its
keystore. It receives --kms-provider/--kms-key-ref/--kms-wrap-command instead, and
trstctl-signer wraps signer-keystore DEKs through that adapter. The chart must
therefore fail fast on incomplete values; otherwise it would render a pod that
cannot open the signer keystore or, worse, appears to use KMS while falling back
to a local KEK.
*/}}
{{- define "trstctl.externalKMS.guard" -}}
{{- with .Values.externalKMS -}}
{{- if .enabled -}}
{{- if not .provider -}}
{{- fail "CRYPTO-002: externalKMS.provider is required when externalKMS.enabled=true (supported: awskms, gcpkms, azurekv, pkcs11)." -}}
{{- else if not (or (eq .provider "awskms") (eq .provider "gcpkms") (eq .provider "azurekv") (eq .provider "pkcs11")) -}}
{{- fail (printf "CRYPTO-002: externalKMS.provider=%q is not supported; use awskms, gcpkms, azurekv, or pkcs11." .provider) -}}
{{- end -}}
{{- if not .keyRef -}}
{{- fail "CRYPTO-002: externalKMS.keyRef is required when externalKMS.enabled=true." -}}
{{- end -}}
{{- if not .wrapCommand -}}
{{- fail "CRYPTO-002: externalKMS.wrapCommand is required when externalKMS.enabled=true; it must be an absolute signer-container path to the KMS/HSM wrapper adapter." -}}
{{- else if not (hasPrefix "/" .wrapCommand) -}}
{{- fail "CRYPTO-002: externalKMS.wrapCommand must be an absolute signer-container path; the signer does not run it through a shell or PATH lookup." -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
