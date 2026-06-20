#!/usr/bin/env bash
# sign-windows-artifact-oidc.sh — send one Windows artifact to an operator-owned
# Authenticode signing service that authenticates this GitHub Actions job through
# OIDC and signs inside an HSM/cloud code-signing boundary.
#
# Required environment:
#   WINDOWS_CODESIGN_URL       HTTPS endpoint that accepts artifact bytes and
#                              returns the signed artifact bytes.
#   ACTIONS_ID_TOKEN_*         Provided by GitHub when the job has id-token: write.
# Optional environment:
#   WINDOWS_CODESIGN_AUDIENCE  OIDC audience for the signing service.
set -euo pipefail

artifact="${1:?usage: sign-windows-artifact-oidc.sh <artifact>}"
url="${WINDOWS_CODESIGN_URL:?WINDOWS_CODESIGN_URL must point at the remote Authenticode signer}"
audience="${WINDOWS_CODESIGN_AUDIENCE:-trstctl-windows-codesign}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?GitHub OIDC request URL is missing; job needs id-token: write}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?GitHub OIDC request token is missing; job needs id-token: write}"

if [[ ! -s "$artifact" ]]; then
	echo "sign-windows-artifact-oidc: artifact is missing or empty: $artifact" >&2
	exit 1
fi

audience_q="$(jq -rn --arg v "$audience" '$v|@uri')"
jwt="$(
	curl -fsSL \
		-H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
		"${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${audience_q}" |
		jq -er '.value'
)"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl -fsS \
	-X POST \
	-H "Authorization: Bearer ${jwt}" \
	-H "Content-Type: application/octet-stream" \
	-H "X-Trstctl-Artifact: $(basename "$artifact")" \
	--data-binary @"$artifact" \
	"$url" \
	-o "$tmp"

if [[ ! -s "$tmp" ]]; then
	echo "sign-windows-artifact-oidc: remote signer returned an empty artifact for $artifact" >&2
	exit 1
fi

mv "$tmp" "$artifact"
trap - EXIT
