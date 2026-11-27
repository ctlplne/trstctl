#!/usr/bin/env bash
# Verify the digest-pinned release chart against its exact release workflow identity.
set -euo pipefail

chart="${1:-}"
tag="${2:-}"
chart_re='^ghcr[.]io/ctlplne/trstctl/charts/trstctl@sha256:[0-9a-f]{64}$'
tag_re='^v[0-9]+[.][0-9]+[.][0-9]+([-+][0-9A-Za-z.-]+)?$'
if [[ ! "$chart" =~ $chart_re || ! "$tag" =~ $tag_re ]]; then
  echo "usage: $0 ghcr.io/ctlplne/trstctl/charts/trstctl@sha256:<64-hex-digest> v<release-version>" >&2
  exit 2
fi

command -v cosign >/dev/null 2>&1 || {
  echo "cosign is required to verify the chart" >&2
  exit 1
}

identity="https://github.com/ctlplne/trstctl/.github/workflows/release.yml@refs/tags/${tag}"
cosign verify "$chart" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
echo ">> chart signature OK: ${chart}"
