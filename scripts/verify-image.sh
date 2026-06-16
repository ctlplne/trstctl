#!/usr/bin/env bash
#
# Verify a published trstctl image before you run it: confirm its keyless cosign
# signature was produced by this repo's release workflow, and that it carries the
# CycloneDX SBOM attestation. This is the signature-on-install check.
#
# Usage: scripts/verify-image.sh ghcr.io/imfeelingtheagi/trstctl:<tag>
set -euo pipefail

image="${1:-}"
if [ -z "$image" ]; then
  echo "usage: $0 <image-ref>   e.g. ghcr.io/imfeelingtheagi/trstctl:v0.1.0" >&2
  exit 2
fi

command -v cosign >/dev/null 2>&1 || {
  echo "::error::cosign is required (https://docs.sigstore.dev/cosign/installation/)" >&2
  exit 1
}

# The identity is the release workflow itself, asserted by GitHub's OIDC issuer —
# so only an image built by .github/workflows/release.yml verifies.
identity_re='^https://github.com/.*/trstctl/.github/workflows/release.yml@.*'
issuer='https://token.actions.githubusercontent.com'

echo ">> verifying cosign signature for ${image}"
cosign verify "$image" \
  --certificate-identity-regexp "$identity_re" \
  --certificate-oidc-issuer "$issuer" >/dev/null
echo ">> signature OK"

echo ">> verifying the CycloneDX SBOM attestation"
cosign verify-attestation "$image" \
  --type cyclonedx \
  --certificate-identity-regexp "$identity_re" \
  --certificate-oidc-issuer "$issuer" >/dev/null
echo ">> SBOM attestation OK"

echo ">> ${image} is signed by the trstctl release workflow and ships an SBOM"
