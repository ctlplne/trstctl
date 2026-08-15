#!/usr/bin/env bash
#
# Verify a published trstctl image before you run it: confirm its keyless cosign
# signature was produced by this repo's release workflow, and that it carries the
# CycloneDX SBOM attestation. This is the signature-on-install check.
#
# Usage: scripts/verify-image.sh ghcr.io/ctlplne/trstctl:<tag>
set -euo pipefail

image="${1:-}"
if [ -z "$image" ]; then
  echo "usage: $0 <image-ref>   e.g. ghcr.io/ctlplne/trstctl:v0.1.0" >&2
  exit 2
fi

command -v cosign >/dev/null 2>&1 || {
  echo "::error::cosign is required (https://docs.sigstore.dev/cosign/installation/)" >&2
  exit 1
}

# The identity is the release workflow itself, asserted by GitHub's OIDC issuer —
# so only an image built by .github/workflows/release.yml verifies.
#
# Both anchors matter. The org segment used to be `.*`, which matched ANY GitHub
# account: a fork at github.com/attacker/trstctl running its own copy of
# release.yml produced a signature this check accepted. And the ref used to be
# `@.*`, which matched any branch — so a signature made from an attacker's
# branch of the real repo verified too. Pin the org, and pin the ref to a
# release tag.
org='ctlplne'
identity_re="^https://github\.com/${org}/trstctl/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$"
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
