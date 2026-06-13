#!/usr/bin/env bash
# Self-test for check-base-pinned.sh — proves the digest-pinning guard accepts a
# correctly pinned setup and rejects a floating-tag regression (SF.1 acceptance).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${here}/check-base-pinned.sh"

fails=0
check() { if [[ "$2" == "$3" ]]; then echo "PASS: $1"; else echo "FAIL: $1 (want exit $2, got $3)"; fails=1; fi; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- GOOD fixture: runtime FROM ${BASE_IMAGE}, release resolves a digest ---
mkdir -p "$tmp/good/deploy/docker" "$tmp/good/.github/workflows"
cat >"$tmp/good/deploy/docker/Dockerfile" <<'EOF'
FROM golang:1.25-bookworm AS build
RUN true
FROM ${BASE_IMAGE}
EOF
cat >"$tmp/good/.github/workflows/release.yml" <<'EOF'
      - run: |
          digest="$(docker buildx imagetools inspect "$base" --format '{{.Manifest.Digest}}')"
          echo "ref=gcr.io/distroless/static-debian12@${digest}"
      - run: docker build --build-arg BASE_IMAGE=${{ steps.base.outputs.ref }} .
EOF

# --- BAD fixture A: runtime FROM a floating tag ---
mkdir -p "$tmp/bad1/deploy/docker" "$tmp/bad1/.github/workflows"
cat >"$tmp/bad1/deploy/docker/Dockerfile" <<'EOF'
FROM golang:1.25-bookworm AS build
FROM gcr.io/distroless/static-debian12:nonroot
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/bad1/.github/workflows/release.yml"

# --- BAD fixture B: release never resolves a digest ---
mkdir -p "$tmp/bad2/deploy/docker" "$tmp/bad2/.github/workflows"
cp "$tmp/good/deploy/docker/Dockerfile" "$tmp/bad2/deploy/docker/Dockerfile"
cat >"$tmp/bad2/.github/workflows/release.yml" <<'EOF'
      - run: docker build -t trustctl .
EOF

set +e
main "$tmp/good"  >/dev/null; check "accepts digest-pinned base + digest-resolving release" 0 $?
main "$tmp/bad1"  >/dev/null; check "rejects floating-tag runtime FROM" 1 $?
main "$tmp/bad2"  >/dev/null; check "rejects release that never resolves a digest" 1 $?
set -e

if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
