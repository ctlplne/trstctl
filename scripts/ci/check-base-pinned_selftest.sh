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

# --- GOOD fixture: build/runtime FROM injectable args, release resolves digests ---
mkdir -p "$tmp/good/deploy/docker" "$tmp/good/.github/workflows"
cat >"$tmp/good/deploy/docker/Dockerfile" <<'EOF'
FROM ${BUILD_IMAGE} AS build
RUN true
FROM ${BASE_IMAGE}
EOF
cat >"$tmp/good/.github/workflows/release.yml" <<'EOF'
      - run: |
          digest="$(docker buildx imagetools inspect "$base" --format '{{.Manifest.Digest}}')"
          echo "runtime_ref=gcr.io/distroless/static-debian12@${digest}"
          echo "build_ref=golang@${digest}"
      - run: docker build --build-arg BUILD_IMAGE=${{ steps.base.outputs.build_ref }} --build-arg BASE_IMAGE=${{ steps.base.outputs.runtime_ref }} .
EOF

# --- BAD fixture A: runtime FROM a floating tag ---
mkdir -p "$tmp/bad1/deploy/docker" "$tmp/bad1/.github/workflows"
cat >"$tmp/bad1/deploy/docker/Dockerfile" <<'EOF'
FROM ${BUILD_IMAGE} AS build
FROM gcr.io/distroless/static-debian12:nonroot
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/bad1/.github/workflows/release.yml"

# --- BAD fixture B: build FROM a floating tag ---
mkdir -p "$tmp/bad2/deploy/docker" "$tmp/bad2/.github/workflows"
cat >"$tmp/bad2/deploy/docker/Dockerfile" <<'EOF'
FROM golang:1.26.4-bookworm AS build
FROM ${BASE_IMAGE}
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/bad2/.github/workflows/release.yml"

# --- BAD fixture C: release never resolves a digest ---
mkdir -p "$tmp/bad3/deploy/docker" "$tmp/bad3/.github/workflows"
cp "$tmp/good/deploy/docker/Dockerfile" "$tmp/bad3/deploy/docker/Dockerfile"
cat >"$tmp/bad3/.github/workflows/release.yml" <<'EOF'
      - run: docker build -t trstctl .
EOF

set +e
main "$tmp/good" >/dev/null; check "accepts digest-pinned build/runtime bases + digest-resolving release" 0 $?
main "$tmp/bad1" >/dev/null; check "rejects floating-tag runtime FROM" 1 $?
main "$tmp/bad2" >/dev/null; check "rejects floating-tag build FROM" 1 $?
main "$tmp/bad3" >/dev/null; check "rejects release that never resolves a digest" 1 $?
set -e

if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
