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
FROM ${BASE_IMAGE} AS runtime
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
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/bad1/.github/workflows/release.yml"

# --- BAD fixture B: build FROM a floating tag ---
mkdir -p "$tmp/bad2/deploy/docker" "$tmp/bad2/.github/workflows"
cat >"$tmp/bad2/deploy/docker/Dockerfile" <<'EOF'
FROM golang:1.26.4-bookworm AS build
FROM ${BASE_IMAGE} AS runtime
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/bad2/.github/workflows/release.yml"

# --- BAD fixture C: release never resolves a digest ---
mkdir -p "$tmp/bad3/deploy/docker" "$tmp/bad3/.github/workflows"
cp "$tmp/good/deploy/docker/Dockerfile" "$tmp/bad3/deploy/docker/Dockerfile"
cat >"$tmp/bad3/.github/workflows/release.yml" <<'EOF'
      - run: docker build -t trstctl .
EOF

# --- DRIFT fixture: the pinned stages are neither the first nor the last FROM.
# This is the exact shape the real Dockerfile grew (a leading `FROM scratch AS
# context-audit` audit stage, a trailing `FROM runtime AS demo` stage). Positional
# (head -1 / tail -1) stage selection fails this fixture; name-based selection
# accepts it. ---
mkdir -p "$tmp/drift/deploy/docker" "$tmp/drift/.github/workflows"
cat >"$tmp/drift/deploy/docker/Dockerfile" <<'EOF'
FROM scratch AS context-audit
COPY . /context
FROM ${WEB_BUILD_IMAGE} AS web-build
FROM ${BUILD_IMAGE} AS build
FROM build AS demo-build
FROM ${BASE_IMAGE} AS runtime
FROM runtime AS demo
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/drift/.github/workflows/release.yml"

# --- BAD fixture D: the `AS build` stage was renamed away. A name-based selector
# must fail loudly on a missing stage instead of silently passing. ---
mkdir -p "$tmp/bad4/deploy/docker" "$tmp/bad4/.github/workflows"
cat >"$tmp/bad4/deploy/docker/Dockerfile" <<'EOF'
FROM ${BUILD_IMAGE} AS compile
FROM ${BASE_IMAGE} AS runtime
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/bad4/.github/workflows/release.yml"

# --- BAD fixture E: the `AS runtime` stage is absent (final stage unnamed). ---
mkdir -p "$tmp/bad5/deploy/docker" "$tmp/bad5/.github/workflows"
cat >"$tmp/bad5/deploy/docker/Dockerfile" <<'EOF'
FROM ${BUILD_IMAGE} AS build
FROM ${BASE_IMAGE}
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/bad5/.github/workflows/release.yml"

# --- BAD fixture F: two stages claim the name `runtime`; the guard must not pick
# one arbitrarily. ---
mkdir -p "$tmp/bad6/deploy/docker" "$tmp/bad6/.github/workflows"
cat >"$tmp/bad6/deploy/docker/Dockerfile" <<'EOF'
FROM ${BUILD_IMAGE} AS build
FROM ${BASE_IMAGE} AS runtime
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/bad6/.github/workflows/release.yml"

# --- REAL fixture: the repository's own deploy/docker/Dockerfile, run through the
# same main(). Every fixture above is synthetic, which is precisely how positional
# stage drift in the real Dockerfile stayed invisible to this self-test. ---
repo_root="$(cd "${here}/../.." && pwd)"
mkdir -p "$tmp/real/deploy/docker" "$tmp/real/.github/workflows"
cp "${repo_root}/deploy/docker/Dockerfile" "$tmp/real/deploy/docker/Dockerfile"
cp "$tmp/good/.github/workflows/release.yml" "$tmp/real/.github/workflows/release.yml"

# --- COMMENT fixture: a trailing comment on the stage line must not make the
# named stage look absent. The name anchor tolerates an optional `# ...` tail. ---
mkdir -p "$tmp/cmt/deploy/docker" "$tmp/cmt/.github/workflows"
cat >"$tmp/cmt/deploy/docker/Dockerfile" <<'EOF'
FROM ${BUILD_IMAGE} AS build  # digest injected by release.yml
FROM ${BASE_IMAGE} AS runtime
EOF
cp "$tmp/good/.github/workflows/release.yml" "$tmp/cmt/.github/workflows/release.yml"

set +e
main "$tmp/good" >/dev/null; check "accepts digest-pinned build/runtime bases + digest-resolving release" 0 $?
main "$tmp/bad1" >/dev/null; check "rejects floating-tag runtime FROM" 1 $?
main "$tmp/bad2" >/dev/null; check "rejects floating-tag build FROM" 1 $?
main "$tmp/bad3" >/dev/null; check "rejects release that never resolves a digest" 1 $?
main "$tmp/drift" >/dev/null; check "accepts pinned stages that are neither the first nor the last FROM" 0 $?
main "$tmp/bad4" >/dev/null; check "rejects a Dockerfile whose build stage was renamed away" 1 $?
main "$tmp/bad5" >/dev/null; check "rejects a Dockerfile with no runtime stage" 1 $?
main "$tmp/bad6" >/dev/null; check "rejects a Dockerfile with a duplicated runtime stage" 1 $?
main "$tmp/real" >/dev/null; check "accepts the repository's real deploy/docker/Dockerfile" 0 $?
main "$tmp/cmt" >/dev/null; check "accepts a build stage line with a trailing comment" 0 $?
set -e

if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
