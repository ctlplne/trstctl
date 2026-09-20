#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Self-test for check-compose-images-pinned.sh — proves the SUPPLY-008 digest-pin
# guard accepts a fully pinned deploy tree and rejects each way a floating tag can
# come back, so a regression in the guard is caught here rather than silently
# weakening the build.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${here}/check-compose-images-pinned.sh"

fails=0
check() { if [[ "$2" == "$3" ]]; then echo "PASS: $1"; else echo "FAIL: $1 (want exit $2, got $3)"; fails=1; fi; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

dig='sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32' # a real digest shape

# --- GOOD fixture: every third-party ref digest-pinned; every exemption used ---
mkdir -p "$tmp/good/deploy/demo" "$tmp/good/deploy/helm/templates"
cat >"$tmp/good/deploy/demo/docker-compose.yml" <<EOF
services:
  db:
    image: postgres:16-alpine@${dig}
  app:
    build: {context: ../..}
    image: trstctl-demo:local
EOF
cat >"$tmp/good/deploy/demo/Dockerfile.seed" <<EOF
ARG BASE_IMAGE=node:22-alpine
FROM \${BASE_IMAGE} AS build
RUN true
FROM build AS package
FROM node:22-alpine@${dig}
EOF
cat >"$tmp/good/deploy/helm/templates/deployment.yaml" <<'EOF'
spec:
  containers:
    - image: {{ include "trstctl.image" . }}
EOF
cat >"$tmp/good/deploy/helm/values.yaml" <<'EOF'
image:
  repository: ghcr.io/ctlplne/trstctl
EOF

# --- BAD fixture A: a floating compose image tag -----------------------------
mkdir -p "$tmp/bad1/deploy/demo"
cat >"$tmp/bad1/deploy/demo/docker-compose.yml" <<'EOF'
services:
  helper:
    image: node:22-alpine
EOF

# --- BAD fixture B: a floating final-stage FROM in a Dockerfile --------------
mkdir -p "$tmp/bad2/deploy/demo"
cat >"$tmp/bad2/deploy/demo/Dockerfile.seed" <<EOF
FROM golang:1.26-bookworm@${dig} AS build
RUN true
FROM node:22-alpine
EOF

# --- BAD fixture C: a stage-shaped ref that no EARLIER \`AS\` declares ---------
# Guards against accepting any bare word as an intra-file stage reference, and
# against order-blindness (a stage may not be referenced before it is declared).
mkdir -p "$tmp/bad3/deploy/docker"
cat >"$tmp/bad3/deploy/docker/Dockerfile" <<EOF
FROM runtime
FROM debian:bookworm-slim@${dig} AS runtime
EOF

# --- BAD fixture D: a quoted floating tag in a Kubernetes job manifest -------
mkdir -p "$tmp/bad4/deploy/iac"
cat >"$tmp/bad4/deploy/iac/job.yaml" <<'EOF'
spec:
  containers:
    - image: "hashicorp/terraform:1.9.8"   # floating
EOF

# --- BAD fixture E: a deploy tree with nothing to inspect -------------------
# A rename or move that empties the scan set must be loud, not a silent pass.
mkdir -p "$tmp/bad5/deploy/notes"
echo 'no manifests here' >"$tmp/bad5/deploy/notes/README.md"

# --- BAD fixture F: no deploy directory at all ------------------------------
mkdir -p "$tmp/bad6"

set +e
main "$tmp/good" >/dev/null
check "accepts a fully digest-pinned deploy tree (:local, \${ARG}, {{template}}, intra-file stage)" 0 $?
main "$tmp/bad1" >/dev/null; check "rejects a floating compose image tag" 1 $?
main "$tmp/bad2" >/dev/null; check "rejects a floating final-stage Dockerfile FROM" 1 $?
main "$tmp/bad3" >/dev/null; check "rejects a stage-shaped ref no earlier AS declares" 1 $?
main "$tmp/bad4" >/dev/null; check "rejects a quoted floating tag in a k8s manifest" 1 $?
main "$tmp/bad5" >/dev/null; check "fails loudly when there is nothing to inspect" 1 $?
main "$tmp/bad6" >/dev/null; check "fails loudly when deploy/ is missing" 1 $?
set -e

# Direct unit assertions on the pure predicate, independent of fixtures.
ref_is_pinned "node:22-alpine@${dig}"; check "ref_is_pinned accepts a digest ref" 0 $?
set +e
ref_is_pinned "node:22-alpine"; check "ref_is_pinned rejects a bare tag" 1 $?
set -e

if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
