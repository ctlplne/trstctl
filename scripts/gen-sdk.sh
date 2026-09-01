#!/usr/bin/env bash
# gen-sdk.sh — regenerate the published client SDKs from the SERVED OpenAPI
# contract (PRODUCT-007). Run by `make sdk`.
#
# Source of truth chain (nothing on it can drift undetected):
#
#   live ServeMux  ==(internal/api.TestOpenAPIGolden)==>  internal/api/testdata/openapi.golden.json
#       ==(internal/api.TestSDKSpecPinnedToGolden)==>      clients/sdk/openapi.json
#       --(this script)-->                                 Go + TypeScript + Python + Java SDKs
#
# Step 0 re-pins clients/sdk/openapi.json to the golden, then the generators run
# against that pinned copy. A backend field add/rename/remove changes the golden,
# the pinning test goes red until this script is re-run, and the regenerated SDK
# types force `go build` / `tsc` to flag any code that used a now-missing field.
#
# Usage:
#   scripts/gen-sdk.sh           # re-pin spec + regenerate Go, TS, Python, and Java SDKs
#   scripts/gen-sdk.sh --check   # verify the SDKs are up to date (CI); exit 1 on drift
#
# Requirements: a Go toolchain, npm (for the lockfile-pinned TypeScript generator),
# and Python 3 (for the Python/Java generators). The TypeScript generator is
# installed with `npm ci` from clients/sdk/typescript/package-lock.json before use,
# so the SDK check never pulls a mutable generator version.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_DIR="${REPO_ROOT}/clients/sdk"
GOLDEN="${REPO_ROOT}/internal/api/testdata/openapi.golden.json"
PINNED="${SDK_DIR}/openapi.json"

CHECK=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK=1
fi

log() { printf '>> %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Step 0: re-pin the SDK spec to the served golden (byte-for-byte).
# ---------------------------------------------------------------------------
log "pin clients/sdk/openapi.json == served OpenAPI golden"
if [[ ! -f "${GOLDEN}" ]]; then
  echo "error: served golden not found at ${GOLDEN}" >&2
  exit 1
fi
if [[ "${CHECK}" == "1" ]]; then
  if ! cmp -s "${GOLDEN}" "${PINNED}"; then
    echo "error: clients/sdk/openapi.json has drifted from the served golden; run 'make sdk'" >&2
    exit 1
  fi
else
  cp "${GOLDEN}" "${PINNED}"
fi

# ---------------------------------------------------------------------------
# Step 1: TypeScript types via openapi-typescript (pure JS, lockfile-pinned).
# ---------------------------------------------------------------------------
TS_DIR="${SDK_DIR}/typescript"
TS_OUT="${TS_DIR}/src/types.gen.ts"
if command -v npm >/dev/null 2>&1; then
  log "install TypeScript SDK generator deps from package-lock.json"
  npm --prefix "${TS_DIR}" ci >/dev/null
  log "generate TypeScript types -> ${TS_OUT#"${REPO_ROOT}/"}"
  if [[ "${CHECK}" == "1" ]]; then
    TMP="$(mktemp)"
    npm --prefix "${TS_DIR}" exec -- openapi-typescript "${PINNED}" -o "${TMP}" >/dev/null
    if ! cmp -s "${TMP}" "${TS_OUT}"; then
      rm -f "${TMP}"
      echo "error: ${TS_OUT#"${REPO_ROOT}/"} is stale; run 'make sdk' and commit the diff" >&2
      exit 1
    fi
    rm -f "${TMP}"
  else
    npm --prefix "${TS_DIR}" exec -- openapi-typescript "${PINNED}" -o "${TS_OUT}"
  fi
else
  echo "error: npm not found; TypeScript SDK generation is required" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Python TypedDict aliases from the pinned OpenAPI schemas.
# ---------------------------------------------------------------------------
PY_DIR="${SDK_DIR}/python"
PY_GEN="${PY_DIR}/scripts/gen_types.py"
PY_OUT="${PY_DIR}/src/trstctl_sdk/types.py"
if command -v python3 >/dev/null 2>&1; then
  log "generate Python TypedDicts -> ${PY_OUT#"${REPO_ROOT}/"}"
  if [[ "${CHECK}" == "1" ]]; then
    TMP="$(mktemp)"
    python3 "${PY_GEN}" "${PINNED}" "${TMP}"
    if ! cmp -s "${TMP}" "${PY_OUT}"; then
      rm -f "${TMP}"
      echo "error: ${PY_OUT#"${REPO_ROOT}/"} is stale; run 'make sdk' and commit the diff" >&2
      exit 1
    fi
    rm -f "${TMP}"
  else
    python3 "${PY_GEN}" "${PINNED}" "${PY_OUT}"
  fi
else
  echo "error: python3 not found; Python SDK generation is required" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Java OpenAPI schema index from the pinned OpenAPI schemas.
# ---------------------------------------------------------------------------
JAVA_DIR="${SDK_DIR}/java"
JAVA_GEN="${JAVA_DIR}/scripts/gen_schemas.py"
JAVA_OUT="${JAVA_DIR}/src/main/java/com/trstctl/sdk/OpenApiSchemas.java"
if command -v python3 >/dev/null 2>&1; then
  log "generate Java OpenAPI schema index -> ${JAVA_OUT#"${REPO_ROOT}/"}"
  if [[ "${CHECK}" == "1" ]]; then
    TMP="$(mktemp)"
    python3 "${JAVA_GEN}" "${PINNED}" "${TMP}"
    if ! cmp -s "${TMP}" "${JAVA_OUT}"; then
      rm -f "${TMP}"
      echo "error: ${JAVA_OUT#"${REPO_ROOT}/"} is stale; run 'make sdk' and commit the diff" >&2
      exit 1
    fi
    rm -f "${TMP}"
  else
    python3 "${JAVA_GEN}" "${PINNED}" "${JAVA_OUT}"
  fi
else
  echo "error: python3 not found; Java SDK generation is required" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 4 (OPT-IN only): regenerate the full Go model set via oapi-codegen.
#
# The supported Go surface is the hand-written, dependency-free transport
# (client.go / resources.go / workloads.go / iterator.go) plus curated structs — it imports
# nothing outside the standard library (see clients/sdk/go/go.mod). oapi-codegen's
# output, by contrast, imports github.com/oapi-codegen/runtime, which would break
# that stdlib-only guarantee. So this step is NOT run by default and the
# generated models file ships build-ignored as a reference. Set TRSTCTL_SDK_GO_MODELS=1
# only if you are forking and accept the extra SDK dependency.
# ---------------------------------------------------------------------------
GO_CFG="${SDK_DIR}/go/oapi-codegen.yaml"
if [[ "${TRSTCTL_SDK_GO_MODELS:-0}" == "1" && -f "${GO_CFG}" ]] && command -v go >/dev/null 2>&1; then
  log "generate full Go models via oapi-codegen (opt-in; adds an SDK dependency)"
  ( cd "${SDK_DIR}/go" && go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1 -config "${GO_CFG}" "${PINNED}" ) || \
    echo "warn: oapi-codegen run failed (offline?); the hand-written Go SDK is unaffected" >&2
else
  log "skip optional full Go model generation (hand-written stdlib-only SDK is the supported surface; set TRSTCTL_SDK_GO_MODELS=1 to opt in)"
fi

log "SDK generation complete"
