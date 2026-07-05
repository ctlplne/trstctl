#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

module='trstctl.com/trstctl'
# Tagged attach seams: the only core files permitted to import ee/. Each must
# carry //go:build !trstctl_core so the core-only build links zero ee/ packages.
# The signer-side seam (cmd/trstctl-signer/ee_attach.go) follows the FeaturePQC
# precedent and is the home for signing.WithSuccessionMinter(...) et al.
allowlist='cmd/trstctl/ee_attach.go cmd/trstctl-signer/ee_attach.go'
# Files that mention ee/ import paths only inside string-literal *fixtures*
# (test data written into a temp tree at runtime), not as real imports of the
# file's own package. The AST-level licenseboundary analyzer in tools/trstctllint
# enforces the real rule for compiled code; this grep-based guard skips the
# fixtures so it does not false-positive on them.
fixture_excludes='tools/trstctllint/repo_selftest_test.go'

is_allowlisted() {
  local f="${1#./}"
  for a in ${allowlist}; do
    [ "${f}" = "${a}" ] && return 0
  done
  return 1
}

is_fixture_excluded() {
  local f="${1#./}"
  for x in ${fixture_excludes}; do
    [ "${f}" = "${x}" ] && return 0
  done
  return 1
}

find_imports() {
  grep -rEn \
    "^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_.]*[[:space:]]+)?\"${module}/ee(/[^\"]*)?\"" \
    --include='*.go' . | grep -v '^\./ee/' || true
}

check() {
  local out=""
  while IFS= read -r line; do
    [ -z "${line}" ] && continue
    local f="${line%%:*}"
    if is_allowlisted "${f}"; then
      if ! grep -qE '^//go:build .*!trstctl_core' "${f}"; then
        out="${out}${f}: allowlisted ee attach seam MISSING the //go:build !trstctl_core constraint
"
      fi
    elif is_fixture_excluded "${f}"; then
      continue
    else
      out="${out}${line}
"
    fi
  done <<EOF
$(find_imports)
EOF
  printf '%s' "${out}"
}

if [ "${SELFTEST:-0}" = "1" ]; then
  tmp="internal/editions_guard_selftest_tmp.go"
  rm -f "${tmp}"
  trap 'rm -f "${tmp}"' EXIT
  cat > "${tmp}" <<EOF
package internal

import _ "${module}/ee"
EOF
  if [ -z "$(check)" ]; then
    echo "editions-guard SELF-TEST FAILED: planted core->ee import was not detected" >&2
    exit 1
  fi
  rm -f "${tmp}"
  trap - EXIT

  seam="cmd/trstctl/ee_attach.go"
  backup=""
  restore_seam() {
    if [ -n "${backup}" ] && [ -f "${backup}" ]; then
      mv "${backup}" "${seam}"
    else
      rm -f "${seam}"
    fi
  }
  if [ -f "${seam}" ]; then
    backup="$(mktemp "${TMPDIR:-/tmp}/trstctl-ee-attach.XXXXXX")"
    cp "${seam}" "${backup}"
  fi
  trap restore_seam EXIT
  cat > "${seam}" <<EOF
package main

import _ "${module}/ee"
EOF
  if ! check | grep -q 'MISSING the //go:build !trstctl_core'; then
    echo "editions-guard SELF-TEST FAILED: planted untagged attach seam was not detected" >&2
    exit 1
  fi
  restore_seam
  trap - EXIT
  echo "editions-guard self-test: OK (planted violations detected)"
fi

violations="$(check)"
if [ -n "${violations}" ]; then
  echo "FORBIDDEN ee/ imports outside the tagged attach seam:" >&2
  echo "${violations}" >&2
  echo "" >&2
  echo "Core may never import ee/. The only exceptions are the tagged attach seams" >&2
  echo "(cmd/trstctl/ee_attach.go, cmd/trstctl-signer/ee_attach.go), each of which" >&2
  echo "must carry //go:build !trstctl_core." >&2
  exit 1
fi

echo "editions guard: OK (core never imports ee/; the attach seam is tagged)"
