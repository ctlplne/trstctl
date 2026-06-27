#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

module='trstctl.com/trstctl'
allowlist='cmd/trstctl/ee_attach.go'

is_allowlisted() {
  local f="${1#./}"
  for a in ${allowlist}; do
    [ "${f}" = "${a}" ] && return 0
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
  echo "Core may never import ee/. The only exception is cmd/trstctl/ee_attach.go," >&2
  echo "and that file must carry //go:build !trstctl_core." >&2
  exit 1
fi

echo "editions guard: OK (core never imports ee/; the attach seam is tagged)"
