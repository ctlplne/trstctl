#!/usr/bin/env bash
# Self-test for compose-e2e.sh portable UUID generation (OPS-006).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash_path="$(command -v bash)"
tr_path="$(command -v tr)"

fails=0
check() { if [[ "$2" == "$3" ]]; then echo "PASS: $1"; else echo "FAIL: $1 (want '$2', got '$3')"; fails=1; fi; }
check_uuid() {
  local label="$1" uuid="$2"
  if [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "PASS: ${label}"
  else
    echo "FAIL: ${label} (not UUID-like: ${uuid})"
    fails=1
  fi
}

read_kv() {
  local out="$1" key want_prefix="$2"
  while IFS='=' read -r key value; do
    case "$key" in
      "$want_prefix") printf '%s\n' "$value"; return 0 ;;
    esac
  done <<<"$out"
  return 1
}

run_uuid_mode() {
  local path="$1"
  COMPOSE_E2E_UUID_SELFTEST=1 PATH="$path" "$bash_path" "${here}/compose-e2e.sh"
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

uuidgen_bin="$tmp/uuidgen-bin"
mkdir -p "$uuidgen_bin"
ln -s "$tr_path" "$uuidgen_bin/tr"
cat >"$uuidgen_bin/uuidgen" <<'EOF'
#!/bin/sh
printf '%s\n' '123E4567-E89B-42D3-A456-426614174000'
EOF
chmod +x "$uuidgen_bin/uuidgen"

out="$(run_uuid_mode "$uuidgen_bin")"
tenant="$(read_kv "$out" TENANT)"
idem_base="$(read_kv "$out" IDEM_BASE)"
check "uuidgen fallback lowercases TENANT" "123e4567-e89b-42d3-a456-426614174000" "$tenant"
check "uuidgen fallback prefixes IDEM_BASE" "e2e-123e4567-e89b-42d3-a456-426614174000" "$idem_base"
check_uuid "uuidgen TENANT is UUID-like" "$tenant"
check_uuid "uuidgen IDEM_BASE suffix is UUID-like" "${idem_base#e2e-}"

python_bin="$tmp/python-bin"
mkdir -p "$python_bin"
ln -s "$tr_path" "$python_bin/tr"
cat >"$python_bin/python3" <<'EOF'
#!/bin/sh
printf '%s\n' '123e4567-e89b-42d3-a456-426614174001'
EOF
chmod +x "$python_bin/python3"

out="$(run_uuid_mode "$python_bin")"
tenant="$(read_kv "$out" TENANT)"
idem_base="$(read_kv "$out" IDEM_BASE)"
check "python fallback sets TENANT" "123e4567-e89b-42d3-a456-426614174001" "$tenant"
check "python fallback prefixes IDEM_BASE" "e2e-123e4567-e89b-42d3-a456-426614174001" "$idem_base"
check_uuid "python TENANT is UUID-like" "$tenant"
check_uuid "python IDEM_BASE suffix is UUID-like" "${idem_base#e2e-}"

if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
