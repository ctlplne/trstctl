#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="${TRSTCTL_KSP_CHECKER:-$root/scripts/ci/check-ksp-dll.sh}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

cat > "$scratch/valid" <<'EOF'
DLL Name: KERNEL32.dll
DLL Name: msvcrt.dll
The Export Tables (interpreted .edata section contents)
  [Ordinal/Name Pointer] Table (MinGW export view)
	          Ordinal   Hint Name
	[   0] +base[   1]  0000 GetKeyStorageInterface
	[   1] +base[   2]  0001 kspDecrypt
EOF

"$checker" "$scratch/valid" > "$scratch/output" || {
  echo 'valid MinGW PE export table was rejected' >&2
  exit 1
}

sed '/\[Ordinal\/Name Pointer\] Table/d' "$scratch/valid" > "$scratch/no-table"
if "$checker" "$scratch/no-table" > "$scratch/output" 2>&1; then
  echo 'export text outside the PE export table was accepted' >&2
  exit 1
fi

sed 's/0000 GetKeyStorageInterface/0000 NotTheKSPEntryPoint/' "$scratch/valid" > "$scratch/no-entry"
if "$checker" "$scratch/no-entry" > "$scratch/output" 2>&1; then
  echo 'a PE export table without the CNG entry point was accepted' >&2
  exit 1
fi

sed 's/msvcrt.dll/foreign.dll/' "$scratch/valid" > "$scratch/foreign-import"
if "$checker" "$scratch/foreign-import" > "$scratch/output" 2>&1; then
  echo 'a PE DLL with an unapproved import was accepted' >&2
  exit 1
fi

echo 'KSP PE export and import checker self-test passed'
