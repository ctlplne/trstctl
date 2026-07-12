#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-trstctl-EE
#
# Self-test for pcas_no_skip_gate.sh (TEST-NOSKIP-001): prove the gate FAILS
# when a gate-tagged package gains a t.Skip, and PASSES when none is present.
# Runs the real gate against a temporary GATE_DIRS so it never mutates the repo.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="${here}/pcas_no_skip_gate.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The gate cd's to the repo root and greps GATE_DIRS relative to it, so lay the
# fixture packages out under a throwaway repo root.
mkdir -p "$tmp/scripts" "$tmp/gatepkg"
cp "$gate" "$tmp/scripts/pcas_no_skip_gate.sh"

# Point the copied gate at our fixture dir.
sed -i 's#^GATE_DIRS=.*#GATE_DIRS="gatepkg"#' "$tmp/scripts/pcas_no_skip_gate.sh"

# 1. Clean gate package: PASS.
cat > "$tmp/gatepkg/clean_test.go" <<'EOF'
package gatepkg

import "testing"

func TestReal(t *testing.T) {
	if 1+1 != 2 {
		t.Fatal("math broke")
	}
}
EOF
( cd "$tmp" && bash scripts/pcas_no_skip_gate.sh >/dev/null 2>&1 ) \
	|| { echo "FAIL: clean gate package was rejected"; exit 1; }

# 2. A t.Skip sneaks into a gate package: FAIL.
cat > "$tmp/gatepkg/skip_test.go" <<'EOF'
package gatepkg

import "testing"

func TestSkips(t *testing.T) {
	t.Skip("no infra")
}
EOF
if ( cd "$tmp" && bash scripts/pcas_no_skip_gate.sh >/dev/null 2>&1 ); then
	echo "FAIL: a t.Skip in a gate package was NOT caught"
	exit 1
fi

echo ">> pcas_no_skip_gate selftest: catches an added t.Skip, passes when clean"
