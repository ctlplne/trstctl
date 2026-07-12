#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-trstctl-EE
#
# PCAS no-skip gate (INT-INV-4): a gate/e2e test that t.Skip()s over missing
# infrastructure is not a gate. This fails if any PCAS gate package contains a
# t.Skip, so the full-stack conformance/e2e path (INT-20) cannot silently degrade
# to in-memory when real PostgreSQL / NATS / WASM are absent.
#
# BLOCKING: INT-20/23 require real gate tests to fail, not skip, when infra is missing.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

# Packages whose tests are release GATES and must run over real infrastructure.
# Every release-GATE and real-infra WIRE-GATE package: a t.Skip in any of these
# is a gate that silently degrades when its substrate is absent (TEST-NOSKIP-001).
GATE_DIRS="ee/succession/conformance ee/succession/signerwiring ee/agentid/intwire ee/decommission/intwire ee/reconcile/intwire"

hits=$(grep -rn --include='*_test.go' -e 't\.Skip' $GATE_DIRS 2>/dev/null)
if [ -n "$hits" ]; then
  echo ">> t.Skip present in PCAS gate tests (a gate must not skip on missing infra):"
  echo "$hits"
  exit 1
fi
echo ">> no t.Skip in PCAS gate packages ($GATE_DIRS)"
exit 0
