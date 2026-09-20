#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# PCAS production-caller gate (INT-INV-1: "delivered != tested"), finalized at INT-23.
#
# The PCAS audit (2026-07-06) found every PCAS mechanism was reachable only from
# _test.go — built and unit-tested, but never wired into a running binary. This gate
# makes that machine-checkable and BLOCKING:
#
#   REQUIRED  — every PCAS mechanism that claims delivered status. Each MUST have a
#               non-test caller reachable from the shipped attach/API/outbox/background
#               wiring; a regression to test-only fails the gate.
#
# SCOPE (PCAS-INT-CALL, 2026-08-02): the REQUIRED array below is HAND-WRITTEN, so it can
# only ever prove what someone remembered to add to it. The constructor-shaped half of
# the family no longer depends on it: internal/succession/intgate ENUMERATES every exported
# internal/succession constructor straight from the AST and applies the same non-test-caller
# floor plus a seam tier and an RTA whole-program reachability tier, so a newly added
# constructor cannot hide from the gate. This script is kept as the COMPLEMENT: it covers
# the mechanism entry points that are NOT constructors (Mint, MintPairedThroughSigner,
# IssueLeafCertificate, IssueStapledLeaf, Import, SignEpochCheckpoint,
# BuildPostureReport, ...), which a constructor enumeration cannot see. Both halves run
# under `make pcas-caller-gate`; the RTA tier is `make pcas-caller-gate-strong` in CI.
#
# Run from the repo root; exit 0 = pass. The shipped binary wires the API/outbox/background
# surfaces specified in PCAS-WIRING-DESIGN.md.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

ROOTS=(ee internal cmd)

# count_callers <grep-pattern> <defining-file-substring>
# Non-test .go references to the pattern, excluding the defining file, generated code,
# and comment lines.
count_callers() {
  local pat="$1" deffile="$2"
  grep -rnI --include='*.go' -e "$pat" "${ROOTS[@]}" 2>/dev/null \
    | grep -v '_test\.go:' \
    | grep -v '\.pb\.go:' \
    | grep -v "$deffile" \
    | grep -vE ':[0-9]+:[[:space:]]*(//|\*)' \
    | wc -l | tr -d ' '
}

fail=0
echo "== PCAS production-caller gate (INT-23) =="
echo

# REQUIRED: "pattern|defining-file|label"
REQUIRED=(
  'NewProductionMinter(|internal/succession/signerwiring/wiring.go|signer minter attach (→ minter.New)'
  'successionapi.NewAPIOptionsFactory(|internal/succession/api/api.go|request-succession API factory'
  'successionorch.NewLicensedOutboxFactory(|internal/succession/orchestrator/serverfactory.go|succession outbox worker'
  'recovery.Mint(|internal/succession/recovery/recovery.go|recovery mint worker'
  'MintPairedThroughSigner(|internal/succession/kem/signer_mint.go|KEM-through-signer worker'
  'monitor.New(|internal/succession/monitor/monitor.go|misissuance background monitor'
  'IssueLeafCertificate(|internal/succession/issuer/x509leaf.go|issuer X.509 leaf API'
  'IssueStapledLeaf(|internal/succession/staple/x509carriage.go|stapled X.509 leaf API'
  'federation.Import(|internal/succession/federation/federation.go|federation import worker'
  'NewMinterConstraint(|internal/succession/delegation/delegation.go|delegation minter constraint'
  'SignEpochCheckpoint(|internal/succession/checkpoint.go|checkpoint background signer'
  'BuildPostureReport(|internal/succession/report.go|signed posture API'
  'retirement.New(|internal/succession/retirement/retirement.go|retirement quorum worker'
)

echo "-- REQUIRED (must be wired into a shipped binary) --"
for entry in "${REQUIRED[@]}"; do
  IFS='|' read -r pat deffile label <<<"$entry"
  n=$(count_callers "$pat" "$deffile")
  if [ "$n" -ge 1 ]; then
    printf "  PASS  %-40s %s non-test caller(s)\n" "$label" "$n"
  else
    printf "  FAIL  %-40s 0 non-test callers (regressed to test-only)\n" "$label"
    fail=1
  fi
done
echo

if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAIL — see above."
  exit 1
fi
echo "RESULT: PASS — every delivered PCAS mechanism has a non-test production caller."
exit 0
