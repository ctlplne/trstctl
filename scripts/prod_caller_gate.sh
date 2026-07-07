#!/usr/bin/env bash
# prod_caller_gate.sh — PCAS production-caller gate (INT-23).
#
# A PCAS mechanism is only DELIVERED if it is reachable from a running binary, not just
# from tests. This gate enforces that for the named PCAS entry points by checking each
# one has (or, for wiring-deferred mechanisms, does NOT yet have) a non-test caller
# outside its own defining file.
#
# Two tiers:
#   REQUIRED  — must have >= 1 non-test caller. These are on the shipped critical path
#               (mint over the isolated signer, the request-succession API, the
#               succession outbox worker). A REQUIRED mechanism that becomes test-only is
#               a regression and FAILS the gate.
#   DEFERRED  — real + unit/integration-tested, but the production call-path is blocked on
#               the Phase-5 real-infra e2e (INT-20: real PG + NATS + cross-process signer +
#               scheduled workers). Each is listed with a reason and MUST currently have
#               zero non-test callers. When INT-20 wires one, this gate FAILS on it —
#               that is the forcing function to PROMOTE it to REQUIRED and mark its claim
#               DELIVERED in the traceability matrix.
#
# Usage: scripts/prod_caller_gate.sh   (run from the repo root; exit 0 = pass)

set -uo pipefail
cd "$(dirname "$0")/.."

# Search roots for non-test production code.
ROOTS=(ee internal cmd)

# count_callers <grep-pattern> <defining-file-substring>
# Counts non-test .go references to the pattern, excluding the defining file.
count_callers() {
  local pat="$1" deffile="$2"
  grep -rn --include='*.go' -e "$pat" "${ROOTS[@]}" 2>/dev/null \
    | grep -v '_test\.go:' \
    | grep -v "$deffile" \
    | grep -Ev ':[0-9]+:[[:space:]]*//' \
    | wc -l | tr -d ' '
}

fail=0

echo "== PCAS production-caller gate =="
echo

# --- REQUIRED: must have a non-test caller (shipped critical path) ---
# Format: "pattern|defining-file|label"
REQUIRED=(
  'NewProductionMinter(|ee/succession/signerwiring/wiring.go|signer minter attach (→ minter.New)'
  'eesuccessionapi.NewAPIOptionsFactory(|ee/succession/api/api.go|request-succession API factory'
  'eesuccessionorch.NewLicensedOutboxFactory(|ee/succession/orchestrator/serverfactory.go|succession outbox worker'
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

# --- DEFERRED: must currently be test-only; a new prod caller means "promote me" ---
# Format: "pattern|defining-file|reason"
DEFERRED=(
  'recovery.Mint(|ee/succession/recovery/recovery.go|recovery mint needs the m-of-n API/worker path (INT-20)'
  'MintPairedThroughSigner(|ee/succession/kem/signer_mint.go|KEM-through-signer needs the served-signer keystore path (INT-12 deferral)'
  'monitor.New(|ee/succession/monitor/monitor.go|misissuance monitor needs a scheduled worker over real ledger (INT-20)'
  'IssueLeafCertificate(|ee/succession/issuer/x509leaf.go|issuer real-leaf needs the CA issuance path wired (INT-20)'
  'IssueStapledLeaf(|ee/succession/staple/x509carriage.go|stapled-leaf needs a serving path (INT-20)'
  'federation.Import(|ee/succession/federation/federation.go|federation import needs the bridge API/worker (INT-20)'
  'NewMinterConstraint(|ee/succession/delegation/delegation.go|delegation constraint needs wiring into the production minter attach (INT-20)'
  'SignEpochCheckpoint(|ee/succession/checkpoint.go|checkpoint emitter needs a scheduled worker (INT-19/20)'
  'BuildPostureReport(|ee/succession/report.go|posture report needs API exposure (INT-19/20)'
)

echo "-- DEFERRED (real + tested; production wiring blocked on INT-20 real infra) --"
for entry in "${DEFERRED[@]}"; do
  IFS='|' read -r pat deffile reason <<<"$entry"
  n=$(count_callers "$pat" "$deffile")
  if [ "$n" -eq 0 ]; then
    printf "  OK    %-32s test-only — %s\n" "${pat%(*}" "$reason"
  else
    printf "  FAIL  %-32s now has %s non-test caller(s): PROMOTE to REQUIRED + mark claim DELIVERED\n" "${pat%(*}" "$n"
    fail=1
  fi
done
echo

if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAIL — see above."
  exit 1
fi
echo "RESULT: PASS — every shipped-critical-path mechanism has a non-test caller;"
echo "        every deferred mechanism is honestly still test-only (tracked for INT-20)."
exit 0
