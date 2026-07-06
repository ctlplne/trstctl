#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-trstctl-EE
#
# PCAS production-caller gate (INT-INV-1: "delivered != tested").
#
# The PCAS audit (2026-07-06) found every PCAS mechanism was reachable only from
# _test.go — built and unit-tested, but never wired into a running binary. This
# gate fails if a PCAS entry point has no NON-TEST caller, so a mechanism cannot be
# marked delivered on the strength of a passing unit test alone.
#
# It is ADVISORY during the PCAS-INT harness (many rows are red until their wiring
# card lands) and becomes BLOCKING at INT-23. Run from the repo root.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

# Qualified call-site patterns that must appear in at least one non-test .go file.
# Format: "call-pattern<TAB>delivering-card".
CHECKS=$(cat <<'EOF'
WithSuccessionMinter(	INT-02 (attach minter in signer binary)
NewProductionMinter(	INT-02 (production minter construction)
NewLicensedOutboxFactory(	INT-03/04 (succession worker registered on server outbox)
retirement.New(	INT-17 (retirement worker)
recovery.Mint(	INT-18 (recovery API/worker)
issuer.IssueLeaf(	INT-14 (issuer succession)
staple.VerifyStapled(	INT-15 (stapling carriage)
federation.Import(	INT-18 (federation import)
GenerateKEMKey(	INT-12 (KEM through the signer)
EOF
)

fail=0
printf '%-26s %-8s %s\n' "ENTRY POINT" "STATUS" "DELIVERING CARD"
printf '%-26s %-8s %s\n' "----------" "------" "---------------"
while IFS=$'\t' read -r pat card; do
  [ -z "${pat:-}" ] && continue
  # Count CALL sites in the product trees (ee/, cmd/): non-test, non-generated,
  # excluding `func ` declarations and comment lines so a symbol's own definition
  # does not count as its own caller. internal/ is excluded so the signer's client
  # plumbing does not mask a missing worker/consumer.
  hits=$(grep -rInI --include='*.go' -e "$pat" ee cmd 2>/dev/null \
           | grep -v '_test\.go:' | grep -v '\.pb\.go:' \
           | grep -vE ':[0-9]+:[[:space:]]*(//|\*|func )' \
           | wc -l | tr -d ' ')
  if [ "$hits" -gt 0 ]; then
    printf '%-26s %-8s %s\n' "${pat}" "WIRED" "$card"
  else
    printf '%-26s %-8s %s\n' "${pat}" "UNWIRED" "$card"
    fail=1
  fi
done <<< "$CHECKS"

if [ "$fail" -ne 0 ]; then
  echo
  echo ">> UNWIRED entry points remain (expected during PCAS-INT; BLOCKING at INT-23)."
fi
exit "$fail"
