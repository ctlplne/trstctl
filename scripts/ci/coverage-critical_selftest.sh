#!/usr/bin/env bash
# Self-test for the critical-package coverage gate (SF.1 acceptance:
# "the branch-coverage gate fails on a critical package taken below threshold").
#
# Feeds the pure evaluator synthetic coverprofiles and asserts it passes when
# every critical package clears the floor and fails when one is dragged under,
# or is missing from the profile entirely. Also covers the per-package `=NN`
# floor override (TEST-COVFLOOR-002) and the two-tier reporting contract in
# main(). Runs without invoking Go.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${here}/coverage-critical.sh"

MOD="trstctl.com/trstctl"
fails=0
check() { # check <desc> <expected-exit> <actual-exit>
	if [[ "$2" == "$3" ]]; then
		echo "PASS: $1"
	else
		echo "FAIL: $1 (expected exit $2, got $3)"
		fails=1
	fi
}
check_contains() { # check_contains <desc> <needle> <haystack>
	if [[ "$3" == *"$2"* ]]; then
		echo "PASS: $1"
	else
		echo "FAIL: $1 (output did not contain $2)"
		fails=1
	fi
}

# A profile where internal/crypto is 3/4 = 75% (>= 70 floor).
pass_profile="$(mktemp)"
cat >"$pass_profile" <<EOF
mode: atomic
${MOD}/internal/crypto/a.go:1.1,2.1 2 1
${MOD}/internal/crypto/a.go:3.1,4.1 1 1
${MOD}/internal/crypto/b.go:1.1,2.1 1 0
EOF

# Same, but internal/crypto dragged to 1/4 = 25% (< 70 floor).
fail_profile="$(mktemp)"
cat >"$fail_profile" <<EOF
mode: atomic
${MOD}/internal/crypto/a.go:1.1,2.1 2 0
${MOD}/internal/crypto/a.go:3.1,4.1 1 0
${MOD}/internal/crypto/b.go:1.1,2.1 1 1
EOF

# A profile that omits the critical package entirely (must fail, not pass-by-absence).
absent_profile="$(mktemp)"
cat >"$absent_profile" <<EOF
mode: atomic
${MOD}/internal/somethingelse/a.go:1.1,2.1 2 1
EOF

# A merged -coverpkg profile can contain duplicate rows for the same source block
# from different package test binaries. The unique block below is covered once and
# uncovered once; it must count as 2/4 covered overall (50%), not 2/6 (33%) after
# double-counting the duplicate zero row.
duplicate_profile="$(mktemp)"
cat >"$duplicate_profile" <<EOF
mode: atomic
${MOD}/internal/crypto/a.go:1.1,2.1 2 0
${MOD}/internal/crypto/a.go:1.1,2.1 2 1
${MOD}/internal/crypto/b.go:1.1,2.1 2 0
EOF

# Two gated packages, each 3/4 = 75%: one for each tier of the main() report.
two_tier_profile="$(mktemp)"
cat >"$two_tier_profile" <<EOF
mode: atomic
${MOD}/internal/crypto/a.go:1.1,2.1 2 1
${MOD}/internal/crypto/a.go:3.1,4.1 1 1
${MOD}/internal/crypto/b.go:1.1,2.1 1 0
${MOD}/internal/events/a.go:1.1,2.1 2 1
${MOD}/internal/events/a.go:3.1,4.1 1 1
${MOD}/internal/events/b.go:1.1,2.1 1 0
EOF

set +e
eval_profile "$pass_profile" 70 "${MOD}/internal/crypto" >/dev/null; check "passes when critical pkg >= floor" 0 $?
eval_profile "$fail_profile" 70 "${MOD}/internal/crypto" >/dev/null; check "fails when critical pkg < floor" 1 $?
eval_profile "$absent_profile" 70 "${MOD}/internal/crypto" >/dev/null; check "fails when critical pkg absent from profile" 1 $?
# Exact-boundary: 75% must clear a 75 floor (>=, not >).
eval_profile "$pass_profile" 75 "${MOD}/internal/crypto" >/dev/null; check "passes at exact floor (75>=75)" 0 $?
eval_profile "$pass_profile" 76 "${MOD}/internal/crypto" >/dev/null; check "fails just above (75<76)" 1 $?
eval_profile "$duplicate_profile" 50 "${MOD}/internal/crypto" >/dev/null; check "deduplicates merged -coverpkg rows before package aggregation" 0 $?
eval_profile "$duplicate_profile" 51 "${MOD}/internal/crypto" >/dev/null; check "deduplicated merged profile still fails above real coverage" 1 $?

# TEST-COVFLOOR-002: a per-package `=NN` entry overrides the tier default in both
# directions, so a strong package can be ratcheted without dragging the tier
# default above its weakest member.
eval_profile "$pass_profile" 50 "${MOD}/internal/crypto=75" >/dev/null; check "per-package floor overrides a lower tier default" 0 $?
eval_profile "$pass_profile" 50 "${MOD}/internal/crypto=76" >/dev/null; check "per-package floor bites above measured coverage" 1 $?
# Mixed list: the overridden package clears its own 70, the bare package is held
# to the 80 tier default and fails. Proves the two mechanisms coexist.
eval_profile "$two_tier_profile" 80 "${MOD}/internal/crypto=70" "${MOD}/internal/events" >/dev/null
check "bare entries still take the tier default alongside an override" 1 $?

# TEST-COVFLOOR-002: main() must evaluate and report BOTH tiers even when tier-1
# fails. `set -e` is deliberately re-enabled inside the subshell so this runs
# under the same errexit regime as a real `bash scripts/ci/coverage-critical.sh`.
both_tiers_out="$(
	set -e
	CRITICAL_PKGS="${MOD}/internal/crypto"
	CRITICAL_COVERAGE_MIN=90
	CRITICAL_PKGS_TIER2="${MOD}/internal/events"
	CRITICAL_COVERAGE_MIN_TIER2=70
	main "$two_tier_profile" 2>&1
)"
both_tiers_rc=$?
check "main() exits 1 when a tier-1 package is below its floor" 1 "$both_tiers_rc"
check_contains "main() reports the tier-1 offender" \
	"FAIL: ${MOD}/internal/crypto coverage 75.0% is below the required 90%" "$both_tiers_out"
check_contains "main() still prints the tier-2 header after a tier-1 failure" \
	">> critical-package coverage gate (tier-2 minimum 70% per package)" "$both_tiers_out"
check_contains "main() still evaluates tier-2 packages after a tier-1 failure" \
	"ok:   ${MOD}/internal/events 75.0% (floor 70%)" "$both_tiers_out"
set -e

rm -f "$pass_profile" "$fail_profile" "$absent_profile" "$duplicate_profile" "$two_tier_profile"
if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
