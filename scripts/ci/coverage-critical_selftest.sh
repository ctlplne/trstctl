#!/usr/bin/env bash
# Self-test for the critical-package coverage gate (SF.1 acceptance:
# "the branch-coverage gate fails on a critical package taken below threshold").
#
# Feeds the pure evaluator synthetic coverprofiles and asserts it passes when
# every critical package clears the floor and fails when one is dragged under,
# or is missing from the profile entirely. Runs without invoking Go.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${here}/coverage-critical.sh"

MOD="trustctl.io/trustctl"
fails=0
check() { # check <desc> <expected-exit> <actual-exit>
	if [[ "$2" == "$3" ]]; then
		echo "PASS: $1"
	else
		echo "FAIL: $1 (expected exit $2, got $3)"
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

set +e
eval_profile "$pass_profile" 70 "${MOD}/internal/crypto" >/dev/null; check "passes when critical pkg >= floor" 0 $?
eval_profile "$fail_profile" 70 "${MOD}/internal/crypto" >/dev/null; check "fails when critical pkg < floor" 1 $?
eval_profile "$absent_profile" 70 "${MOD}/internal/crypto" >/dev/null; check "fails when critical pkg absent from profile" 1 $?
# Exact-boundary: 75% must clear a 75 floor (>=, not >).
eval_profile "$pass_profile" 75 "${MOD}/internal/crypto" >/dev/null; check "passes at exact floor (75>=75)" 0 $?
eval_profile "$pass_profile" 76 "${MOD}/internal/crypto" >/dev/null; check "fails just above (75<76)" 1 $?
set -e

rm -f "$pass_profile" "$fail_profile" "$absent_profile"
if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
