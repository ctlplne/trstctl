#!/usr/bin/env bash
# Self-test for the assembled-server lifecycle coverage floor (TEST-007: the
# gate-of-the-gate the audit flagged as missing — coverage-critical and
# check-base-pinned had self-tests, this inline Makefile floor did not).
#
# Feeds eval_lifecycle synthetic `go tool cover -func` output and asserts it:
#   - PASSES when all four lifecycle funcs are present and each clears the floor,
#   - FAILS when one func is below the floor,
#   - FAILS when one func is missing from the profile (count < 4),
#   - respects the exact >= boundary.
# Runs without invoking Go.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${here}/coverage-server-lifecycle.sh"

MOD="trstctl.com/trstctl"
FILE_RE='/internal/server/server[.]go:'
FUNCS='Build|IssueLeaf|Drain|Shutdown'
fails=0
check() { # check <desc> <expected-exit> <actual-exit>
	if [[ "$2" == "$3" ]]; then
		echo "PASS: $1"
	else
		echo "FAIL: $1 (expected exit $2, got $3)"
		fails=1
	fi
}

# All four present and >= 70%.
all_pass="$(mktemp)"
cat >"$all_pass" <<EOF
${MOD}/internal/server/server.go:10:	Build	85.0%
${MOD}/internal/server/server.go:40:	IssueLeaf	92.3%
${MOD}/internal/server/server.go:80:	Drain	71.0%
${MOD}/internal/server/server.go:120:	Shutdown	100.0%
${MOD}/internal/server/server.go:5:	New	66.6%
${MOD}/internal/server/other.go:3:	helper	0.0%
EOF

# One lifecycle func (Drain) dragged below the floor.
one_below="$(mktemp)"
cat >"$one_below" <<EOF
${MOD}/internal/server/server.go:10:	Build	85.0%
${MOD}/internal/server/server.go:40:	IssueLeaf	92.3%
${MOD}/internal/server/server.go:80:	Drain	12.5%
${MOD}/internal/server/server.go:120:	Shutdown	100.0%
EOF

# One lifecycle func (Shutdown) missing entirely (the e2e dropped out of the merge).
one_missing="$(mktemp)"
cat >"$one_missing" <<EOF
${MOD}/internal/server/server.go:10:	Build	85.0%
${MOD}/internal/server/server.go:40:	IssueLeaf	92.3%
${MOD}/internal/server/server.go:80:	Drain	71.0%
EOF

# Exact-boundary profile: every func exactly at 70%.
exact="$(mktemp)"
cat >"$exact" <<EOF
${MOD}/internal/server/server.go:10:	Build	70.0%
${MOD}/internal/server/server.go:40:	IssueLeaf	70.0%
${MOD}/internal/server/server.go:80:	Drain	70.0%
${MOD}/internal/server/server.go:120:	Shutdown	70.0%
EOF

set +e
eval_lifecycle "$all_pass" "$FILE_RE" "$FUNCS" 70 4 >/dev/null;  check "passes when all 4 present and >= floor" 0 $?
eval_lifecycle "$one_below" "$FILE_RE" "$FUNCS" 70 4 >/dev/null; check "fails when one func is below the floor" 1 $?
eval_lifecycle "$one_missing" "$FILE_RE" "$FUNCS" 70 4 >/dev/null; check "fails when one func is missing (count < 4)" 1 $?
eval_lifecycle "$exact" "$FILE_RE" "$FUNCS" 70 4 >/dev/null;     check "passes at the exact floor (70>=70)" 0 $?
eval_lifecycle "$exact" "$FILE_RE" "$FUNCS" 71 4 >/dev/null;     check "fails just above the floor (70<71)" 1 $?
set -e

rm -f "$all_pass" "$one_below" "$one_missing" "$exact"
if [[ "$fails" -ne 0 ]]; then echo "SELF-TEST FAILED"; exit 1; fi
echo "ALL SELF-TESTS PASSED"
