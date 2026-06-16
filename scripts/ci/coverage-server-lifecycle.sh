#!/usr/bin/env bash
# coverage-server-lifecycle.sh — the assembled-control-plane lifecycle coverage floor
# (R4.3), extracted from the inline `make test` awk so it can be self-tested
# (TEST-007: the gate-of-the-gate, like coverage-critical.sh).
#
# The four core lifecycle functions of the assembled server (server.Build /
# server.IssueLeaf / server.Drain / server.Shutdown) read ~0% IN-PACKAGE but are
# exercised by the cross-package projections e2e under `-coverpkg=./...`; this floor
# surfaces and guards their REAL merged coverage so CI reports the assembled server
# honestly, not the misleading in-package figure. The gate also fails if fewer than
# all four functions are present in the profile (a regression that dropped the e2e
# from the merged run, hiding the number).
#
# Input: the output of `go tool cover -func=<merged-profile>`, whose lines look like
#   trstctl.com/trstctl/internal/server/server.go:123:\tBuild\t85.0%
# i.e. field 1 = file:line:, field 2 = function name, field 3 = NN.N%.
#
# Usage:
#   go tool cover -func=cover.out.nogen | scripts/ci/coverage-server-lifecycle.sh
#   scripts/ci/coverage-server-lifecycle.sh <func-output-file>
#
# Env (with defaults):
#   SERVER_FILE_RE             regex matching the server.go path (default below)
#   SERVER_LIFECYCLE_FUNCS     '|'-separated function names (default Build|IssueLeaf|Drain|Shutdown)
#   SERVER_FUNC_COVERAGE_MIN   per-function floor, percent (default 70)
#   SERVER_LIFECYCLE_COUNT     how many of the funcs must be present (default 4)
#
# Exit: 0 if all named lifecycle funcs are present AND each is at/above the floor; 1
# otherwise. eval_lifecycle is pure text processing so the self-test runs without Go.

set -euo pipefail

# Use a bracket class for the literal dot so awk does not warn about `\.`.
SERVER_FILE_RE="${SERVER_FILE_RE:-/internal/server/server[.]go:}"
SERVER_LIFECYCLE_FUNCS="${SERVER_LIFECYCLE_FUNCS:-Build|IssueLeaf|Drain|Shutdown}"
SERVER_FUNC_COVERAGE_MIN="${SERVER_FUNC_COVERAGE_MIN:-70}"
SERVER_LIFECYCLE_COUNT="${SERVER_LIFECYCLE_COUNT:-4}"

# eval_lifecycle <func-output-file> <file-re> <funcs-re> <min> <expected-count>
# Reads `go tool cover -func` output and enforces the lifecycle floor. funcs-re is a
# '|'-separated function list (e.g. Build|IssueLeaf|Drain|Shutdown); it is anchored to
# a whole-field match inside awk so a function named e.g. "Buildable" is not matched.
eval_lifecycle() {
	local input="$1" filere="$2" funcsre="$3" min="$4" want="$5"
	awk -v filere="$filere" -v funcsre="$funcsre" -v m="$min" -v want="$want" '
		BEGIN { anchored = "^(" funcsre ")$" }
		$1 ~ filere && $2 ~ anchored {
			seen++
			cov = $3
			sub(/%$/, "", cov)
			if (cov + 0 < m + 0) {
				bad++
				printf "FAIL: internal/server %s coverage %s is below the required %d%% (assembled fail-closed/drain branches regressed, or were measured in-package only)\n", $2, $3, m
			} else {
				printf "ok:   internal/server %s %s\n", $2, $3
			}
		}
		END {
			if (seen + 0 < want + 0) {
				printf "FAIL: expected %d assembled-lifecycle functions in the merged profile, saw %d (did the cross-package e2e run under -coverpkg=./...?)\n", want, seen + 0
				exit 1
			}
			if (bad) exit 1
		}
	' "$input"
}

main() {
	local input="${1:-/dev/stdin}"
	echo ">> assembled-server lifecycle coverage floor (each of ${SERVER_LIFECYCLE_FUNCS} >= ${SERVER_FUNC_COVERAGE_MIN}%, all ${SERVER_LIFECYCLE_COUNT} present)"
	eval_lifecycle "$input" "$SERVER_FILE_RE" "$SERVER_LIFECYCLE_FUNCS" "$SERVER_FUNC_COVERAGE_MIN" "$SERVER_LIFECYCLE_COUNT"
}

# Only run main when executed directly so the self-test can source eval_lifecycle.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
