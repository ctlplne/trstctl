#!/usr/bin/env bash
# coverage-critical.sh — per-package coverage gate for the security-critical
# packages (SF.1).
#
# The repo-wide gate in `make test` enforces only an *aggregate* floor: the
# average can clear the bar while a critical package quietly rots. This gate
# closes that hole by requiring EACH critical package to independently meet a
# floor, computed from the merged `-coverpkg=./...` profile that `make test`
# already writes (so it sees coverage delivered by cross-package integration
# tests, not just in-package unit tests).
#
# Usage:
#   scripts/ci/coverage-critical.sh [profile]
#
# Inputs (env, with defaults):
#   COVERPROFILE            merged, generated-excluded profile (default cover.out.nogen)
#   CRITICAL_COVERAGE_MIN   per-package floor, percent (default 70)
#   CRITICAL_PKGS           space/newline-separated import paths to gate
#
# Exit status: 0 if every critical package is at or above the floor; 1 otherwise
# (printing each offender). The evaluator (eval_profile) is pure text processing
# over the Go coverprofile format so it can be unit-tested without running Go.

set -euo pipefail

MODULE="${MODULE:-trustctl.io/trustctl}"
CRITICAL_COVERAGE_MIN="${CRITICAL_COVERAGE_MIN:-70}"

# The security-critical packages named in the SF.1 card: the crypto boundary,
# issuance, the outbox, RLS storage, signing, and revocation.
default_pkgs="\
${MODULE}/internal/crypto
${MODULE}/internal/store
${MODULE}/internal/signing
${MODULE}/internal/orchestrator
${MODULE}/internal/ca
${MODULE}/internal/ca/revocation"
CRITICAL_PKGS="${CRITICAL_PKGS:-$default_pkgs}"

# eval_profile <profile> <min> <pkg...>
# Computes per-package statement coverage from a merged -coverpkg profile and
# fails (returns 1) if any named package is below <min> or absent from the
# profile. Coverage lines look like:
#   import/path/file.go:12.34,56.7 3 1
# where field 2 is the statement count for the block and field 3 the exec count.
#
# A merged -coverpkg profile can contain the same source block once per test
# binary. The block's source position is the stable identity; count its
# statements once, and mark it covered if ANY duplicate row has count > 0. This
# matches the meaning operators expect from a merged profile: unique source
# statements covered by the whole test run, not duplicate uncovered copies from
# unrelated test binaries.
eval_profile() {
	local profile="$1" min="$2"
	shift 2
	awk -v min="$min" -v pkglist="$*" '
		function dirname(path,    n, parts, i, out) {
			n = split(path, parts, "/")
			if (n <= 1) return "."
			out = parts[1]
			for (i = 2; i < n; i++) out = out "/" parts[i]
			return out
		}
		BEGIN {
			n = split(pkglist, want, " ")
			for (i = 1; i <= n; i++) { wanted[want[i]] = 1; order[i] = want[i] }
			norder = n
		}
		NR == 1 && $1 ~ /^mode:/ { next }
		{
			# $1 = path:lo.col,hi.col ; $2 = numstmts ; $3 = count.
			block = $1
			path = block
			sub(/:[0-9].*$/, "", path)        # strip the position suffix -> file path
			stmts = $2 + 0
			if (!(block in seen)) {
				seen[block] = 1
				blocks[++nblocks] = block
				block_dir[block] = dirname(path)
				block_stmts[block] = stmts
			}
			if (($3 + 0) > 0) block_covered[block] = 1
		}
		END {
			for (i = 1; i <= nblocks; i++) {
				b = blocks[i]
				dir = block_dir[b]
				stmts = block_stmts[b]
				total[dir] += stmts
				if (block_covered[b]) covered[dir] += stmts
			}
			fail = 0
			for (i = 1; i <= norder; i++) {
				p = order[i]
				if (!(p in total) || total[p] == 0) {
					printf "FAIL: critical package %s has no coverage data in the profile\n", p
					fail = 1
					continue
				}
				pct = 100.0 * covered[p] / total[p]
				if (pct + 0 < min + 0) {
					printf "FAIL: %s coverage %.1f%% is below the required %d%% (critical package)\n", p, pct, min
					fail = 1
				} else {
					printf "ok:   %s %.1f%%\n", p, pct
				}
			}
			exit fail
		}
	' "$profile"
}

main() {
	local profile="${1:-${COVERPROFILE:-cover.out.nogen}}"
	if [[ ! -f "$profile" ]]; then
		echo "coverage-critical: profile '$profile' not found — run 'make test' first (it writes the merged profile)." >&2
		exit 2
	fi
	echo ">> critical-package coverage gate (minimum ${CRITICAL_COVERAGE_MIN}% per package)"
	# shellcheck disable=SC2086
	eval_profile "$profile" "$CRITICAL_COVERAGE_MIN" $CRITICAL_PKGS
}

# Only run main when executed directly, so the self-test can source the
# evaluator without triggering a profile read.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
