#!/usr/bin/env bash
# coverage-critical.sh — per-package coverage gate for the security-critical
# packages (SF.1).
#
# The repo-wide gate in `make test` enforces only an *aggregate* floor: the
# average can clear the bar while a critical package quietly rots. This gate
# closes that hole by requiring EACH critical package to independently meet a
# floor, computed from the merged `-coverpkg=$(GO_COVER_PACKAGES)` profile that `make test`
# already writes (so it sees coverage delivered by cross-package integration
# tests, not just in-package unit tests).
#
# Usage:
#   scripts/ci/coverage-critical.sh [profile]
#
# Inputs (env, with defaults):
#   COVERPROFILE                 merged, generated-excluded profile (default cover.out.nogen)
#   CRITICAL_COVERAGE_MIN        core-tier floor, percent (default 70)
#   CRITICAL_PKGS                space/newline-separated import paths to gate
#   CRITICAL_COVERAGE_MIN_TIER2  tier-2 floor, percent (default 70)
#   CRITICAL_PKGS_TIER2          same, for the tier-2 set
#
# A package entry may carry its own floor as `import/path=NN`; a bare entry takes
# the tier default. Per-package floors exist because one flat number cannot
# ratchet a 98%-covered package and a 70%-covered package together: the flat
# number has to sit under the weakest member of its tier, which leaves the strong
# members 20+ points of dead headroom that a large regression can fall through
# without ever crossing the bar. The floors below are therefore each set just
# under the package's own measured coverage.
#
# Exit status: 0 if every critical package is at or above its floor; 1 otherwise
# (printing each offender). The evaluator (eval_profile) is pure text processing
# over the Go coverprofile format so it can be unit-tested without running Go.

set -euo pipefail

MODULE="${MODULE:-trstctl.com/trstctl}"
CRITICAL_COVERAGE_MIN="${CRITICAL_COVERAGE_MIN:-70}"

# The security-critical packages named in the SF.1 card: the crypto boundary,
# issuance, the outbox, RLS storage, signing, and revocation — plus the
# TEST-COVFLOOR-001 additions (license validation, authz decisions, the event
# spine, and the untrusted protocol parsers).
#
# RATCHET 2026-08-02 (TEST-COVFLOOR-002), measured from the merged
# `cover.out.nogen` written by `make test`: crypto 71.7, store 72.0, signing
# 70.5, orchestrator 73.5, ca 77.3, ca/revocation 78.2, authz 98.1, license 94.1.
# Packages within ~3 points of the tier default stay bare and inherit it; the
# rest carry a floor a few points under their measured figure so ordinary churn
# does not red the build but a real regression does. Re-ratchet is a review
# decision — raise these when the measured figures move up, never lower them.
default_pkgs="\
${MODULE}/internal/crypto
${MODULE}/internal/store
${MODULE}/internal/signing
${MODULE}/internal/orchestrator
${MODULE}/internal/ca=74
${MODULE}/internal/ca/revocation=75
${MODULE}/internal/authz=95
${MODULE}/internal/license=91"
CRITICAL_PKGS="${CRITICAL_PKGS:-$default_pkgs}"

# Tier-2 security-critical packages (TEST-COVFLOOR-001): the event spine, secret
# material handling, and the untrusted-input protocol parsers.
#
# RATCHET 2026-08-02 (TEST-COVFLOOR-002), same profile: events 73.2,
# crypto/secret 73.0, acme 77.3, est 79.7, scep 75.4 — every one of them 18-25
# points above the old flat 55 floor, which therefore could not bite. The tier
# default moves 55 -> 70 (under crypto/secret, the weakest member) and the
# stronger members carry their own floors.
default_pkgs_tier2="\
${MODULE}/internal/events
${MODULE}/internal/crypto/secret
${MODULE}/internal/protocols/acme=74
${MODULE}/internal/protocols/est=76
${MODULE}/internal/protocols/scep=72"
CRITICAL_PKGS_TIER2="${CRITICAL_PKGS_TIER2:-$default_pkgs_tier2}"
CRITICAL_COVERAGE_MIN_TIER2="${CRITICAL_COVERAGE_MIN_TIER2:-70}"

# eval_profile <profile> <min> <pkg[=floor]...>
# Computes per-package statement coverage from a merged -coverpkg profile and
# fails (returns 1) if any named package is below its floor — its own `=NN` if it
# carries one, otherwise <min> — or is absent from the profile. Coverage lines
# look like:
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
			for (i = 1; i <= n; i++) {
				entry = want[i]
				eq = index(entry, "=")
				if (eq > 0) {
					p = substr(entry, 1, eq - 1)
					pkgmin[p] = substr(entry, eq + 1) + 0
				} else {
					p = entry
					pkgmin[p] = min + 0
				}
				wanted[p] = 1
				order[i] = p
			}
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
				fl = pkgmin[p]
				# Raise-only: a per-package entry may lift a package ABOVE its tier
				# default, never hold it below one. Without this the pin acts as a
				# CEILING and raising CRITICAL_COVERAGE_MIN silently skips pinned packages.
				if (min + 0 > fl + 0) fl = min + 0
				if (!(p in total) || total[p] == 0) {
					printf "FAIL: critical package %s has no coverage data in the profile\n", p
					fail = 1
					continue
				}
				pct = 100.0 * covered[p] / total[p]
				if (pct + 0 < fl + 0) {
					printf "FAIL: %s coverage %.1f%% is below the required %d%% (critical package)\n", p, pct, fl
					fail = 1
				} else {
					printf "ok:   %s %.1f%% (floor %d%%)\n", p, pct, fl
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
	# Both tiers must be EVALUATED even when the first one fails, so a single run
	# names every offender. Without the `|| var=$?` capture, `set -e` above aborts
	# main() at the first failing eval_profile and the entire tier-2 block never
	# runs — operators fix tier-1 and rerun before they can even see tier-2.
	local core=0 tier2=0
	echo ">> critical-package coverage gate (core minimum ${CRITICAL_COVERAGE_MIN}% per package)"
	# shellcheck disable=SC2086
	eval_profile "$profile" "$CRITICAL_COVERAGE_MIN" $CRITICAL_PKGS || core=$?
	echo ">> critical-package coverage gate (tier-2 minimum ${CRITICAL_COVERAGE_MIN_TIER2}% per package)"
	# shellcheck disable=SC2086
	eval_profile "$profile" "$CRITICAL_COVERAGE_MIN_TIER2" $CRITICAL_PKGS_TIER2 || tier2=$?
	if [[ "$core" -ne 0 || "$tier2" -ne 0 ]]; then
		return 1
	fi
}

# Only run main when executed directly, so the self-test can source the
# evaluator without triggering a profile read.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
