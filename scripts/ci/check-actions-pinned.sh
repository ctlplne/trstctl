#!/usr/bin/env bash
# check-actions-pinned.sh — enforce that every THIRD-PARTY GitHub Action a
# workflow `uses:` is pinned to a full 40-hex commit SHA, never a mutable tag
# (SUPPLY-002). A tag like `@v4` is mutable: an upstream account compromise can
# repoint it, and our release pipeline runs build-push/cosign/sbom while holding
# `packages:write` + `id-token:write`, so a poisoned action could exfiltrate the
# OIDC token or push a malicious image under our own signed identity (cf.
# tj-actions/changed-files, 2025). A commit SHA is immutable, so this guard fails
# CI if any external action regresses to a floating tag.
#
# Scope: a "third-party" action is any `uses:` whose value names an external repo
# (`owner/repo[/path]@ref`). Local (`./...`) and container (`docker://...`)
# actions are out of scope. (Today every action we use is third-party; there are
# no first-party actions to exempt.)
#
# The single check below is unit-tested by check-actions-pinned_selftest.sh.
set -euo pipefail

# A 40-char lowercase-hex commit SHA (what an immutable pin looks like).
sha_re='[0-9a-f]{40}'

# offending_uses <workflow-file>
# Prints every `uses:` line in the file that names a third-party action pinned by
# something OTHER than a 40-hex commit SHA. Emits nothing (and returns 0 lines)
# when the file is fully pinned.
offending_uses() {
	local wf="$1"
	# Pull the ref off each `uses:` value, ignoring inline `# version` comments.
	# Keep only external `owner/repo...@ref` forms (skip ./local and docker://).
	grep -nE '^[[:space:]]*-?[[:space:]]*uses:' "$wf" | while IFS= read -r line; do
		# Isolate the value after `uses:` and strip a trailing comment.
		val="${line#*uses:}"
		val="${val%%#*}"
		# Trim surrounding whitespace and any surrounding quotes.
		val="$(printf '%s' "$val" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/^["'\'']//; s/["'\'']$//')"
		case "$val" in
		./* | docker://*) continue ;; # local / container action: out of scope
		esac
		# Must be owner/repo[/path]@ref to be a third-party action.
		[[ "$val" == */*@* ]] || continue
		ref="${val##*@}"
		if [[ ! "$ref" =~ ^${sha_re}$ ]]; then
			printf '%s\n' "$line"
		fi
	done
}

main() {
	local root="${1:-.}"
	local dir="${root}/.github/workflows"
	local rc=0 found_any=0

	if [[ ! -d "$dir" ]]; then
		echo "FAIL: no workflows directory at $dir"
		return 1
	fi

	shopt -s nullglob
	for wf in "$dir"/*.yml "$dir"/*.yaml; do
		found_any=1
		local offenders
		offenders="$(offending_uses "$wf")"
		if [[ -n "$offenders" ]]; then
			echo "FAIL: ${wf} pins a third-party action by a mutable tag, not a 40-hex commit SHA (SUPPLY-002):"
			# Indent each offending line for readability.
			printf '%s\n' "$offenders" | sed 's/^[[:space:]]*/        /'
			rc=1
		else
			echo "ok:   $(basename "$wf") — every third-party action is SHA-pinned"
		fi
	done

	if [[ "$found_any" -eq 0 ]]; then
		echo "FAIL: found no workflow files to check under $dir"
		return 1
	fi

	if [[ "$rc" -ne 0 ]]; then
		echo
		echo "Pin each offending action by its commit SHA with a version comment, e.g.:"
		echo "    uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1"
		echo "Bump a SHA pin, with its # vX.Y.Z comment, in a commit on main."
	fi
	return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
