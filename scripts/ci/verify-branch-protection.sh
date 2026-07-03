#!/usr/bin/env bash
set -euo pipefail

root="${TRSTCTL_BRANCH_PROTECTION_ROOT:-.}"
policy="${TRSTCTL_BRANCH_PROTECTION_POLICY:-${root}/.github/branch-protection.json}"
repo="${TRSTCTL_BRANCH_PROTECTION_REPO:-${GITHUB_REPOSITORY:-}}"
branch="${TRSTCTL_BRANCH_PROTECTION_BRANCH:-main}"
receipt="${TRSTCTL_BRANCH_PROTECTION_RECEIPT:-}"

if ! command -v jq >/dev/null 2>&1; then
	echo "jq is required to verify branch protection" >&2
	exit 2
fi

policy_json="$(jq -c . "$policy")"
if [ -n "${TRSTCTL_BRANCH_PROTECTION_LIVE_JSON:-}" ]; then
	live_json="$(jq -c . "$TRSTCTL_BRANCH_PROTECTION_LIVE_JSON")"
else
	if [ -z "$repo" ]; then
		echo "GITHUB_REPOSITORY or TRSTCTL_BRANCH_PROTECTION_REPO is required" >&2
		exit 2
	fi
	live_json="$(gh api "repos/${repo}/branches/${branch}/protection")"
fi

policy_contexts="$(jq -r '.required_status_checks.contexts[]' <<<"$policy_json" | sort)"
live_contexts="$(jq -r '.required_status_checks.contexts[]' <<<"$live_json" | sort)"

fail=0
if [ "$policy_contexts" != "$live_contexts" ]; then
	echo "branch protection required contexts drifted from .github/branch-protection.json" >&2
	diff -u <(printf '%s\n' "$policy_contexts") <(printf '%s\n' "$live_contexts") >&2 || true
	fail=1
fi

check_bool() {
	local label="$1"
	local policy_expr="$2"
	local live_expr="$3"
	local want live
	want="$(jq -r "$policy_expr" <<<"$policy_json")"
	live="$(jq -r "$live_expr" <<<"$live_json")"
	if [ "$want" != "$live" ]; then
		echo "branch protection ${label} drifted: policy=${want} live=${live}" >&2
		fail=1
	fi
}

check_bool "strict status checks" '.required_status_checks.strict' '.required_status_checks.strict'
check_bool "enforce admins" '.enforce_admins' '.enforce_admins.enabled'
check_bool "code-owner reviews" '.required_pull_request_reviews.require_code_owner_reviews' '.required_pull_request_reviews.require_code_owner_reviews'
check_bool "stale review dismissal" '.required_pull_request_reviews.dismiss_stale_reviews' '.required_pull_request_reviews.dismiss_stale_reviews'
check_bool "last-push approval" '.required_pull_request_reviews.require_last_push_approval' '.required_pull_request_reviews.require_last_push_approval'
check_bool "review count" '.required_pull_request_reviews.required_approving_review_count' '.required_pull_request_reviews.required_approving_review_count'
check_bool "linear history" '.required_linear_history' '.required_linear_history.enabled'
check_bool "force pushes" '.allow_force_pushes' '.allow_force_pushes.enabled'
check_bool "branch deletion" '.allow_deletions' '.allow_deletions.enabled'
check_bool "conversation resolution" '.required_conversation_resolution' '.required_conversation_resolution.enabled'

write_receipt() {
	local status="$1"
	[ -n "$receipt" ] || return 0
	mkdir -p "$(dirname "$receipt")"
	local tmp
	tmp="${receipt}.tmp"
	jq -n \
		--arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
		--arg status "$status" \
		--arg verifier "scripts/ci/verify-branch-protection.sh" \
		--arg policy_path "$policy" \
		--arg repository "${repo:-offline}" \
		--arg branch "$branch" \
		--argjson policy_contexts "$(jq -c '.required_status_checks.contexts' <<<"$policy_json")" \
		--argjson live_contexts "$(jq -c '.required_status_checks.contexts' <<<"$live_json")" \
		--argjson policy_strict "$(jq -c '.required_status_checks.strict' <<<"$policy_json")" \
		--argjson live_strict "$(jq -c '.required_status_checks.strict' <<<"$live_json")" \
		--argjson policy_enforce_admins "$(jq -c '.enforce_admins' <<<"$policy_json")" \
		--argjson live_enforce_admins "$(jq -c '.enforce_admins.enabled' <<<"$live_json")" \
		--argjson policy_code_owner_reviews "$(jq -c '.required_pull_request_reviews.require_code_owner_reviews' <<<"$policy_json")" \
		--argjson live_code_owner_reviews "$(jq -c '.required_pull_request_reviews.require_code_owner_reviews' <<<"$live_json")" \
		--argjson policy_dismiss_stale_reviews "$(jq -c '.required_pull_request_reviews.dismiss_stale_reviews' <<<"$policy_json")" \
		--argjson live_dismiss_stale_reviews "$(jq -c '.required_pull_request_reviews.dismiss_stale_reviews' <<<"$live_json")" \
		--argjson policy_last_push_approval "$(jq -c '.required_pull_request_reviews.require_last_push_approval' <<<"$policy_json")" \
		--argjson live_last_push_approval "$(jq -c '.required_pull_request_reviews.require_last_push_approval' <<<"$live_json")" \
		--argjson policy_review_count "$(jq -c '.required_pull_request_reviews.required_approving_review_count' <<<"$policy_json")" \
		--argjson live_review_count "$(jq -c '.required_pull_request_reviews.required_approving_review_count' <<<"$live_json")" \
		--argjson policy_linear_history "$(jq -c '.required_linear_history' <<<"$policy_json")" \
		--argjson live_linear_history "$(jq -c '.required_linear_history.enabled' <<<"$live_json")" \
		--argjson policy_allow_force_pushes "$(jq -c '.allow_force_pushes' <<<"$policy_json")" \
		--argjson live_allow_force_pushes "$(jq -c '.allow_force_pushes.enabled' <<<"$live_json")" \
		--argjson policy_allow_deletions "$(jq -c '.allow_deletions' <<<"$policy_json")" \
		--argjson live_allow_deletions "$(jq -c '.allow_deletions.enabled' <<<"$live_json")" \
		--argjson policy_conversation_resolution "$(jq -c '.required_conversation_resolution' <<<"$policy_json")" \
		--argjson live_conversation_resolution "$(jq -c '.required_conversation_resolution.enabled' <<<"$live_json")" \
		'{
			schema_version: 1,
			id: "branch-protection-live-drift",
			generated_at: $generated_at,
			status: $status,
			verifier: $verifier,
			policy: {
				path: $policy_path,
				required_status_checks: {strict: $policy_strict, contexts: $policy_contexts},
				enforce_admins: $policy_enforce_admins,
				required_pull_request_reviews: {
					required_approving_review_count: $policy_review_count,
					require_code_owner_reviews: $policy_code_owner_reviews,
					dismiss_stale_reviews: $policy_dismiss_stale_reviews,
					require_last_push_approval: $policy_last_push_approval
				},
				required_linear_history: $policy_linear_history,
				allow_force_pushes: $policy_allow_force_pushes,
				allow_deletions: $policy_allow_deletions,
				required_conversation_resolution: $policy_conversation_resolution
			},
			live: {
				repository: $repository,
				branch: $branch,
				required_status_checks: {strict: $live_strict, contexts: $live_contexts},
				enforce_admins: $live_enforce_admins,
				required_pull_request_reviews: {
					required_approving_review_count: $live_review_count,
					require_code_owner_reviews: $live_code_owner_reviews,
					dismiss_stale_reviews: $live_dismiss_stale_reviews,
					require_last_push_approval: $live_last_push_approval
				},
				required_linear_history: $live_linear_history,
				allow_force_pushes: $live_allow_force_pushes,
				allow_deletions: $live_allow_deletions,
				required_conversation_resolution: $live_conversation_resolution
			}
		}' >"$tmp"
	mv "$tmp" "$receipt"
}

if [ "$fail" -ne 0 ]; then
	write_receipt "failed"
	echo "branch protection drift check failed" >&2
	exit 1
fi

write_receipt "passed"
echo "ok: live branch protection matches ${policy} for ${repo:-offline}/${branch}"
