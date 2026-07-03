#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/.github"
cat >"$tmp/.github/branch-protection.json" <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "build / test / lint",
      "govulncheck"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true,
    "require_last_push_approval": true
  },
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true,
  "restrictions": null
}
JSON

cat >"$tmp/live-good.json" <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "govulncheck",
      "build / test / lint"
    ]
  },
  "enforce_admins": {
    "enabled": true
  },
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true,
    "require_last_push_approval": true
  },
  "required_linear_history": {
    "enabled": true
  },
  "allow_force_pushes": {
    "enabled": false
  },
  "allow_deletions": {
    "enabled": false
  },
  "required_conversation_resolution": {
    "enabled": true
  }
}
JSON

TRSTCTL_BRANCH_PROTECTION_ROOT="$tmp" \
TRSTCTL_BRANCH_PROTECTION_LIVE_JSON="$tmp/live-good.json" \
TRSTCTL_BRANCH_PROTECTION_RECEIPT="$tmp/branch-protection-drift-receipt.json" \
"$script_dir/verify-branch-protection.sh"

jq -e '
  .schema_version == 1 and
  .id == "branch-protection-live-drift" and
  .status == "passed" and
  .verifier == "scripts/ci/verify-branch-protection.sh" and
  .policy.required_status_checks.strict == true and
  (.policy.required_status_checks.contexts | sort) == ["build / test / lint", "govulncheck"] and
  .live.repository == "offline" and
  .live.branch == "main" and
  .live.enforce_admins == true
' "$tmp/branch-protection-drift-receipt.json" >/dev/null || {
	echo "branch-protection receipt did not contain the expected release evidence" >&2
	cat "$tmp/branch-protection-drift-receipt.json" >&2
	exit 1
}

cat >"$tmp/live-bad.json" <<'JSON'
{
  "required_status_checks": {
    "strict": false,
    "contexts": [
      "build / test / lint"
    ]
  },
  "enforce_admins": {
    "enabled": false
  },
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "require_code_owner_reviews": false,
    "dismiss_stale_reviews": false,
    "require_last_push_approval": false
  },
  "required_linear_history": {
    "enabled": false
  },
  "allow_force_pushes": {
    "enabled": true
  },
  "allow_deletions": {
    "enabled": true
  },
  "required_conversation_resolution": {
    "enabled": false
  }
}
JSON

bad_out="$tmp/live-bad.out"
if TRSTCTL_BRANCH_PROTECTION_ROOT="$tmp" \
	TRSTCTL_BRANCH_PROTECTION_LIVE_JSON="$tmp/live-bad.json" \
	"$script_dir/verify-branch-protection.sh" >"$bad_out" 2>&1; then
	echo "expected branch-protection drift to fail" >&2
	exit 1
fi
for want in "required contexts drifted" "enforce admins" "linear history" "force pushes"; do
	if ! grep -q "$want" "$bad_out"; then
		echo "drift output did not mention ${want}" >&2
		cat "$bad_out" >&2
		exit 1
	fi
done

echo "ok: verify-branch-protection self-test"
