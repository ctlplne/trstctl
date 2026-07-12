#!/usr/bin/env bash
# verify-scheduled-gates.sh — promote the scheduled-only nightly gates to
# REQUIRED (OPS-CI-101, OPS-CI-105, OPS-CI-106, OPS-CI-107).
#
# GitHub cannot require a schedule-only job as a pull-request status check, so
# this script runs as the per-PR "scheduled gates / nightly freshness" job and
# FAILS CLOSED unless the latest completed scheduled CI run:
#   1. exists,
#   2. is fresh (updated within TRSTCTL_SCHEDULED_GATES_MAX_AGE_HOURS, default 26),
#   3. concluded success, and
#   4. actually executed EVERY promoted nightly gate with conclusion success:
#        - captured soak / leak gate
#        - spine burst / replay-outbox gate
#        - branch protection / live policy drift
#        - perf live / served hot-path load gate
#
# A stale, red, missing, or silently-skipped nightly therefore blocks merge —
# the scheduled gates are required in effect, not in name only.
#
# Fixture overrides (used by verify-scheduled-gates_selftest.sh):
#   TRSTCTL_SCHEDULED_GATES_RUNS_JSON  path to a workflow-runs JSON document
#   TRSTCTL_SCHEDULED_GATES_JOBS_JSON  path to a run-jobs JSON document
#   TRSTCTL_SCHEDULED_GATES_NOW        RFC3339 "current time" for age math
#   TRSTCTL_SCHEDULED_GATES_RECEIPT    optional JSON receipt output path
set -euo pipefail

max_age_hours="${TRSTCTL_SCHEDULED_GATES_MAX_AGE_HOURS:-26}"
repo="${TRSTCTL_SCHEDULED_GATES_REPO:-${GITHUB_REPOSITORY:-}}"

promoted_gates=(
	"captured soak / leak gate"
	"spine burst / replay-outbox gate"
	"branch protection / live policy drift"
	"perf live / served hot-path load gate"
)

if ! command -v jq >/dev/null 2>&1; then
	echo "jq is required to verify scheduled gates" >&2
	exit 2
fi

fetch_runs_json() {
	if [ -n "${TRSTCTL_SCHEDULED_GATES_RUNS_JSON:-}" ]; then
		jq -c . "$TRSTCTL_SCHEDULED_GATES_RUNS_JSON"
		return
	fi
	if [ -z "$repo" ]; then
		echo "GITHUB_REPOSITORY or TRSTCTL_SCHEDULED_GATES_REPO is required" >&2
		exit 2
	fi
	gh api "repos/${repo}/actions/workflows/ci.yml/runs?event=schedule&status=completed&per_page=10"
}

fetch_jobs_json() { # $1 = run id
	if [ -n "${TRSTCTL_SCHEDULED_GATES_JOBS_JSON:-}" ]; then
		jq -c . "$TRSTCTL_SCHEDULED_GATES_JOBS_JSON"
		return
	fi
	gh api --paginate "repos/${repo}/actions/runs/$1/jobs" -F per_page=100 | jq -s '{jobs: map(.jobs[])}'
}

runs="$(fetch_runs_json)"
latest="$(printf '%s' "$runs" | jq -c '[.workflow_runs[]? | select(.event == "schedule" and .status == "completed")] | sort_by(.updated_at) | last // empty')"
if [ -z "$latest" ] || [ "$latest" = "null" ]; then
	echo "FAIL: no completed scheduled CI run exists — run the nightly (or workflow_dispatch ci.yml) once before merging (OPS-CI-105/106/107)" >&2
	exit 1
fi

run_id="$(printf '%s' "$latest" | jq -r '.id')"
run_conclusion="$(printf '%s' "$latest" | jq -r '.conclusion // "unknown"')"
run_updated="$(printf '%s' "$latest" | jq -r '.updated_at')"

now_epoch="$(date -u -d "${TRSTCTL_SCHEDULED_GATES_NOW:-now}" +%s)"
run_epoch="$(date -u -d "$run_updated" +%s)"
age_hours=$(((now_epoch - run_epoch) / 3600))
if [ "$age_hours" -gt "$max_age_hours" ]; then
	echo "FAIL: latest scheduled CI run ${run_id} is ${age_hours}h old (max ${max_age_hours}h) — the nightly gates have gone stale" >&2
	exit 1
fi
if [ "$run_conclusion" != "success" ]; then
	echo "FAIL: latest scheduled CI run ${run_id} concluded '${run_conclusion}' — fix the nightly gates before merging" >&2
	exit 1
fi

jobs="$(fetch_jobs_json "$run_id")"
failures=0
for gate in "${promoted_gates[@]}"; do
	conclusion="$(printf '%s' "$jobs" | jq -r --arg name "$gate" '[.jobs[]? | select(.name == $name)] | last | .conclusion // "missing"')"
	if [ "$conclusion" != "success" ]; then
		echo "FAIL: promoted scheduled gate '${gate}' concluded '${conclusion}' in run ${run_id} — a promoted nightly gate may not be skipped or red" >&2
		failures=$((failures + 1))
	else
		echo ">> scheduled gate green: ${gate}"
	fi
done

if [ -n "${TRSTCTL_SCHEDULED_GATES_RECEIPT:-}" ]; then
	jq -n --argjson runID "$run_id" --arg updated "$run_updated" --arg conclusion "$run_conclusion" \
		--argjson ageHours "$age_hours" --argjson maxAgeHours "$max_age_hours" --argjson failures "$failures" \
		'{schema_version: 1, run_id: $runID, updated_at: $updated, conclusion: $conclusion, age_hours: $ageHours, max_age_hours: $maxAgeHours, failures: $failures}' \
		> "$TRSTCTL_SCHEDULED_GATES_RECEIPT"
fi

if [ "$failures" -ne 0 ]; then
	exit 1
fi
echo ">> scheduled gates fresh and green (run ${run_id}, ${age_hours}h old)"
