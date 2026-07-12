#!/usr/bin/env bash
# verify-scheduled-gates_selftest.sh — prove the scheduled-gates freshness
# promotion fails closed (OPS-CI-105/106/107). Exercises the verifier against
# committed-style fixtures: a fresh green nightly PASSES; a stale run, a red
# run, a missing run, and a silently-skipped promoted job all FAIL.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
verifier="${here}/verify-scheduled-gates.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

now="2026-07-12T12:00:00Z"
fresh="2026-07-12T02:00:00Z"   # 10h old
stale="2026-07-09T02:00:00Z"   # >26h old

runs() { # $1 = updated_at, $2 = conclusion
	cat > "$tmp/runs.json" <<EOF
{"workflow_runs":[{"id":4242,"event":"schedule","status":"completed","conclusion":"$2","updated_at":"$1"}]}
EOF
}

jobs_all_green() {
	cat > "$tmp/jobs.json" <<'EOF'
{"jobs":[
  {"name":"captured soak / leak gate","conclusion":"success"},
  {"name":"spine burst / replay-outbox gate","conclusion":"success"},
  {"name":"branch protection / live policy drift","conclusion":"success"},
  {"name":"perf live / served hot-path load gate","conclusion":"success"}
]}
EOF
}

jobs_missing_one() {
	cat > "$tmp/jobs.json" <<'EOF'
{"jobs":[
  {"name":"captured soak / leak gate","conclusion":"success"},
  {"name":"spine burst / replay-outbox gate","conclusion":"success"},
  {"name":"branch protection / live policy drift","conclusion":"success"}
]}
EOF
}

jobs_one_red() {
	cat > "$tmp/jobs.json" <<'EOF'
{"jobs":[
  {"name":"captured soak / leak gate","conclusion":"failure"},
  {"name":"spine burst / replay-outbox gate","conclusion":"success"},
  {"name":"branch protection / live policy drift","conclusion":"success"},
  {"name":"perf live / served hot-path load gate","conclusion":"success"}
]}
EOF
}

run_verifier() {
	TRSTCTL_SCHEDULED_GATES_RUNS_JSON="$tmp/runs.json" \
	TRSTCTL_SCHEDULED_GATES_JOBS_JSON="$tmp/jobs.json" \
	TRSTCTL_SCHEDULED_GATES_NOW="$now" \
	TRSTCTL_SCHEDULED_GATES_RECEIPT="$tmp/receipt.json" \
	bash "$verifier"
}

# 1. Fresh green nightly with every promoted gate green PASSES.
runs "$fresh" success; jobs_all_green
run_verifier >/dev/null || { echo "FAIL: fresh green nightly was rejected" >&2; exit 1; }
jq -e '.failures == 0 and .run_id == 4242' "$tmp/receipt.json" >/dev/null \
	|| { echo "FAIL: green receipt is wrong" >&2; exit 1; }

# 2. Stale nightly FAILS.
runs "$stale" success; jobs_all_green
if run_verifier >/dev/null 2>&1; then
	echo "FAIL: stale nightly was accepted" >&2; exit 1
fi

# 3. Red nightly run FAILS.
runs "$fresh" failure; jobs_all_green
if run_verifier >/dev/null 2>&1; then
	echo "FAIL: red nightly run was accepted" >&2; exit 1
fi

# 4. A silently-skipped promoted gate FAILS.
runs "$fresh" success; jobs_missing_one
if run_verifier >/dev/null 2>&1; then
	echo "FAIL: nightly that skipped a promoted gate was accepted" >&2; exit 1
fi

# 5. A red promoted gate FAILS even when the run somehow concluded success.
runs "$fresh" success; jobs_one_red
if run_verifier >/dev/null 2>&1; then
	echo "FAIL: nightly with a red promoted gate was accepted" >&2; exit 1
fi

# 6. No scheduled run at all FAILS (bootstrap is explicit, not silent).
printf '{"workflow_runs":[]}' > "$tmp/runs.json"; jobs_all_green
if run_verifier >/dev/null 2>&1; then
	echo "FAIL: missing nightly run was accepted" >&2; exit 1
fi

echo ">> verify-scheduled-gates selftest: fail-closed in all directions"
