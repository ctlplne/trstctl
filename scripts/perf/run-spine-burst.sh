#!/usr/bin/env bash
# Capture a reproducible event-spine burst series and feed it to soak.sh --in.
set -euo pipefail

profile="${SPINE_BURST_PROFILE:-cap-small}"
out=""
samples="${SPINE_BURST_SAMPLES:-}"
step_seconds="${SPINE_BURST_STEP_SECONDS:-}"
events="${SPINE_BURST_EVENTS:-}"
outbox_items="${SPINE_BURST_OUTBOX_ITEMS:-}"
tenants="${SPINE_BURST_TENANTS:-}"
agents="${SPINE_BURST_AGENTS:-}"
slow_upstream_ms="${SPINE_BURST_SLOW_UPSTREAM_MS:-}"
sleep_flag=()

usage() {
	cat >&2 <<'EOF'
usage: scripts/perf/run-spine-burst.sh --profile cap-small --out <series.json>
                                      [--samples N] [--step-seconds S]
                                      [--events N] [--outbox-items N]
                                      [--tenants N] [--agents N]
                                      [--slow-upstream-ms N] [--sleep]
EOF
	exit 2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--profile)          profile="${2:?--profile requires a value}"; shift 2 ;;
		--out)              out="${2:?--out requires a value}"; shift 2 ;;
		--samples)          samples="${2:?--samples requires a value}"; shift 2 ;;
		--step-seconds)     step_seconds="${2:?--step-seconds requires a value}"; shift 2 ;;
		--events)           events="${2:?--events requires a value}"; shift 2 ;;
		--outbox-items)     outbox_items="${2:?--outbox-items requires a value}"; shift 2 ;;
		--tenants)          tenants="${2:?--tenants requires a value}"; shift 2 ;;
		--agents)           agents="${2:?--agents requires a value}"; shift 2 ;;
		--slow-upstream-ms) slow_upstream_ms="${2:?--slow-upstream-ms requires a value}"; shift 2 ;;
		--sleep)            sleep_flag=(--sleep); shift ;;
		-h|--help)          usage ;;
		*)                  echo "unknown argument: $1" >&2; usage ;;
	esac
done

args=(./scripts/perf/cmd/spineburst --profile "$profile")
if [[ -n "$out" ]]; then
	args+=(--out "$out")
fi
if [[ -n "$samples" ]]; then
	args+=(--samples "$samples")
fi
if [[ -n "$step_seconds" ]]; then
	args+=(--step-seconds "$step_seconds")
fi
if [[ -n "$events" ]]; then
	args+=(--events "$events")
fi
if [[ -n "$outbox_items" ]]; then
	args+=(--outbox-items "$outbox_items")
fi
if [[ -n "$tenants" ]]; then
	args+=(--tenants "$tenants")
fi
if [[ -n "$agents" ]]; then
	args+=(--agents "$agents")
fi
if [[ -n "$slow_upstream_ms" ]]; then
	args+=(--slow-upstream-ms "$slow_upstream_ms")
fi
if ((${#sleep_flag[@]})); then
	args+=("${sleep_flag[@]}")
fi

echo ">> spine-burst profile=$profile${out:+ out=$out}" >&2
go run "${args[@]}"
