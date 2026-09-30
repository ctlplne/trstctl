#!/usr/bin/env bash
set -euo pipefail

profile="smoke"
out=""
samples=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		--profile)
			profile="${2:?--profile requires a value}"
			shift 2
			;;
		--out)
			out="${2:?--out requires a value}"
			shift 2
			;;
		--samples)
			samples="${2:?--samples requires a value}"
			shift 2
			;;
		*)
			echo "usage: scripts/perf/run-local.sh [--profile smoke|live] [--samples N] [--out path]" >&2
			exit 2
			;;
	esac
done

if [[ -z "$samples" ]]; then
	if [[ "$profile" == "live" || "$profile" == "live-load" ]]; then
		samples="${PERF_LIVE_SAMPLES:-32}"
	else
		samples="${PERF_SMOKE_SAMPLES:-64}"
	fi
fi

args=(./scripts/perf/cmd/perfgate --profile "$profile" --samples "$samples")
if [[ -n "$out" ]]; then
	args+=(--out "$out")
fi

go run "${args[@]}"
if [[ "$profile" == "live" || "$profile" == "live-load" ]] && [[ -n "$out" ]]; then
	python3 scripts/perf/live-baseline.py stamp "$out"
fi
