#!/usr/bin/env bash
set -euo pipefail

out="scripts/perf/artifacts/capacity-measurement-baseline.json"
samples="${PERF_CAPACITY_SAMPLES:-1000}"
live_artifact="scripts/perf/artifacts/live-load-baseline.json"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--out)
			out="${2:?--out requires a value}"
			shift 2
			;;
		--samples)
			samples="${2:?--samples requires a value}"
			shift 2
			;;
		--live-artifact)
			live_artifact="${2:?--live-artifact requires a value}"
			shift 2
			;;
		*)
			echo "usage: scripts/perf/run-capacity-calibration.sh [--out path] [--samples N] [--live-artifact path]" >&2
			exit 2
			;;
	esac
done

go run ./scripts/perf/cmd/capacitycalibrate --out "$out" --samples "$samples" --live-artifact "$live_artifact"
