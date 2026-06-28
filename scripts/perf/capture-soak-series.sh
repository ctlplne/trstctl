#!/usr/bin/env bash
# Capture a real local eval-stack soak series for scripts/perf/soak.sh --in.
set -euo pipefail

out=""
profile="${SOAK_CAPTURE_PROFILE:-captured-soak}"
samples="${SOAK_CAPTURE_SAMPLES:-12}"
step_seconds="${SOAK_CAPTURE_STEP_SECONDS:-5}"
load_samples="${SOAK_CAPTURE_LOAD_SAMPLES:-8}"
sleep_flag=()

usage() {
	cat >&2 <<'EOF'
usage: scripts/perf/capture-soak-series.sh [--out <series.json>] [--profile NAME]
                                           [--samples N] [--step-seconds S]
                                           [--load-samples N] [--no-sleep]
EOF
	exit 2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--out)          out="${2:?--out requires a value}"; shift 2 ;;
		--profile)      profile="${2:?--profile requires a value}"; shift 2 ;;
		--samples)      samples="${2:?--samples requires a value}"; shift 2 ;;
		--step-seconds) step_seconds="${2:?--step-seconds requires a value}"; shift 2 ;;
		--load-samples) load_samples="${2:?--load-samples requires a value}"; shift 2 ;;
		--no-sleep)     sleep_flag=(--no-sleep); shift ;;
		-h|--help)      usage ;;
		*)              echo "unknown argument: $1" >&2; usage ;;
	esac
done

args=(./scripts/perf/cmd/soakcapture
	--profile "$profile"
	--samples "$samples"
	--step-seconds "$step_seconds"
	--load-samples "$load_samples")
if [[ -n "$out" ]]; then
	args+=(--out "$out")
fi
args+=("${sleep_flag[@]}")

echo ">> soak-capture profile=$profile samples=$samples step=${step_seconds}s load_samples=$load_samples${out:+ out=$out}" >&2
go run "${args[@]}"
