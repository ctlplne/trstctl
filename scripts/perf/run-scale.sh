#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# The enterprise-scale harness's rerun script (A266): one reproducible run of
# internal/perf's scale profile — inventory imported through the switching
# kit, a managed fleet issued and deployed, then a renewal storm through the
# scheduler once the fleet's renewal windows open — writing its receipt. The
# same seed imports the same inventory. Before the storm the run waits for the
# fleet's renewal windows to open: by default a storm budget of 200 ms a
# renewal, at least 3m, which the storm then gets again.
#
#   scripts/perf/run-scale.sh --inventory 1000000 --renewals 20000 --clients 32 --out dist/scale/receipt.json
set -euo pipefail

inventory="${SCALE_INVENTORY:-10000}"
renewals="${SCALE_RENEWALS:-200}"
clients="${SCALE_CLIENTS:-8}"
chunk="${SCALE_CHUNK:-25000}"
seed="${SCALE_SEED:-266}"
lifetime="${SCALE_FLEET_LIFETIME:-0}"
timeout="${SCALE_TIMEOUT:-6h}"
out="${SCALE_OUT:-dist/scale/receipt.json}"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--inventory) inventory="${2:?--inventory requires a value}"; shift 2 ;;
		--renewals) renewals="${2:?--renewals requires a value}"; shift 2 ;;
		--clients) clients="${2:?--clients requires a value}"; shift 2 ;;
		--chunk) chunk="${2:?--chunk requires a value}"; shift 2 ;;
		--seed) seed="${2:?--seed requires a value}"; shift 2 ;;
		--fleet-lifetime) lifetime="${2:?--fleet-lifetime requires a duration}"; shift 2 ;;
		--timeout) timeout="${2:?--timeout requires a duration}"; shift 2 ;;
		--out) out="${2:?--out requires a value}"; shift 2 ;;
		*)
			echo "usage: scripts/perf/run-scale.sh [--inventory N] [--renewals N] [--clients N] [--chunk N] [--seed N] [--fleet-lifetime D] [--timeout D] [--out path]" >&2
			exit 2
			;;
	esac
done

go run ./scripts/perf/cmd/scalegate --inventory "$inventory" --renewals "$renewals" --clients "$clients" --chunk "$chunk" --seed "$seed" \
	--fleet-lifetime "$lifetime" --timeout "$timeout" --out "$out"
