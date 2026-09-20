#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Choose a conservative Go package-worker bound from the descriptor budget that
# this shell actually received. The 256-descriptor macOS default stays serial;
# larger budgets spend one 128-descriptor slice per package after a 256-FD
# reserve, then cap at the machine's logical CPU count.
set -euo pipefail

is_positive_integer() {
	[[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 > 0 ))
}

minimum_numeric_limit() {
	local result="" value
	for value in "$@"; do
		if ! is_positive_integer "$value"; then
			continue
		fi
		if [[ -z "$result" ]] || (( 10#$value < 10#$result )); then
			result="$value"
		fi
	done
	printf '%s\n' "$result"
}

parallelism_from_limits() {
	local soft="$1" per_process="$2" global="$3" cpus="$4"
	if ! is_positive_integer "$cpus"; then
		printf '1\n'
		return
	fi

	local global_share=""
	if is_positive_integer "$global"; then
		global_share="$(( 10#$global / 10#$cpus ))"
	fi
	local effective
	effective="$(minimum_numeric_limit "$soft" "$per_process" "$global_share")"
	if [[ -z "$effective" ]]; then
		printf '1\n'
		return
	fi

	local reserve=256 per_package=128 workers
	if (( 10#$effective <= reserve )); then
		workers=1
	else
		workers="$(( (10#$effective - reserve) / per_package ))"
		(( workers >= 1 )) || workers=1
	fi
	if (( workers > 10#$cpus )); then
		workers="$cpus"
	fi
	printf '%s\n' "$workers"
}

if [[ "${1:-}" == "--from-limits" ]]; then
	[[ "$#" == 5 ]] || { echo "usage: $0 --from-limits SOFT PER_PROCESS GLOBAL CPUS" >&2; exit 2; }
	parallelism_from_limits "$2" "$3" "$4" "$5"
	exit
fi
[[ "$#" == 0 ]] || { echo "usage: $0 [--from-limits SOFT PER_PROCESS GLOBAL CPUS]" >&2; exit 2; }

soft="$(ulimit -n 2>/dev/null || true)"
per_process=""
global=""
if command -v sysctl >/dev/null 2>&1; then
	per_process="$(sysctl -n kern.maxfilesperproc 2>/dev/null || true)"
	global="$(sysctl -n kern.maxfiles 2>/dev/null || true)"
fi
if [[ -z "$global" && -r /proc/sys/fs/file-max ]]; then
	IFS= read -r global </proc/sys/fs/file-max || true
fi

cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
if ! is_positive_integer "$cpus" && command -v sysctl >/dev/null 2>&1; then
	cpus="$(sysctl -n hw.logicalcpu 2>/dev/null || true)"
fi

parallelism_from_limits "$soft" "$per_process" "$global" "$cpus"
