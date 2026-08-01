#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/go-package-parallelism.sh"

assert_parallelism() {
	local soft="$1" per_process="$2" global="$3" cpus="$4" want="$5"
	local got
	got="$($script --from-limits "$soft" "$per_process" "$global" "$cpus")"
	if [[ "$got" != "$want" ]]; then
		echo "parallelism($soft, $per_process, $global, $cpus) = $got, want $want" >&2
		exit 1
	fi
}

# A default macOS shell must keep the closed-P0 serial fallback. Larger live
# budgets may use more packages, but never more than the machine's CPU count.
assert_parallelism 256 245760 491520 12 1
assert_parallelism 1024 245760 491520 12 6
assert_parallelism 1048575 245760 491520 12 12
assert_parallelism unlimited 245760 491520 12 12
assert_parallelism invalid invalid invalid invalid 1

echo "go-package-parallelism self-test: PASS"
