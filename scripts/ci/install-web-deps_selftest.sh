#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

repo_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install-web-deps.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/web"
printf '{"lockfileVersion":3}\n' >"$scratch/web/package-lock.json"
printf '{"private":true}\n' >"$scratch/web/package.json"

printf '%s\n' \
	'#!/usr/bin/env bash' \
	'set -euo pipefail' \
	'if [[ "$1" != "--prefix" || "$3" != "ci" ]]; then' \
	'  echo "unexpected npm arguments: $*" >&2' \
	'  exit 2' \
	'fi' \
	'mkdir -p "$2/node_modules"' \
	'printf "ci\\n" >>"$2/npm-ci.calls"' \
	>"$scratch/bin/npm"
chmod +x "$scratch/bin/npm"

run_install() {
	PATH="$scratch/bin:$PATH" "$repo_script" "$scratch/web"
}

run_install
run_install
[[ "$(wc -l <"$scratch/web/npm-ci.calls" | tr -d ' ')" == 1 ]]

printf '{"lockfileVersion":3,"changed":true}\n' >"$scratch/web/package-lock.json"
run_install
[[ "$(wc -l <"$scratch/web/npm-ci.calls" | tr -d ' ')" == 2 ]]

TRSTCTL_WEB_CLEAN_INSTALL=1 run_install
[[ "$(wc -l <"$scratch/web/npm-ci.calls" | tr -d ' ')" == 3 ]]

CI=true run_install
[[ "$(wc -l <"$scratch/web/npm-ci.calls" | tr -d ' ')" == 4 ]]

echo "install-web-deps self-test: PASS"
