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
	'mkdir -p "$2/node_modules/.bin"' \
	'for tool in eslint playwright prettier size-limit storybook tsc vite vitest; do' \
	'  printf "#!/usr/bin/env bash\\nexit 0\\n" >"$2/node_modules/.bin/$tool"' \
	'  chmod +x "$2/node_modules/.bin/$tool"' \
	'done' \
	'printf "ci\\n" >>"$2/npm-ci.calls"' \
	>"$scratch/bin/npm"
chmod +x "$scratch/bin/npm"

run_install() {
	PATH="$scratch/bin:$PATH" "$repo_script" "$scratch/web"
}

assert_call_count() {
	local expected="$1" actual
	actual="$(wc -l <"$scratch/web/npm-ci.calls" | tr -d ' ')"
	[[ "$actual" == "$expected" ]] || {
		echo "npm ci call count: got $actual, expected $expected" >&2
		exit 1
	}
}

run_install
run_install
assert_call_count 1

rm "$scratch/web/node_modules/.bin/vitest"
run_install
assert_call_count 2

printf '{"lockfileVersion":3,"changed":true}\n' >"$scratch/web/package-lock.json"
run_install
assert_call_count 3

TRSTCTL_WEB_CLEAN_INSTALL=1 run_install
assert_call_count 4

CI=true run_install
assert_call_count 5

echo "install-web-deps self-test: PASS"
