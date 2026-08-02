#!/usr/bin/env bash
# Self-test for npm-audit-dependency-surfaces.sh — proves the npm SCA gate
# rejects a known HIGH/CRITICAL advisory in the TypeScript SDK generator lockfile
# (SUPPLY-005 acceptance), not just the web package-lock.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="${here}/npm-audit-dependency-surfaces.sh"

fails=0
check() {
	if [[ "$2" == "$3" ]]; then
		echo "PASS: $1"
	else
		echo "FAIL: $1 (want exit $2, got $3)"
		fails=1
	fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

write_empty_lock() {
	local dir="$1" name="$2"
	mkdir -p "$dir"
	cat >"${dir}/package.json" <<EOF
{"name":"${name}","version":"0.0.0","private":true}
EOF
	cat >"${dir}/package-lock.json" <<EOF
{"name":"${name}","version":"0.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"${name}","version":"0.0.0"}}}
EOF
}

write_vulnerable_sdk_lock() {
	local dir="$1" name="${2:-trstctl-sdk-audit-vulnerable}"
	mkdir -p "$dir"
	cat >"${dir}/package.json" <<EOF
{"name":"${name}","version":"0.0.0","private":true,"devDependencies":{"minimist":"0.0.8"}}
EOF
	npm --prefix "$dir" install --package-lock-only --ignore-scripts --no-audit >/dev/null
}

write_empty_lock "$tmp/good-web" "trstctl-web-audit-clean"
write_empty_lock "$tmp/good-sdk" "trstctl-sdk-audit-clean"
write_empty_lock "$tmp/good-pulumi" "trstctl-pulumi-audit-clean"
write_vulnerable_sdk_lock "$tmp/bad-sdk"
write_vulnerable_sdk_lock "$tmp/bad-pulumi" "trstctl-pulumi-audit-vulnerable"

set +e
TRSTCTL_WEB_NPM_PREFIX="$tmp/good-web" \
	TRSTCTL_TS_SDK_NPM_PREFIX="$tmp/good-sdk" \
	TRSTCTL_PULUMI_IAC_NPM_PREFIX="$tmp/good-pulumi" \
	bash "$checker" >/dev/null
check "accepts clean web + TypeScript SDK lockfiles" 0 $?

TRSTCTL_WEB_NPM_PREFIX="$tmp/good-web" \
	TRSTCTL_TS_SDK_NPM_PREFIX="$tmp/bad-sdk" \
	TRSTCTL_PULUMI_IAC_NPM_PREFIX="$tmp/good-pulumi" \
	bash "$checker" >/dev/null
check "rejects critical minimist advisory in TypeScript SDK generator lockfile" 1 $?

TRSTCTL_WEB_NPM_PREFIX="$tmp/good-web" \
	TRSTCTL_TS_SDK_NPM_PREFIX="$tmp/good-sdk" \
	TRSTCTL_PULUMI_IAC_NPM_PREFIX="$tmp/bad-pulumi" \
	bash "$checker" >/dev/null
check "rejects critical minimist advisory in Pulumi IaC lockfile" 1 $?
set -e

if [[ "$fails" -ne 0 ]]; then
	echo "SELF-TEST FAILED"
	exit 1
fi
echo "ALL SELF-TESTS PASSED"
