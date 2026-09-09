#!/usr/bin/env bash
# npm-audit-dependency-surfaces.sh — fail CI on HIGH/CRITICAL npm advisories
# across dependency trees that live outside go.sum. The web release executes its
# Vite/PostCSS build dependencies, so that complete lockfile is a supply-chain
# surface even though only production packages remain in the runtime image. The
# TypeScript SDK likewise executes its devDependency generator. The Pulumi IaC
# example is a third such tree: its Node runtime resolves @pulumi/pulumi at deploy
# time, so a copyable example still carries a real dependency closure. The set of
# surfaces below must equal the set of first-party package.json trees in the
# repository — docs/supply_npm_surface_parity_test.go (SUPPLY-106) fails if a
# package.json appears that this script does not audit.
set -euo pipefail
umask 077

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
npm_bin="${NPM:-npm}"
receipt="${TRSTCTL_NPM_AUDIT_RECEIPT:-${TMPDIR:-/tmp}/trstctl-npm-audit-dependency-surfaces.json}"
expected_npm_version="${TRSTCTL_NPM_AUDIT_EXPECTED_VERSION:-}"

web_prefix="${TRSTCTL_WEB_NPM_PREFIX:-${repo}/web}"
sdk_prefix="${TRSTCTL_TS_SDK_NPM_PREFIX:-${repo}/clients/sdk/typescript}"
pulumi_prefix="${TRSTCTL_PULUMI_IAC_NPM_PREFIX:-${repo}/deploy/iac/pulumi/trstctl-resources}"

npm_version="$("${npm_bin}" --version)"
node_version="$(node --version 2>/dev/null || true)"
if [[ -n "${expected_npm_version}" && "${npm_version}" != "${expected_npm_version}" ]]; then
	echo "FAIL: npm audit scanner version ${npm_version}; want pinned ${expected_npm_version}" >&2
	exit 1
fi

mkdir -p "$(dirname "${receipt}")"
# Raw stdout/stderr survive both success and failure beside the receipt.
tmp="$(mktemp -d "${receipt}.raw.XXXXXX")"
report_reader="${repo}/scripts/ci/npm-audit-report.mjs"
surface_jsonl="${tmp}/surfaces.jsonl"
: >"${surface_jsonl}"

audit_lock() {
	local id="$1" label="$2" prefix="$3" dependency_scope="$4"
	shift 4
	if [[ ! -f "${prefix}/package.json" ]]; then
		echo "FAIL: ${label} has no package.json at ${prefix}/package.json" >&2
		return 1
	fi
	if [[ ! -f "${prefix}/package-lock.json" ]]; then
		echo "FAIL: ${label} has no package-lock.json at ${prefix}/package-lock.json" >&2
		return 1
	fi

	local report="${tmp}/${id}.json"
	local stderr="${tmp}/${id}.stderr"
	echo ">> npm audit (${label})"
	set +e
	"${npm_bin}" --prefix "${prefix}" audit --json --package-lock-only --audit-level=high "$@" >"${report}" 2>"${stderr}"
	local status=$?
	set -e
	if [[ -s "${stderr}" ]]; then
		cat "${stderr}" >&2
	fi

	local summary report_status
	if summary="$(node "${report_reader}" surface "${report}" "${stderr}" "${surface_jsonl}" "${repo}" "${id}" "${label}" "${prefix}" "${dependency_scope}" "${status}" "$*")"; then
		report_status=0
	else
		report_status=1
	fi
	echo "   severity counts: ${summary}"
	# A malformed or absent report must fail even when npm returned zero.
	if [[ "${status}" -ne 0 || "${report_status}" -ne 0 ]]; then return 1; fi
	return 0
}

failures=0
audit_lock "web" "web build and runtime dependency tree" "${web_prefix}" "build-and-production" --include=dev || failures=1
audit_lock "typescript-sdk-generator" "TypeScript SDK generator dependency tree" "${sdk_prefix}" "dev-generator" --include=dev || failures=1
audit_lock "pulumi-iac" "Pulumi IaC example dependency tree" "${pulumi_prefix}" "deploy-time" --include=dev || failures=1

if ! node "${report_reader}" aggregate "${surface_jsonl}" "${receipt}" "${npm_version}" "${node_version}" "${failures}" "${tmp}"; then
	failures=1
fi
echo ">> wrote npm audit receipt: ${receipt}"
echo ">> retained raw npm audit evidence: ${tmp}"
exit "${failures}"
