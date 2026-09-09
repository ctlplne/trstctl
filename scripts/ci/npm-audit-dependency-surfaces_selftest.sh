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

if [[ $# -gt 1 ]]; then echo "usage: $0 [new-evidence-directory]" >&2; exit 2; fi
if [[ $# -eq 1 ]]; then
	# Qualification passes a fresh directory below its private attempt. Keep the
	# actual reports; the caller owns retention, never a shared source path.
	tmp="$1"
	mkdir -m 700 "$tmp"
else
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
fi
mkdir -m 700 "$tmp/evidence"

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

# An expected failure is useful only when npm actually reported the advisory.
# A transport error or a malformed report must not impersonate this control.
check_receipt() {
	local expected="$1" receipt="$2"
	node - "$expected" "$receipt" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const [expected, filename] = process.argv.slice(2);
const r = JSON.parse(fs.readFileSync(filename, 'utf8'));
const ids = ['web', 'typescript-sdk-generator', 'pulumi-iac'];
if (r.schema !== 'trstctl.npm-audit-dependency-surfaces.v1' || r.scan_completed !== true ||
    r.surfaces.length !== ids.length) throw new Error('incomplete native calibration receipt');
for (let i = 0; i < ids.length; i++) {
  const s = r.surfaces[i];
  for (const [field, suffix] of [['raw_report', 'json'], ['raw_stderr', 'stderr']]) {
    const raw = fs.readFileSync(s[field].path);
    const digest = require('node:crypto').createHash('sha256').update(raw).digest('hex');
    if (raw.length !== s[field].bytes || digest !== s[field].sha256) throw new Error('native bytes changed');
    // Empty stderr is real evidence. Bounded chunks preserve its exact bytes
    // inside a nonempty record without a long redaction-sensitive byte string.
    const chunks = [];
    for (let offset = 0; offset < raw.length; offset += 96) chunks.push(raw.subarray(offset, offset + 96).toString('base64'));
    fs.writeFileSync(path.join(path.dirname(filename), 'evidence', `${expected}-${ids[i]}.${suffix}.raw.json`),
      JSON.stringify({ bytes: raw.length, sha256: digest, chunks_base64: chunks }) + '\n', { flag: 'wx', mode: 0o600 });
  }
  if (s.id !== ids[i] || s.scan_completed !== true || s.parse_error ||
      !Number.isSafeInteger(s.counts.high) || !Number.isSafeInteger(s.counts.critical)) {
    throw new Error('native calibration report was not valid');
  }
  const bad = s.id === expected;
  if (bad ? !(s.exit_code === 1 && s.result === 'fail' && s.counts.high + s.counts.critical > 0)
          : !(s.exit_code === 0 && s.result === 'pass' && s.counts.total === 0)) {
    throw new Error(`wrong actual scanner result for ${s.id}`);
  }
}
if (r.result !== (expected === 'clean' ? 'pass' : 'fail')) throw new Error('wrong aggregate result');
console.log(`PASS: native advisory inventory authenticated (${expected})`);
NODE
}

set +e
TRSTCTL_NPM_AUDIT_RECEIPT="$tmp/clean-receipt.json" \
TRSTCTL_WEB_NPM_PREFIX="$tmp/good-web" \
	TRSTCTL_TS_SDK_NPM_PREFIX="$tmp/good-sdk" \
	TRSTCTL_PULUMI_IAC_NPM_PREFIX="$tmp/good-pulumi" \
	bash "$checker" >/dev/null
check "accepts clean web + TypeScript SDK lockfiles" 0 $?
check_receipt clean "$tmp/clean-receipt.json" || fails=1

TRSTCTL_NPM_AUDIT_RECEIPT="$tmp/sdk-receipt.json" \
TRSTCTL_WEB_NPM_PREFIX="$tmp/good-web" \
	TRSTCTL_TS_SDK_NPM_PREFIX="$tmp/bad-sdk" \
	TRSTCTL_PULUMI_IAC_NPM_PREFIX="$tmp/good-pulumi" \
	bash "$checker" >/dev/null
check "rejects critical minimist advisory in TypeScript SDK generator lockfile" 1 $?
check_receipt typescript-sdk-generator "$tmp/sdk-receipt.json" || fails=1

TRSTCTL_NPM_AUDIT_RECEIPT="$tmp/pulumi-receipt.json" \
TRSTCTL_WEB_NPM_PREFIX="$tmp/good-web" \
	TRSTCTL_TS_SDK_NPM_PREFIX="$tmp/good-sdk" \
	TRSTCTL_PULUMI_IAC_NPM_PREFIX="$tmp/bad-pulumi" \
	bash "$checker" >/dev/null
check "rejects critical minimist advisory in Pulumi IaC lockfile" 1 $?
check_receipt pulumi-iac "$tmp/pulumi-receipt.json" || fails=1
set -e

if [[ "$fails" -ne 0 ]]; then
	echo "SELF-TEST FAILED"
	exit 1
fi
echo "ALL SELF-TESTS PASSED"
