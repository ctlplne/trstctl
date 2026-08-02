#!/usr/bin/env bash
# Convert a Trivy JSON report for the embedded PostgreSQL rootfs into a compact
# scanner receipt, and fail closed when a fixable Critical finding exists or when
# the scan inventoried nothing it could have found those findings in.
#
# Severity counts alone cannot tell "scanned the binary and found nothing" apart
# from "scanned nothing": both produce high=0 critical=0 and would be written out
# as result:"pass". So the receipt also records INVENTORY COVERAGE — how many
# packages the report listed, and which of them carried the pinned PostgreSQL
# version — and refuses to emit a passing receipt when that evidence is absent.
set -euo pipefail

fail() {
  printf '::error::embedded-postgres scan receipt: %s\n' "$*" >&2
  exit 1
}

if [[ "$#" -ne 7 ]]; then
  fail "usage: embedded-postgres-scan-receipt.sh <trivy-json> <trivy-version.txt> <receipt-json> <arch> <postgres-version> <jar-sha256> <txz-sha256>"
fi

report="$1"
version_file="$2"
receipt="$3"
arch="$4"
postgres_version="$5"
jar_sha256="$6"
txz_sha256="$7"

command -v jq >/dev/null 2>&1 || fail "jq is required"
[[ -s "$report" ]] || fail "Trivy JSON report is missing or empty: $report"
[[ -s "$version_file" ]] || fail "Trivy version output is missing or empty: $version_file"

count_severity() {
  local severity="$1"
  jq --arg severity "$severity" '[.Results[]?.Vulnerabilities[]? | select(.Severity == $severity)] | length' "$report"
}

count_fixable() {
  local severity="$1"
  jq --arg severity "$severity" '[.Results[]?.Vulnerabilities[]? | select(.Severity == $severity and (((.FixedVersion // "") | tostring | length) > 0))] | length' "$report"
}

high_total="$(count_severity HIGH)"
high_fixable="$(count_fixable HIGH)"
critical_total="$(count_severity CRITICAL)"
critical_fixable="$(count_fixable CRITICAL)"

# Inventory coverage. packages_inventoried is every package in every Results
# block; version_evidence is the subset carrying the pinned server version, kept
# with the block that supplied it so the receipt names its own source.
packages_inventoried="$(jq '[.Results[]?.Packages[]?] | length' "$report")"
version_evidence="$(jq -c --arg v "$postgres_version" '
  [ .Results[]? as $r
    | $r.Packages[]?
    | select(((.Version // .InstalledVersion // "") | tostring) == $v)
    | {
        name: (.Name // ""),
        version: $v,
        target: ($r.Target // ""),
        class: ($r.Class // ""),
        type: ($r.Type // "")
      } ]' "$report")"
version_evidence_count="$(printf '%s' "$version_evidence" | jq 'length')"
# The zonky wrapper is a Maven coordinate (io.zonky.test.postgres:...), not the
# server. Only a package NAMED for PostgreSQL is the server itself, and only then
# do PostgreSQL server advisories actually get matched against this scan.
server_pkg_evidence="$(printf '%s' "$version_evidence" | jq -c '
  [ .[] | select((.name | ascii_downcase) | test("(^|/)postgres(ql)?($|[0-9._-])")) ]')"
server_pkg_count="$(printf '%s' "$server_pkg_evidence" | jq 'length')"
if [[ "$packages_inventoried" -eq 0 ]]; then
  coverage_note="the report inventoried no packages at all — this scan examined nothing and certifies nothing"
elif [[ "$version_evidence_count" -eq 0 ]]; then
  coverage_note="the report inventoried packages but none carrying the pinned PostgreSQL version — this scan did not cover the pinned binary"
elif [[ "$server_pkg_count" -gt 0 ]]; then
  coverage_note="the PostgreSQL server is inventoried as a named package, so server advisories are matched by this scan"
else
  coverage_note="the pinned version is evidenced only by the packaging coordinate; Trivy found no package database in the extracted archive, so PostgreSQL server advisories are NOT matched by this scan and the version pin in deploy/supply-chain/embedded-postgres.json is the control that moves it"
fi

generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
trivy_version="$(awk -F': ' '/^Version:/ {print $2; exit}' "$version_file")"
db_version="$(awk '/^Vulnerability DB:/ {seen=1; next} seen && /^[[:space:]]*Version:/ {sub(/^[[:space:]]*Version:[[:space:]]*/, ""); print; exit}' "$version_file")"
db_updated_at="$(awk '/^Vulnerability DB:/ {seen=1; next} seen && /^[[:space:]]*UpdatedAt:/ {sub(/^[[:space:]]*UpdatedAt:[[:space:]]*/, ""); print; exit}' "$version_file")"

[[ -n "$trivy_version" ]] || fail "Trivy version output did not include the scanner version"
[[ -n "$db_version" ]] || fail "Trivy version output did not include the vulnerability DB version"
[[ -n "$db_updated_at" ]] || fail "Trivy version output did not include the vulnerability DB update timestamp"

mkdir -p "$(dirname "$receipt")"
jq -n \
  --arg generated_at "$generated_at" \
  --arg arch "$arch" \
  --arg postgres_version "$postgres_version" \
  --arg jar_sha256 "$jar_sha256" \
  --arg txz_sha256 "$txz_sha256" \
  --arg trivy_version "$trivy_version" \
  --arg db_version "$db_version" \
  --arg db_updated_at "$db_updated_at" \
  --rawfile trivy_version_output "$version_file" \
  --argjson high_total "$high_total" \
  --argjson high_fixable "$high_fixable" \
  --argjson critical_total "$critical_total" \
  --argjson critical_fixable "$critical_fixable" \
  --argjson packages_inventoried "$packages_inventoried" \
  --argjson version_evidence "$version_evidence" \
  --argjson server_pkg_evidence "$server_pkg_evidence" \
  --arg coverage_note "$coverage_note" \
  '{
    schema: "trstctl.embedded-postgres.trivy-receipt.v2",
    generated_at_utc: $generated_at,
    arch: $arch,
    postgres_version: $postgres_version,
    artifact: {
      jar_sha256: $jar_sha256,
      txz_sha256: $txz_sha256
    },
    scanner: {
      tool: "trivy",
      version: $trivy_version,
      vulnerability_db_version: $db_version,
      vulnerability_db_updated_at: $db_updated_at,
      version_output: $trivy_version_output
    },
    policy: {
      severity: "HIGH,CRITICAL",
      ignore_unfixed: true,
      fail_on_fixable_critical: true,
      fail_on_empty_inventory: true,
      fail_on_missing_pinned_version_evidence: true
    },
    coverage: {
      packages_inventoried: $packages_inventoried,
      pinned_version_evidence: $version_evidence,
      postgres_server_package_inventoried: (($server_pkg_evidence | length) > 0),
      note: $coverage_note
    },
    counts: {
      high: {
        total: $high_total,
        fixable: $high_fixable
      },
      critical: {
        total: $critical_total,
        fixable: $critical_fixable
      }
    },
    result: (if $critical_fixable == 0
               and $packages_inventoried > 0
               and ($version_evidence | length) > 0
             then "pass" else "fail" end)
  }' >"$receipt"

if [[ "$packages_inventoried" -eq 0 ]]; then
  fail "Trivy report inventoried 0 packages — a scan that examined nothing cannot certify anything; see $receipt and $report"
fi

if [[ "$version_evidence_count" -eq 0 ]]; then
  inventoried="$(jq -r '[.Results[]?.Packages[]? | "\(.Name // "?")@\(.Version // .InstalledVersion // "?")"] | join(", ")' "$report")"
  fail "Trivy report inventoried ${packages_inventoried} package(s) but none at the pinned PostgreSQL version ${postgres_version} — the scan did not cover the pinned binary; inventoried: ${inventoried}; see $receipt and $report"
fi

if [[ "$critical_fixable" -ne 0 ]]; then
  fail "Trivy found ${critical_fixable} fixable Critical finding(s); see $receipt and $report"
fi
