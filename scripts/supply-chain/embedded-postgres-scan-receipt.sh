#!/usr/bin/env bash
# Reduce embedded-PostgreSQL scanner and official PostgreSQL CNA evidence into a
# compact receipt. The extracted Zonky archive has no OS package database, so
# Trivy commonly inventories only the Maven wrapper. A wrapper VERSION is not a
# PostgreSQL server advisory match: the gate needs either a named server package
# in Trivy or a fresh official PostgreSQL catalog for this exact server version.
set -euo pipefail

fail() {
  printf '::error::embedded-postgres scan receipt: %s\n' "$*" >&2
  exit 1
}

if [[ "$#" -lt 8 || "$#" -gt 9 ]]; then
  fail "usage: embedded-postgres-scan-receipt.sh <trivy-json> <trivy-version.txt> <receipt-json> <arch> <postgres-version> <jar-sha256> <txz-sha256> <committed-manifest.json> [postgresql-security-catalog.json]"
fi

report="$1"
version_file="$2"
receipt="$3"
arch="$4"
postgres_version="$5"
jar_sha256="$6"
txz_sha256="$7"
manifest="$8"
catalog="${9:-}"

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
[[ -s "$report" ]] || fail "Trivy JSON report is missing or empty: $report"
[[ -s "$version_file" ]] || fail "Trivy version output is missing or empty: $version_file"

# PROVENANCE is evaluated independently from vulnerability status. The verifier
# passes hashes computed from the downloaded bytes; this reducer rebinds those
# observations to the exact committed version/architecture manifest rather than
# stamping a hard-coded “verified” label into every receipt.
provenance_verified=false
provenance_error=""
sha256_pattern='^[0-9a-f]{64}$'
manifest_sha256=""
manifest_postgres_version=""
manifest_source_version=""
expected_jar_sha256=""
expected_txz_sha256=""
if [[ ! -s "$manifest" ]]; then
  provenance_error="committed provenance manifest is missing or empty: ${manifest}"
elif ! jq -e '
    type == "object"
    and (.postgresVersion | type == "string" and length > 0)
    and (.source.version | type == "string" and length > 0)
    and (.archives | type == "array")' "$manifest" >/dev/null 2>&1; then
  provenance_error="committed provenance manifest is invalid: ${manifest}"
else
  manifest_sha256="$(sha256sum "$manifest" | awk '{print $1}')"
  manifest_postgres_version="$(jq -r '.postgresVersion' "$manifest")"
  manifest_source_version="$(jq -r '.source.version' "$manifest")"
  manifest_arch_count="$(jq --arg arch "$arch" '[.archives[] | select(.arch == $arch)] | length' "$manifest")"
  if [[ "$manifest_arch_count" -ne 1 ]]; then
    provenance_error="committed provenance manifest has ${manifest_arch_count} entries for architecture ${arch}, expected exactly one"
  else
    expected_jar_sha256="$(jq -r --arg arch "$arch" '.archives[] | select(.arch == $arch) | .jar_sha256 // ""' "$manifest")"
    expected_txz_sha256="$(jq -r --arg arch "$arch" '.archives[] | select(.arch == $arch) | .txz_sha256 // ""' "$manifest")"
    if [[ "$manifest_postgres_version" != "$postgres_version" || "$manifest_source_version" != "$postgres_version" ]]; then
      provenance_error="committed provenance manifest version ${manifest_postgres_version}/${manifest_source_version} does not match observed PostgreSQL ${postgres_version}"
    elif [[ -z "$expected_jar_sha256" || -z "$expected_txz_sha256" ]]; then
      provenance_error="committed provenance manifest has empty jar/TXZ hashes for ${arch}"
    elif [[ ! "$expected_jar_sha256" =~ $sha256_pattern || ! "$expected_txz_sha256" =~ $sha256_pattern || ! "$jar_sha256" =~ $sha256_pattern || ! "$txz_sha256" =~ $sha256_pattern ]]; then
      provenance_error="committed and observed jar/TXZ values must all be lowercase 64-character SHA-256 digests"
    elif [[ "$expected_jar_sha256" != "$jar_sha256" || "$expected_txz_sha256" != "$txz_sha256" ]]; then
      provenance_error="observed artifact provenance does not match the committed manifest for ${arch} PostgreSQL ${postgres_version}"
    else
      provenance_verified=true
    fi
  fi
fi

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

# INVENTORY COVERAGE answers “what did Trivy actually recognize?” A Maven
# coordinate carrying 16.14.0 proves artifact/version alignment, but it does not
# make PostgreSQL server CVEs appear in Trivy's Vulnerabilities array.
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
server_pkg_evidence="$(printf '%s' "$version_evidence" | jq -c '
  [ .[] | select((.name | ascii_downcase) | test("(^|/)postgres(ql)?($|[0-9._-])")) ]')"
server_pkg_count="$(printf '%s' "$server_pkg_evidence" | jq 'length')"

# AUTHORITATIVE ADVISORY COVERAGE is optional only when Trivy explicitly named
# the PostgreSQL server package. When supplied, it must be fresh and must assess
# this exact pin; a stale/mismatched catalog is evidence failure, not a fallback.
catalog_provided=false
catalog_evaluated=false
catalog_error=""
catalog_source='null'
catalog_assessed_version=""
catalog_advisory_count=0
catalog_age_seconds=-1
affected_advisories='[]'
affected_high=0
affected_critical=0
catalog_max_age_seconds=86400
expected_major="${postgres_version%%.*}"
expected_source_url="https://www.postgresql.org/support/security/${expected_major}/"

if [[ -n "$catalog" ]]; then
  catalog_provided=true
  if [[ ! -s "$catalog" ]]; then
    catalog_error="official PostgreSQL catalog is missing or empty: ${catalog}"
  elif ! jq -e 'type == "object"' "$catalog" >/dev/null 2>&1; then
    catalog_error="official PostgreSQL catalog is not valid JSON: ${catalog}"
  elif ! jq -e '
      .schema == "trstctl.postgresql-security-catalog.v1"
      and (.source | type == "object")
      and (.source.authority == "PostgreSQL Global Development Group CVE Numbering Authority")
      and (.source.url | type == "string")
      and (.source.fetched_at_utc | type == "string")
      and (.source.fetched_at_unix | type == "number")
      and (.source.content_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
      and (.assessed_postgres_version | type == "string")
      and (.assessed_major | type == "string")
      and (.advisories | type == "array" and length > 0)
      and all(.advisories[];
        (.cve | type == "string" and test("^CVE-[0-9]{4}-[0-9]{4,}$"))
        and (.advisory_url | type == "string" and startswith("https://www.postgresql.org/"))
        and (.fixed_version | type == "string" and test("^[0-9]+([.][0-9]+){1,2}$"))
        and (.component | type == "string" and length > 0)
        and (.cvss_score | type == "number")
        and (.cvss_vector | type == "string" and (startswith("CVSS:") or startswith("AV:")))
        and (.severity == "LOW" or .severity == "MEDIUM" or .severity == "HIGH" or .severity == "CRITICAL")
        and (.affects_assessed_version | type == "boolean")
      )' "$catalog" >/dev/null 2>&1; then
    catalog_error="official PostgreSQL catalog has an invalid or incomplete schema: ${catalog}"
  else
    catalog_source="$(jq -c '.source' "$catalog")"
    catalog_assessed_version="$(jq -r '.assessed_postgres_version' "$catalog")"
    catalog_major="$(jq -r '.assessed_major' "$catalog")"
    catalog_source_url="$(jq -r '.source.url' "$catalog")"
    fetched_at_unix="$(jq -r '.source.fetched_at_unix | floor' "$catalog")"
    catalog_advisory_count="$(jq '.advisories | length' "$catalog")"
    now_unix="$(date +%s)"
    catalog_age_seconds="$((now_unix - fetched_at_unix))"

    if [[ "$catalog_assessed_version" != "$postgres_version" ]]; then
      catalog_error="official PostgreSQL catalog assessed ${catalog_assessed_version}, not pinned version ${postgres_version}"
    elif [[ "$catalog_major" != "$expected_major" ]]; then
      catalog_error="official PostgreSQL catalog assessed major ${catalog_major}, not pinned major ${expected_major}"
    elif [[ "$catalog_source_url" != "$expected_source_url" ]]; then
      catalog_error="official PostgreSQL catalog source is ${catalog_source_url}, expected ${expected_source_url}"
    elif [[ "$catalog_age_seconds" -lt -300 ]]; then
      catalog_error="official PostgreSQL catalog timestamp is ${catalog_age_seconds}s in the future"
    elif [[ "$catalog_age_seconds" -gt "$catalog_max_age_seconds" ]]; then
      catalog_error="official PostgreSQL catalog is stale: age ${catalog_age_seconds}s exceeds ${catalog_max_age_seconds}s"
    else
      affected_advisories="$(jq -c --arg pinned "$postgres_version" '
        def version_parts:
          split(".") | map(tonumber) | . + [0, 0, 0] | .[0:3];
        [ .advisories[]
          | select(.severity == "HIGH" or .severity == "CRITICAL")
          | select(($pinned | version_parts) < (.fixed_version | version_parts)) ]' "$catalog")"
      affected_high="$(printf '%s' "$affected_advisories" | jq '[.[] | select(.severity == "HIGH")] | length')"
      affected_critical="$(printf '%s' "$affected_advisories" | jq '[.[] | select(.severity == "CRITICAL")] | length')"
      catalog_evaluated=true
    fi
  fi
fi

if [[ "$server_pkg_count" -gt 0 && "$catalog_evaluated" == true ]]; then
  coverage_note="Trivy named the PostgreSQL server package and a fresh official PostgreSQL catalog independently assessed the exact pin"
elif [[ "$server_pkg_count" -gt 0 ]]; then
  coverage_note="Trivy named the PostgreSQL server package, so its scanner inventory can match server advisories"
elif [[ "$catalog_evaluated" == true ]]; then
  coverage_note="Trivy saw only packaging evidence; a fresh official PostgreSQL CNA catalog independently assessed the exact server pin"
else
  coverage_note="the pin is evidenced only by packaging metadata; neither Trivy nor fresh official PostgreSQL evidence covered server advisories"
fi

generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
trivy_version="$(awk -F': ' '/^Version:/ {print $2; exit}' "$version_file")"
db_version="$(awk '/^Vulnerability DB:/ {seen=1; next} seen && /^[[:space:]]*Version:/ {sub(/^[[:space:]]*Version:[[:space:]]*/, ""); print; exit}' "$version_file")"
db_updated_at="$(awk '/^Vulnerability DB:/ {seen=1; next} seen && /^[[:space:]]*UpdatedAt:/ {sub(/^[[:space:]]*UpdatedAt:[[:space:]]*/, ""); print; exit}' "$version_file")"

[[ -n "$trivy_version" ]] || fail "Trivy version output did not include the scanner version"
[[ -n "$db_version" ]] || fail "Trivy version output did not include the vulnerability DB version"
[[ -n "$db_updated_at" ]] || fail "Trivy version output did not include the vulnerability DB update timestamp"

if [[ "$catalog_provided" == true ]]; then
  coverage_satisfied="$catalog_evaluated"
elif [[ "$server_pkg_count" -gt 0 ]]; then
  coverage_satisfied=true
else
  coverage_satisfied=false
fi

mkdir -p "$(dirname "$receipt")"
jq -n \
  --arg generated_at "$generated_at" \
  --arg arch "$arch" \
  --arg postgres_version "$postgres_version" \
  --arg jar_sha256 "$jar_sha256" \
  --arg txz_sha256 "$txz_sha256" \
  --argjson provenance_verified "$provenance_verified" \
  --arg provenance_error "$provenance_error" \
  --arg manifest_sha256 "$manifest_sha256" \
  --arg manifest_postgres_version "$manifest_postgres_version" \
  --arg manifest_source_version "$manifest_source_version" \
  --arg expected_jar_sha256 "$expected_jar_sha256" \
  --arg expected_txz_sha256 "$expected_txz_sha256" \
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
  --argjson catalog_provided "$catalog_provided" \
  --argjson catalog_evaluated "$catalog_evaluated" \
  --arg catalog_error "$catalog_error" \
  --argjson catalog_source "$catalog_source" \
  --arg catalog_assessed_version "$catalog_assessed_version" \
  --argjson catalog_advisory_count "$catalog_advisory_count" \
  --argjson catalog_age_seconds "$catalog_age_seconds" \
  --argjson catalog_max_age_seconds "$catalog_max_age_seconds" \
  --argjson affected_advisories "$affected_advisories" \
  --argjson affected_high "$affected_high" \
  --argjson affected_critical "$affected_critical" \
  --argjson coverage_satisfied "$coverage_satisfied" \
  'def receipt_passes:
     $provenance_verified
     and $packages_inventoried > 0
     and ($version_evidence | length) > 0
     and $high_fixable == 0
     and $critical_fixable == 0
     and $coverage_satisfied
     and $affected_high == 0
     and $affected_critical == 0;
   {
    schema: "trstctl.embedded-postgres.security-receipt.v3",
    generated_at_utc: $generated_at,
    arch: $arch,
    postgres_version: $postgres_version,
    artifact: {
      jar_sha256: $jar_sha256,
      txz_sha256: $txz_sha256,
      checksum_verification: (if $provenance_verified then "verified-against-committed-manifest" else "failed" end),
      provenance: {
        result: (if $provenance_verified then "pass" else "fail" end),
        validation_error: (if $provenance_error == "" then null else $provenance_error end),
        manifest: {
          content_sha256: (if $manifest_sha256 == "" then null else $manifest_sha256 end),
          postgres_version: (if $manifest_postgres_version == "" then null else $manifest_postgres_version end),
          source_version: (if $manifest_source_version == "" then null else $manifest_source_version end)
        },
        expected: {
          jar_sha256: (if $expected_jar_sha256 == "" then null else $expected_jar_sha256 end),
          txz_sha256: (if $expected_txz_sha256 == "" then null else $expected_txz_sha256 end)
        },
        observed: {
          jar_sha256: $jar_sha256,
          txz_sha256: $txz_sha256
        }
      }
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
      ignore_unfixed_in_trivy: true,
      fail_on_fixable_high_or_critical: true,
      fail_on_empty_inventory: true,
      fail_on_missing_pinned_version_evidence: true,
      require_postgres_server_advisory_coverage: true,
      authoritative_catalog_max_age_seconds: $catalog_max_age_seconds,
      accepted_server_coverage: [
        "trivy-named-postgresql-server-package",
        "fresh-official-postgresql-cna-catalog-for-exact-version"
      ]
    },
    coverage: {
      packages_inventoried: $packages_inventoried,
      pinned_version_evidence: $version_evidence,
      postgres_server_package_inventoried: (($server_pkg_evidence | length) > 0),
      postgres_server_package_evidence: $server_pkg_evidence,
      server_advisory_coverage_satisfied: $coverage_satisfied,
      note: $coverage_note
    },
    authoritative_advisory_catalog: {
      provided: $catalog_provided,
      evaluated: $catalog_evaluated,
      validation_error: (if $catalog_error == "" then null else $catalog_error end),
      source: $catalog_source,
      assessed_postgres_version: (if $catalog_assessed_version == "" then null else $catalog_assessed_version end),
      age_seconds: (if $catalog_age_seconds < 0 then null else $catalog_age_seconds end),
      advisories_evaluated: $catalog_advisory_count,
      affected_high: $affected_high,
      affected_critical: $affected_critical,
      affected_advisories: $affected_advisories
    },
    counts: {
      high: {total: $high_total, fixable: $high_fixable},
      critical: {total: $critical_total, fixable: $critical_fixable}
    },
    result: (if receipt_passes then "pass" else "fail" end)
  }' >"$receipt"

if [[ "$provenance_verified" != true ]]; then
  fail "$provenance_error; see $receipt and $manifest"
fi

if [[ "$packages_inventoried" -eq 0 ]]; then
  fail "Trivy report inventoried 0 packages — a scan that examined nothing cannot certify anything; see $receipt and $report"
fi

if [[ "$version_evidence_count" -eq 0 ]]; then
  inventoried="$(jq -r '[.Results[]?.Packages[]? | "\(.Name // "?")@\(.Version // .InstalledVersion // "?")"] | join(", ")' "$report")"
  fail "Trivy report inventoried ${packages_inventoried} package(s) but none at the pinned PostgreSQL version ${postgres_version} — the scan did not cover the pinned binary; inventoried: ${inventoried}; see $receipt and $report"
fi

if [[ "$high_fixable" -ne 0 || "$critical_fixable" -ne 0 ]]; then
  fail "Trivy found ${high_fixable} fixable HIGH and ${critical_fixable} fixable CRITICAL finding(s); see $receipt and $report"
fi

if [[ "$catalog_provided" == true && "$catalog_evaluated" != true ]]; then
  fail "$catalog_error; see $receipt and $catalog"
fi

if [[ "$coverage_satisfied" != true ]]; then
  fail "neither a named PostgreSQL server package nor fresh official PostgreSQL advisory evidence covered ${postgres_version}; see $receipt and $report"
fi

affected_total="$((affected_high + affected_critical))"
if [[ "$affected_total" -ne 0 ]]; then
  affected_ids="$(printf '%s' "$affected_advisories" | jq -r '[.[].cve] | join(", ")')"
  fail "official PostgreSQL catalog matched ${affected_total} affected HIGH/CRITICAL advisory(s) (${affected_ids}); see $receipt and $catalog"
fi
