#!/usr/bin/env bash
# Self-test for the embedded-postgres Trivy receipt policy. It proves HIGH and
# non-fixable Critical findings are recorded, fixable Critical findings fail, and
# that a report which inventoried nothing — or nothing at the pinned PostgreSQL
# version — is rejected instead of being written out as a clean receipt.
#
# Each case prints one "SELFTEST-OK <name>" line and the caller asserts the exact
# count, so removing a case is visible rather than a silent coverage loss.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok() { printf 'SELFTEST-OK %s\n' "$1"; }

jar_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
txz_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
wrong_jar_sha="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

receipt() {
  "$here/embedded-postgres-scan-receipt.sh" "$@"
}

cat >"$tmp/trivy-version.txt" <<'EOF'
Version: 0.58.1
Vulnerability DB:
  Version: 2
  UpdatedAt: 2026-06-17 00:00:00 +0000 UTC
EOF

# The official PostgreSQL project is the CNA for PostgreSQL. Its supported-major
# security table is the independent server advisory inventory when Trivy can see
# only the Maven wrapper coordinate around the extracted server binaries.
cat >"$tmp/postgresql-security.html" <<'EOF'
<html><body><table>
  <tr><th>CVE</th><th>Affected</th><th>Fixed</th><th>Component / CVSS</th><th>Summary</th></tr>
  <tr>
    <td><a href="/support/security/CVE-2026-16239/">CVE-2026-16239</a></td>
    <td>13 - 16</td><td>13.20, 14.17, 15.12, 16.8</td>
    <td>Core server 8.8 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
    <td>Representative server advisory.</td>
  </tr>
</table></body></html>
EOF

"$here/postgresql-security-catalog.py" \
  --html "$tmp/postgresql-security.html" \
  --output "$tmp/postgresql-security.json" \
  --postgres-version 16.7.0 \
  --source-url https://www.postgresql.org/support/security/16/
jq -e '.schema == "trstctl.postgresql-security-catalog.v1"
  and .assessed_postgres_version == "16.7.0"
  and .advisories[0].cve == "CVE-2026-16239"
  and .advisories[0].fixed_version == "16.8"
  and .advisories[0].severity == "HIGH"' "$tmp/postgresql-security.json" >/dev/null
ok parses-authoritative-postgresql-catalog

cat >"$tmp/postgresql-security-clean.html" <<'EOF'
<html><body><table><tr>
  <td><a href="/support/security/CVE-2025-10001/">CVE-2025-10001</a></td>
  <td>13 - 16</td><td>13.16, 14.13, 15.8, 16.4</td>
  <td>Core server 8.1 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N</td>
  <td>Already fixed at the assessed version.</td>
</tr></table></body></html>
EOF
"$here/postgresql-security-catalog.py" \
  --html "$tmp/postgresql-security-clean.html" \
  --output "$tmp/postgresql-security-clean.json" \
  --postgres-version 16.4.0 \
  --source-url https://www.postgresql.org/support/security/16/
"$here/postgresql-security-catalog.py" \
  --html "$tmp/postgresql-security-clean.html" \
  --output "$tmp/postgresql-security-clean-16.14.json" \
  --postgres-version 16.14.0 \
  --source-url https://www.postgresql.org/support/security/16/

cat >"$tmp/manifest-16.4.json" <<EOF
{
  "postgresVersion": "16.4.0",
  "source": {"version": "16.4.0"},
  "archives": [
    {"arch": "linux-amd64", "jar_sha256": "$jar_sha", "txz_sha256": "$txz_sha"}
  ]
}
EOF
jq '.postgresVersion = "16.14.0" | .source.version = "16.14.0"' "$tmp/manifest-16.4.json" >"$tmp/manifest-16.14.json"
jq '.postgresVersion = "16.7.0" | .source.version = "16.7.0"' "$tmp/manifest-16.4.json" >"$tmp/manifest-16.7.json"

cat >"$tmp/pass.json" <<'EOF'
{
  "Results": [
    {
      "Target": "postgres",
      "Class": "os-pkgs",
      "Type": "debian",
      "Packages": [
        {"Name": "postgresql-16", "Version": "16.4.0"}
      ],
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-HIGH-UNFIXED", "Severity": "HIGH", "FixedVersion": ""},
        {"VulnerabilityID": "CVE-CRIT-UNFIXED", "Severity": "CRITICAL", "FixedVersion": ""}
      ]
    }
  ]
}
EOF

receipt "$tmp/pass.json" "$tmp/trivy-version.txt" "$tmp/pass-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security-clean.json"
jq -e '.result == "pass" and .counts.high.total == 1 and .counts.high.fixable == 0 and .counts.critical.total == 1 and .counts.critical.fixable == 0' "$tmp/pass-receipt.json" >/dev/null
jq -e '.coverage.packages_inventoried == 1
  and (.coverage.pinned_version_evidence | length) == 1
  and .coverage.pinned_version_evidence[0].name == "postgresql-16"
  and .coverage.postgres_server_package_inventoried == true
  and .artifact.provenance.result == "pass"
  and .authoritative_advisory_catalog.evaluated == true
  and .authoritative_advisory_catalog.affected_high == 0' "$tmp/pass-receipt.json" >/dev/null
ok records-inventory-coverage

cat >"$tmp/no-db-version.txt" <<'EOF'
Version: 0.58.1
EOF

set +e
receipt "$tmp/pass.json" "$tmp/no-db-version.txt" "$tmp/no-db-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security-clean.json" >/dev/null 2>"$tmp/no-db.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy accepted missing Trivy DB metadata"
  exit 1
fi
grep -q 'vulnerability DB version' "$tmp/no-db.err"
ok rejects-missing-trivy-db-metadata

# An empty scan must not read as a clean scan: every severity count is 0 here,
# exactly as it is for a genuinely clean scan.
cat >"$tmp/empty-inventory.json" <<'EOF'
{
  "SchemaVersion": 2,
  "ArtifactName": "/scan",
  "Results": []
}
EOF

set +e
receipt "$tmp/empty-inventory.json" "$tmp/trivy-version.txt" "$tmp/empty-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security-clean.json" >/dev/null 2>"$tmp/empty.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy certified a scan that inventoried 0 packages"
  exit 1
fi
grep -q 'inventoried 0 packages' "$tmp/empty.err"
jq -e '.result == "fail" and .coverage.packages_inventoried == 0' "$tmp/empty-receipt.json" >/dev/null
ok rejects-empty-inventory

# The vacuity an "empty Results" check alone would miss: Results is non-empty and
# does list a package, but nothing carries the pinned server version, so the
# pinned binary was never examined. This is the shape of the real rootfs report.
cat >"$tmp/wrapper-only.json" <<'EOF'
{
  "SchemaVersion": 2,
  "ArtifactName": "/scan",
  "Results": [
    {
      "Target": "Java",
      "Class": "lang-pkgs",
      "Type": "jar",
      "Packages": [
        {"Name": "io.zonky.test.postgres:embedded-postgres-binaries-linux-amd64", "Version": "16.4.0"}
      ]
    }
  ]
}
EOF

set +e
receipt "$tmp/wrapper-only.json" "$tmp/trivy-version.txt" "$tmp/drift-receipt.json" linux-amd64 16.14.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.14.json" "$tmp/postgresql-security-clean-16.14.json" >/dev/null 2>"$tmp/drift.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy certified a scan with no package at the pinned PostgreSQL version"
  exit 1
fi
grep -q 'none at the pinned PostgreSQL version 16.14.0' "$tmp/drift.err"
grep -q 'io.zonky.test.postgres:embedded-postgres-binaries-linux-amd64@16.4.0' "$tmp/drift.err"
jq -e '.result == "fail" and (.coverage.pinned_version_evidence | length) == 0' "$tmp/drift-receipt.json" >/dev/null
ok rejects-missing-pinned-version-evidence

# Same report, pinned version matching: the wrapper is not server coverage. It
# passes only because a fresh official PostgreSQL catalog independently assessed
# this exact version and found no still-affected HIGH/CRITICAL advisory.
set +e
receipt "$tmp/wrapper-only.json" "$tmp/trivy-version.txt" "$tmp/coordinate-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security-clean.json" >/dev/null 2>"$tmp/coordinate.err"
status="$?"
set -e
if [[ "$status" -ne 0 ]]; then
  echo "receipt policy rejected fresh official evidence for the wrapper-only binary"
  cat "$tmp/coordinate.err"
  exit 1
fi
jq -e '.result == "pass"
  and .coverage.postgres_server_package_inventoried == false
  and .coverage.pinned_version_evidence[0].name == "io.zonky.test.postgres:embedded-postgres-binaries-linux-amd64"
  and .authoritative_advisory_catalog.evaluated == true
  and .authoritative_advisory_catalog.assessed_postgres_version == "16.4.0"
  and (.coverage.note | test("official PostgreSQL"))' "$tmp/coordinate-receipt.json" >/dev/null
ok accepts-wrapper-only-with-clean-official-evidence

jq '(.Results[].Packages[].Version) = "16.7.0"' "$tmp/wrapper-only.json" >"$tmp/wrapper-only-vulnerable.json"

set +e
receipt "$tmp/wrapper-only.json" "$tmp/trivy-version.txt" "$tmp/no-authority-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" >/dev/null 2>"$tmp/no-authority.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy certified a wrapper coordinate without server advisory evidence"
  exit 1
fi
grep -q 'neither a named PostgreSQL server package nor fresh official PostgreSQL advisory evidence' "$tmp/no-authority.err"
jq -e '.result == "fail" and .authoritative_advisory_catalog.evaluated == false' "$tmp/no-authority-receipt.json" >/dev/null
ok rejects-wrapper-only-without-authoritative-evidence

set +e
receipt "$tmp/wrapper-only-vulnerable.json" "$tmp/trivy-version.txt" "$tmp/vulnerable-receipt.json" linux-amd64 16.7.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.7.json" "$tmp/postgresql-security.json" >/dev/null 2>"$tmp/vulnerable.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy certified a version affected by an official HIGH advisory"
  exit 1
fi
grep -q 'official PostgreSQL catalog matched 1 affected HIGH/CRITICAL' "$tmp/vulnerable.err"
jq -e '.result == "fail"
  and .authoritative_advisory_catalog.affected_high == 1
  and .authoritative_advisory_catalog.affected_critical == 0
  and .authoritative_advisory_catalog.affected_advisories[0].cve == "CVE-2026-16239"' "$tmp/vulnerable-receipt.json" >/dev/null
ok rejects-official-high-server-advisory

jq '.source.fetched_at_unix = 1 | .source.fetched_at_utc = "1970-01-01T00:00:01Z"' \
  "$tmp/postgresql-security-clean.json" >"$tmp/postgresql-security-stale.json"
set +e
receipt "$tmp/wrapper-only.json" "$tmp/trivy-version.txt" "$tmp/stale-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security-stale.json" >/dev/null 2>"$tmp/stale.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy certified stale official advisory evidence"
  exit 1
fi
grep -q 'official PostgreSQL catalog is stale' "$tmp/stale.err"
ok rejects-stale-official-evidence

set +e
receipt "$tmp/wrapper-only.json" "$tmp/trivy-version.txt" "$tmp/mismatch-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security.json" >/dev/null 2>"$tmp/mismatch.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy accepted official evidence for a different PostgreSQL version"
  exit 1
fi
grep -q 'assessed 16.7.0, not pinned version 16.4.0' "$tmp/mismatch.err"
ok rejects-version-mismatched-official-evidence

set +e
receipt "$tmp/pass.json" "$tmp/trivy-version.txt" "$tmp/provenance-receipt.json" linux-amd64 16.4.0 "$wrong_jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security-clean.json" >/dev/null 2>"$tmp/provenance.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy accepted observed hashes that differ from the committed manifest"
  exit 1
fi
grep -q 'observed artifact provenance does not match the committed manifest' "$tmp/provenance.err"
jq -e --arg expected "$jar_sha" --arg observed "$wrong_jar_sha" '.result == "fail" and .artifact.provenance.result == "fail"
  and .artifact.provenance.expected.jar_sha256 == $expected
  and .artifact.provenance.observed.jar_sha256 == $observed' "$tmp/provenance-receipt.json" >/dev/null
ok rejects-provenance-mismatch

cat >"$tmp/fail.json" <<'EOF'
{
  "Results": [
    {
      "Target": "postgres",
      "Class": "os-pkgs",
      "Type": "debian",
      "Packages": [
        {"Name": "postgresql-16", "Version": "16.4.0"}
      ],
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-CRIT-FIXABLE", "Severity": "CRITICAL", "FixedVersion": "16.4.1"}
      ]
    }
  ]
}
EOF

set +e
receipt "$tmp/fail.json" "$tmp/trivy-version.txt" "$tmp/fail-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security-clean.json" >/dev/null 2>"$tmp/fail.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy accepted a fixable Critical finding"
  exit 1
fi
jq -e '.result == "fail" and .counts.critical.fixable == 1' "$tmp/fail-receipt.json" >/dev/null
grep -q 'fixable CRITICAL' "$tmp/fail.err"
ok rejects-fixable-critical

jq '(.Results[0].Vulnerabilities[0].Severity) = "HIGH"' "$tmp/fail.json" >"$tmp/fail-high.json"
set +e
receipt "$tmp/fail-high.json" "$tmp/trivy-version.txt" "$tmp/fail-high-receipt.json" linux-amd64 16.4.0 "$jar_sha" "$txz_sha" "$tmp/manifest-16.4.json" "$tmp/postgresql-security-clean.json" >/dev/null 2>"$tmp/fail-high.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy accepted a fixable HIGH finding"
  exit 1
fi
jq -e '.result == "fail" and .counts.high.fixable == 1' "$tmp/fail-high-receipt.json" >/dev/null
grep -q 'fixable HIGH' "$tmp/fail-high.err"
ok rejects-fixable-high

echo "ALL SELF-TESTS PASSED"
