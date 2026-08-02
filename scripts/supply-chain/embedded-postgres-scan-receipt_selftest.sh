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

cat >"$tmp/trivy-version.txt" <<'EOF'
Version: 0.58.1
Vulnerability DB:
  Version: 2
  UpdatedAt: 2026-06-17 00:00:00 +0000 UTC
EOF

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
        {"VulnerabilityID": "CVE-HIGH", "Severity": "HIGH", "FixedVersion": "16.4.1"},
        {"VulnerabilityID": "CVE-CRIT-UNFIXED", "Severity": "CRITICAL", "FixedVersion": ""}
      ]
    }
  ]
}
EOF

"$here/embedded-postgres-scan-receipt.sh" "$tmp/pass.json" "$tmp/trivy-version.txt" "$tmp/pass-receipt.json" linux-amd64 16.4.0 jar txz
jq -e '.result == "pass" and .counts.high.fixable == 1 and .counts.critical.total == 1 and .counts.critical.fixable == 0' "$tmp/pass-receipt.json" >/dev/null
jq -e '.coverage.packages_inventoried == 1
  and (.coverage.pinned_version_evidence | length) == 1
  and .coverage.pinned_version_evidence[0].name == "postgresql-16"
  and .coverage.postgres_server_package_inventoried == true' "$tmp/pass-receipt.json" >/dev/null
ok records-inventory-coverage

cat >"$tmp/no-db-version.txt" <<'EOF'
Version: 0.58.1
EOF

set +e
"$here/embedded-postgres-scan-receipt.sh" "$tmp/pass.json" "$tmp/no-db-version.txt" "$tmp/no-db-receipt.json" linux-amd64 16.4.0 jar txz >/dev/null 2>"$tmp/no-db.err"
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
"$here/embedded-postgres-scan-receipt.sh" "$tmp/empty-inventory.json" "$tmp/trivy-version.txt" "$tmp/empty-receipt.json" linux-amd64 16.4.0 jar txz >/dev/null 2>"$tmp/empty.err"
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
"$here/embedded-postgres-scan-receipt.sh" "$tmp/wrapper-only.json" "$tmp/trivy-version.txt" "$tmp/drift-receipt.json" linux-amd64 16.14.0 jar txz >/dev/null 2>"$tmp/drift.err"
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

# Same report, pinned version matching: this passes, but the receipt must say out
# loud that the evidence came from the packaging coordinate and NOT from the
# PostgreSQL server itself, so the limit of the scan is on the record.
set +e
"$here/embedded-postgres-scan-receipt.sh" "$tmp/wrapper-only.json" "$tmp/trivy-version.txt" "$tmp/coordinate-receipt.json" linux-amd64 16.4.0 jar txz >/dev/null 2>"$tmp/coordinate.err"
status="$?"
set -e
if [[ "$status" -ne 0 ]]; then
  echo "receipt policy rejected a report that does carry the pinned version"
  cat "$tmp/coordinate.err"
  exit 1
fi
jq -e '.result == "pass"
  and .coverage.postgres_server_package_inventoried == false
  and .coverage.pinned_version_evidence[0].name == "io.zonky.test.postgres:embedded-postgres-binaries-linux-amd64"
  and (.coverage.note | test("only by the packaging coordinate"))' "$tmp/coordinate-receipt.json" >/dev/null
ok names-the-package-that-supplied-the-version-evidence

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
"$here/embedded-postgres-scan-receipt.sh" "$tmp/fail.json" "$tmp/trivy-version.txt" "$tmp/fail-receipt.json" linux-amd64 16.4.0 jar txz >/dev/null 2>"$tmp/fail.err"
status="$?"
set -e
if [[ "$status" -eq 0 ]]; then
  echo "receipt policy accepted a fixable Critical finding"
  exit 1
fi
jq -e '.result == "fail" and .counts.critical.fixable == 1' "$tmp/fail-receipt.json" >/dev/null
grep -q 'fixable Critical' "$tmp/fail.err"
ok rejects-fixable-critical

echo "ALL SELF-TESTS PASSED"
