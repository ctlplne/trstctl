#!/usr/bin/env bash
#
# Verify the provenance of the PostgreSQL binary that the embedded-postgres test
# dependency downloads at runtime, then scan it. That binary comes from Maven
# Central (NOT the Go module proxy), so it is outside go.sum and needs its own
# pin + scan before any redistribution that bundles it.
#
# Trust-on-first-use: if the manifest has no pinned SHA-256 yet, this prints the
# observed hash for a maintainer to pin and commit. Once pinned, every run
# verifies it and fails on any change. Requires network access (Maven Central).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
manifest="$repo/deploy/supply-chain/embedded-postgres.json"
workdir="$repo/.supply-chain/embedded-postgres"

for tool in jq curl sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "::error::$tool is required" >&2; exit 1; }
done

url="$(jq -r '.source.urlTemplate' "$manifest")"
want="$(jq -r '.checksum.sha256 // ""' "$manifest")"
ver="$(jq -r '.postgresVersion' "$manifest")"

mkdir -p "$workdir"
jar="$workdir/embedded-postgres-${ver}.jar"

echo ">> downloading PostgreSQL ${ver} binary: ${url}"
curl -fsSL "$url" -o "$jar"

got="$(sha256sum "$jar" | awk '{print $1}')"
echo ">> sha256(${ver}) = ${got}"

if [ -z "$want" ]; then
  echo "::notice::no pinned checksum yet for embedded-postgres ${ver} (trust-on-first-use)."
  echo "    ACTION: set .checksum.sha256 in deploy/supply-chain/embedded-postgres.json to:"
  echo "        ${got}"
  echo "    then commit it so every future run is verified."
elif [ "$got" != "$want" ]; then
  echo "::error::embedded-postgres ${ver} checksum mismatch — refusing to proceed" >&2
  echo "    expected ${want}" >&2
  echo "    got      ${got}" >&2
  exit 1
else
  echo ">> checksum verified against the pinned manifest"
fi

echo ">> extracting for vulnerability scan"
( cd "$workdir" && unzip -oq "$jar" )
# The jar wraps a postgres-<os>-<arch>.txz; unpack any we find so Trivy can scan
# the actual binaries and shared libraries.
find "$workdir" -name '*.txz' -print0 | while IFS= read -r -d '' txz; do
  tar -xf "$txz" -C "$workdir" 2>/dev/null || true
done

# The scan is advisory (exit-code 0): this binary is integration-test only and is
# not shipped, and a transitive OS-package CVE in a prebuilt PostgreSQL binary is
# only fixable by bumping the pinned version upstream — so we RECORD findings here
# rather than block the build. The hard gate is the checksum-change check above.
TRIVY_IMAGE="aquasec/trivy:0.58.1"
scan_args=(rootfs --severity HIGH,CRITICAL --ignore-unfixed --no-progress --exit-code 0)
if command -v trivy >/dev/null 2>&1; then
  echo ">> trivy rootfs scan (local binary; advisory)"
  trivy "${scan_args[@]}" "$workdir" || echo "::warning::trivy scan did not complete cleanly (advisory; checksum gate already passed)"
elif command -v docker >/dev/null 2>&1; then
  echo ">> trivy rootfs scan (pinned ${TRIVY_IMAGE}; advisory)"
  docker run --rm -v "${workdir}:/scan:ro" "$TRIVY_IMAGE" "${scan_args[@]}" /scan \
    || echo "::warning::trivy (docker) scan did not complete cleanly (advisory; checksum gate already passed)"
else
  echo "::notice::neither trivy nor docker present; provenance + checksum verified, deep scan skipped."
fi

echo ">> embedded-postgres supply-chain check complete"
