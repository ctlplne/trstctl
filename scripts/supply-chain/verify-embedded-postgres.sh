#!/usr/bin/env bash
#
# Verify the provenance of the PostgreSQL binary that the embedded-postgres
# dependency downloads at runtime, then scan it. That binary comes from Maven
# Central (NOT the Go module proxy), so it is outside go.sum and needs its own
# COMMITTED pin + scan. It is run both by the integration tests AND by the served
# single-node/eval path (internal/server/startBundledPostgres), so the pin is a
# HARD gate here and is enforced again at runtime (SUPPLY-003).
#
# The committed pin is per-arch (deploy/supply-chain/embedded-postgres.json
# archives[]). This script verifies the jar for the requested arch against
# jar_sha256, and the inner .txz against txz_sha256 (the artifact the runtime
# verifies). A missing pin is a HARD FAILURE now — no trust-on-first-use fallback,
# because the pin has been completed. Requires network access (Maven Central).
#
#   ARCH=linux-amd64 ./verify-embedded-postgres.sh   # default
#   ARCH=linux-arm64v8 ./verify-embedded-postgres.sh
#   ARCH=darwin-arm64v8 ./verify-embedded-postgres.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
manifest="$repo/deploy/supply-chain/embedded-postgres.json"
workdir="$repo/.supply-chain/embedded-postgres"

for tool in jq curl sha256sum unzip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "::error::$tool is required" >&2; exit 1; }
done

ver="$(jq -r '.postgresVersion' "$manifest")"
arch="${ARCH:-linux-amd64}"

# Pull the per-arch pins + jar URL from the committed manifest.
entry="$(jq -c --arg a "$arch" '.archives[] | select(.arch == $a)' "$manifest")"
if [ -z "$entry" ] || [ "$entry" = "null" ]; then
  echo "::error::no committed provenance pin for arch ${arch} in ${manifest} (SUPPLY-003)" >&2
  echo "    known arches: $(jq -r '.archives[].arch' "$manifest" | paste -sd, -)" >&2
  exit 1
fi
url="$(printf '%s' "$entry" | jq -r '.jarUrl')"
wantJar="$(printf '%s' "$entry" | jq -r '.jar_sha256 // ""')"
wantTxz="$(printf '%s' "$entry" | jq -r '.txz_sha256 // ""')"

if [ -z "$wantJar" ] || [ -z "$wantTxz" ]; then
  echo "::error::embedded-postgres ${arch} pin is empty in the manifest — the provenance gate is a no-op (SUPPLY-003)" >&2
  exit 1
fi

mkdir -p "$workdir"
archWorkdir="$workdir/${arch}-${ver}"
rm -rf "$archWorkdir"
mkdir -p "$archWorkdir"
jar="$archWorkdir/embedded-postgres-${arch}-${ver}.jar"

echo ">> downloading PostgreSQL ${ver} (${arch}) binary: ${url}"
curl -fsSL "$url" -o "$jar"

gotJar="$(sha256sum "$jar" | awk '{print $1}')"
echo ">> sha256(jar ${arch} ${ver}) = ${gotJar}"
if [ "$gotJar" != "$wantJar" ]; then
  echo "::error::embedded-postgres ${arch} ${ver} JAR checksum mismatch — refusing to proceed" >&2
  echo "    expected ${wantJar}" >&2
  echo "    got      ${gotJar}" >&2
  exit 1
fi
echo ">> jar checksum verified against the committed manifest"

# Verify the inner .txz too — that is the artifact the runtime caches and checks.
( cd "$archWorkdir" && unzip -oq "$jar" )
innerTxz="$(find "$archWorkdir" -name '*.txz' -print | head -1)"
if [ -z "$innerTxz" ]; then
  echo "::error::could not find the inner .txz inside the jar for ${arch}" >&2
  exit 1
fi
gotTxz="$(sha256sum "$innerTxz" | awk '{print $1}')"
echo ">> sha256(.txz ${arch}) = ${gotTxz}"
if [ "$gotTxz" != "$wantTxz" ]; then
  echo "::error::embedded-postgres ${arch} ${ver} .txz checksum mismatch — the runtime pin would reject this binary" >&2
  echo "    expected ${wantTxz}" >&2
  echo "    got      ${gotTxz}" >&2
  exit 1
fi
echo ">> inner .txz checksum verified against the committed runtime pin"

echo ">> extracting for vulnerability scan"
( cd "$archWorkdir" && unzip -oq "$jar" )
# The jar wraps a postgres-<os>-<arch>.txz; unpack any we find so Trivy can scan
# the actual binaries and shared libraries.
find "$archWorkdir" -name '*.txz' -print0 | while IFS= read -r -d '' txz; do
  tar -xf "$txz" -C "$archWorkdir" 2>/dev/null || true
done

# The Trivy JSON report and compact receipt are CI artifacts. HIGH and non-fixable
# CRITICAL findings are recorded for audit. Fixable CRITICAL findings fail the gate:
# the pinned binary has an available patched upstream replacement, so continuing
# would turn the receipt into a known-bad green check.
TRIVY_IMAGE="aquasec/trivy@sha256:ab70a02200597efa04748f210f793936eb647cbcdb0ea69cc30b226d6f5a22c7"
case "$TRIVY_IMAGE" in
  *@sha256:*) ;;
  *)
    echo "::error::embedded-postgres fallback Trivy image must be pinned by digest, got ${TRIVY_IMAGE}" >&2
    exit 1
    ;;
esac
scan_args=(rootfs --severity HIGH,CRITICAL --ignore-unfixed --no-progress --format json --exit-code 0)
receipt_dir="${TRSTCTL_EMBEDDED_PG_SCAN_DIR:-$archWorkdir/scan-receipt}"
mkdir -p "$receipt_dir"
receipt_dir="$(cd "$receipt_dir" && pwd)"
trivy_report="$receipt_dir/trivy-rootfs.json"
trivy_version_out="$receipt_dir/trivy-version.txt"
receipt="$receipt_dir/embedded-postgres-trivy-receipt.json"
if command -v trivy >/dev/null 2>&1; then
  echo ">> trivy rootfs scan (local binary; receipt ${receipt_dir})"
  trivy "${scan_args[@]}" --output "$trivy_report" "$archWorkdir"
  trivy --version >"$trivy_version_out"
elif command -v docker >/dev/null 2>&1; then
  echo ">> trivy rootfs scan (pinned ${TRIVY_IMAGE}; receipt ${receipt_dir})"
  trivy_cache="$archWorkdir/trivy-cache"
  mkdir -p "$trivy_cache"
  docker run --rm -v "${trivy_cache}:/root/.cache/trivy" -v "${archWorkdir}:/scan:ro" -v "${receipt_dir}:/out" "$TRIVY_IMAGE" "${scan_args[@]}" --output /out/trivy-rootfs.json /scan
  docker run --rm -v "${trivy_cache}:/root/.cache/trivy:ro" "$TRIVY_IMAGE" --version >"$trivy_version_out"
else
  echo "::error::neither trivy nor docker present; cannot produce the embedded-postgres scanner receipt (SUPPLY-003)" >&2
  exit 1
fi
"$here/embedded-postgres-scan-receipt.sh" "$trivy_report" "$trivy_version_out" "$receipt" "$arch" "$ver" "$gotJar" "$gotTxz"
echo ">> wrote embedded-postgres Trivy receipt: $receipt"

echo ">> embedded-postgres supply-chain check complete"
