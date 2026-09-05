#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Build the standalone API client for the five supported desktop/CI targets.
# Every archive embeds the full source commit, and one checksum manifest binds
# the archives to a machine-readable release manifest. No credential or trust
# bundle is packaged: those stay explicit operator inputs at first connection.
set -euo pipefail

VERSION_INPUT="${1:?usage: cli-assets.sh <vX.Y.Z|candidate-name> <outdir>}"
OUT="${2:?usage: cli-assets.sh <vX.Y.Z|candidate-name> <outdir>}"
VERSION="${VERSION_INPUT#v}"

case "$VERSION" in
	"" | *[!A-Za-z0-9._-]*)
		echo "version must contain only letters, numbers, dot, underscore, or dash: ${VERSION_INPUT}" >&2
		exit 2
		;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COMMIT="${TRSTCTL_CLI_COMMIT:-$(git rev-parse HEAD)}"
case "$COMMIT" in
	*[!0-9a-f]* | "")
		echo "TRSTCTL_CLI_COMMIT must be the full lowercase hexadecimal source commit" >&2
		exit 2
		;;
esac
if [ "${#COMMIT}" -ne 40 ]; then
	echo "TRSTCTL_CLI_COMMIT must contain all 40 hexadecimal commit characters" >&2
	exit 2
fi

DATE="${TRSTCTL_CLI_DATE:-$(git show -s --format=%cI "$COMMIT")}"
PLATFORMS="${TRSTCTL_CLI_PLATFORMS:-linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64}"
LDFLAGS="-s -w -buildid= -X trstctl.com/trstctl/internal/buildinfo.version=${VERSION_INPUT} -X trstctl.com/trstctl/internal/buildinfo.commit=${COMMIT} -X trstctl.com/trstctl/internal/buildinfo.date=${DATE}"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

artifacts=()
for platform in $PLATFORMS; do
	case "$platform" in
		linux_amd64 | linux_arm64 | darwin_amd64 | darwin_arm64 | windows_amd64) ;;
		*) echo "unsupported CLI release platform: $platform" >&2; exit 2 ;;
	esac
	os="${platform%%_*}"
	arch="${platform##*_}"
	name="trstctl-cli"
	if [ "$os" = "windows" ]; then
		name="trstctl-cli.exe"
	fi
	stage="${WORK}/${platform}"
	mkdir -p "$stage"
	echo ">> build trstctl-cli ${platform} at ${COMMIT}"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" \
		-o "${stage}/${name}" ./cmd/trstctl-cli

	if [ "$os" = "windows" ]; then
		archive="trstctl-cli_${VERSION}_${platform}.zip"
		python3 - "$stage" "$name" "${OUT}/${archive}" <<'PYEOF'
import os, sys, zipfile
stage, name, dest = sys.argv[1:]
info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
info.external_attr = 0o755 << 16
with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
    with open(os.path.join(stage, name), "rb") as src:
        zf.writestr(info, src.read())
PYEOF
	else
		archive="trstctl-cli_${VERSION}_${platform}.tar.gz"
		python3 - "$stage" "$name" "${OUT}/${archive}" <<'PYEOF'
import gzip, os, sys, tarfile
stage, name, dest = sys.argv[1:]
src_path = os.path.join(stage, name)
with open(dest, "wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
            info = tf.gettarinfo(src_path, arcname=name)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755
            with open(src_path, "rb") as src:
                tf.addfile(info, src)
PYEOF
	fi
	artifacts+=("$archive")
done

manifest="trstctl-cli_${VERSION}_manifest.json"
python3 - "${OUT}/${manifest}" "$VERSION_INPUT" "$COMMIT" "$DATE" "${artifacts[@]}" <<'PYEOF'
import json, sys
dest, version, commit, built_at, *artifacts = sys.argv[1:]
payload = {
    "schema_version": 1,
    "product": "trstctl-cli",
    "version": version,
    "source_commit": commit,
    "source_commit_length": len(commit),
    "built_at": built_at,
    "artifacts": artifacts,
    "connection_security": {
        "tls_verification_required": True,
        "trust_bundle_packaged": False,
        "credential_packaged": False,
    },
}
with open(dest, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF

checksum_file="trstctl-cli_${VERSION}_SHA256SUMS"
(
	cd "$OUT"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${artifacts[@]}" "$manifest" > "$checksum_file"
		sha256sum -c "$checksum_file"
	else
		shasum -a 256 "${artifacts[@]}" "$manifest" > "$checksum_file"
		shasum -a 256 -c "$checksum_file"
	fi
)

echo "trstctl-cli exact-candidate assets ready in ${OUT}"
