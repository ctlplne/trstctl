#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Build deterministic Linux and macOS host-agent archives from one exact commit.
# Windows uses the separately Authenticode-signed MSI release job.
set -euo pipefail

version_input="${1:?usage: agent-assets.sh <vX.Y.Z|candidate-name> <outdir>}"
out="${2:?usage: agent-assets.sh <vX.Y.Z|candidate-name> <outdir>}"
version="${version_input#v}"
case "$version" in
	"" | *[!A-Za-z0-9._-]*) echo "invalid release version" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
commit="$(git rev-parse HEAD)"
date="$(git show -s --format=%cI "$commit")"
ldflags="-s -w -buildid= -X trstctl.com/trstctl/internal/buildinfo.version=${version_input} -X trstctl.com/trstctl/internal/buildinfo.commit=${commit} -X trstctl.com/trstctl/internal/buildinfo.date=${date}"
platforms="${TRSTCTL_AGENT_PLATFORMS:-linux_amd64 linux_arm64 darwin_amd64 darwin_arm64}"

mkdir -p "$out"
out="$(cd "$out" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
artifacts=()
for platform in $platforms; do
	case "$platform" in
		linux_amd64 | linux_arm64 | darwin_amd64 | darwin_arm64) ;;
		*) echo "unsupported host-agent platform: $platform" >&2; exit 2 ;;
	esac
	os="${platform%%_*}"
	arch="${platform##*_}"
	stage="${work}/${platform}"
	mkdir -p "$stage"
	echo ">> build trstctl-agent ${platform} at ${commit}"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -trimpath -buildvcs=false -ldflags "$ldflags" \
		-o "${stage}/trstctl-agent" ./cmd/trstctl-agent
	archive="trstctl-agent_${version}_${platform}.tar.gz"
	python3 - "${stage}/trstctl-agent" "${out}/${archive}" <<'PYEOF'
import gzip, os, sys, tarfile
source, destination = sys.argv[1:]
with open(destination, "wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
            info = tf.gettarinfo(source, arcname="trstctl-agent")
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755
            with open(source, "rb") as binary:
                tf.addfile(info, binary)
PYEOF
	artifacts+=("$archive")
done

manifest="trstctl-agent_${version}_manifest.json"
python3 - "${out}/${manifest}" "$version_input" "$commit" "$date" "${artifacts[@]}" <<'PYEOF'
import json, sys
destination, version, commit, built_at, *artifacts = sys.argv[1:]
payload = {
    "schema_version": 1,
    "product": "trstctl-agent",
    "version": version,
    "source_commit": commit,
    "built_at": built_at,
    "artifacts": artifacts,
    "credential_packaged": False,
    "trust_bundle_packaged": False,
}
with open(destination, "w", encoding="utf-8") as output:
    json.dump(payload, output, indent=2, sort_keys=True)
    output.write("\n")
PYEOF

checksums="trstctl-agent_${version}_SHA256SUMS"
(
	cd "$out"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${artifacts[@]}" "$manifest" > "$checksums"
		sha256sum -c "$checksums"
	else
		shasum -a 256 "${artifacts[@]}" "$manifest" > "$checksums"
		shasum -a 256 -c "$checksums"
	fi
)
echo "trstctl-agent exact-candidate assets ready in ${out}"
