#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Build a trstctl air-gap install bundle.

Required:
  VERSION=vX.Y.Z scripts/airgap-bundle.sh

Optional:
  IMAGE=ghcr.io/ctlplne/trstctl:vX.Y.Z
  OUT_DIR=dist/airgap
  TRSTCTL_AIRGAP_SKIP_IMAGES=1   # test-only: write the bundle without docker save

The bundle contains the Helm chart, values-airgap.yaml, customer docs, checksums,
and a docker-save tarball of the release image unless explicitly skipped.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:-${1:-}}"
if [[ -z "$version" ]]; then
  usage
  exit 2
fi

image="${IMAGE:-ghcr.io/ctlplne/trstctl:${version}}"
out_root="${OUT_DIR:-${repo_root}/dist/airgap}"
bundle_name="trstctl-${version#v}-airgap"
bundle_dir="${out_root}/${bundle_name}"
archive="${out_root}/${bundle_name}.tar.gz"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

require shasum
require tar

rm -rf "$bundle_dir" "$archive"
mkdir -p "$bundle_dir"/{charts,docs,images,manifests}

cp -R "$repo_root/deploy/helm/trstctl" "$bundle_dir/charts/trstctl"
cp "$repo_root/deploy/helm/trstctl/values-airgap.yaml" "$bundle_dir/manifests/values-airgap.yaml"
cp "$repo_root/docs/airgap.md" "$bundle_dir/docs/airgap.md"
cp "$repo_root/docs/install.md" "$bundle_dir/docs/install.md"
cp "$repo_root/docs/configuration.md" "$bundle_dir/docs/configuration.md"
cp "$repo_root/docs/telemetry.md" "$bundle_dir/docs/telemetry.md"

if command -v helm >/dev/null 2>&1; then
  helm package "$repo_root/deploy/helm/trstctl" --destination "$bundle_dir/charts" >/dev/null
else
  tar -C "$repo_root/deploy/helm" -czf "$bundle_dir/charts/trstctl-chart.tar.gz" trstctl
fi

if [[ "${TRSTCTL_AIRGAP_SKIP_IMAGES:-0}" == "1" ]]; then
  printf 'image save skipped by TRSTCTL_AIRGAP_SKIP_IMAGES=1; do not use this bundle for production install\n' > "$bundle_dir/images/README.txt"
else
  require docker
  docker pull "$image"
  docker save "$image" -o "$bundle_dir/images/trstctl-image.tar"
  printf '%s\n' "$image" > "$bundle_dir/images/trstctl-image.ref"
fi

cat > "$bundle_dir/MANIFEST.txt" <<EOF
trstctl air-gap bundle
version: ${version}
image: ${image}
created_by: scripts/airgap-bundle.sh

install entrypoints:
- docs/airgap.md
- charts/trstctl
- manifests/values-airgap.yaml
- images/trstctl-image.tar
EOF

(
  cd "$bundle_dir"
  find . -type f ! -name CHECKSUMS.txt -print | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
  done > CHECKSUMS.txt
)

tar -C "$out_root" -czf "$archive" "$bundle_name"
shasum -a 256 "$archive" > "${archive}.sha256"

echo "bundle: $archive"
echo "checksum: ${archive}.sha256"
