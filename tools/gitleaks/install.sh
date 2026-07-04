#!/usr/bin/env bash
set -euo pipefail

supported_version="v8.27.2"
version="${TRSTCTL_GITLEAKS_VERSION:-${supported_version}}"
if [[ "${version}" == "${version#v}" ]]; then
  version="v${version}"
fi
if [[ "${version}" != "${supported_version}" ]]; then
  echo "trstctl supports Gitleaks ${supported_version} for the served secrets scan bridge; got ${version}" >&2
  exit 2
fi

asset_version="${version#v}"
os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
machine="$(uname -m)"

platform=""
expected_sha=""
case "${os_name}/${machine}" in
  linux/x86_64 | linux/amd64)
    platform="linux_x64"
    expected_sha="141c3b2dede46d8b3a53b47116da756bd223decc0374797559a6b50ecba5590c"
    ;;
  linux/i386 | linux/i686)
    platform="linux_x32"
    expected_sha="22dfa64b4177879c192483fb01ae68b6bca777d0e6e952e6609fb35bc3985c82"
    ;;
  linux/aarch64 | linux/arm64)
    platform="linux_arm64"
    expected_sha="fd59a77b3d898ab14782264bf7a22db457871db56debc5d7ac3e30b64b379921"
    ;;
  linux/armv6l | linux/armv6)
    platform="linux_armv6"
    expected_sha="ccdc58d512d8430e08e20f95743c4688aa568bc7242d07c2ebe9633447a5c818"
    ;;
  linux/armv7l | linux/armv7)
    platform="linux_armv7"
    expected_sha="59227c8d32a4952cbaba3a4e5eecb98088bb8e2d799f9b3e3c6fd077e64dab3e"
    ;;
  darwin/x86_64 | darwin/amd64)
    platform="darwin_x64"
    expected_sha="aa79c412d76872d4917e6c53f784fd247576ded0d06c17262dc0299e4cc8e79f"
    ;;
  darwin/arm64 | darwin/aarch64)
    platform="darwin_arm64"
    expected_sha="ae969ca6b04c8621bae4dbb707cb4293264904c0e890901f0643c266d5e02bea"
    ;;
  *)
    echo "unsupported Gitleaks platform ${os_name}/${machine}" >&2
    exit 2
    ;;
esac

# Pinned release artifacts:
# gitleaks_8.27.2_linux_x64.tar.gz    141c3b2dede46d8b3a53b47116da756bd223decc0374797559a6b50ecba5590c
# gitleaks_8.27.2_linux_x32.tar.gz    22dfa64b4177879c192483fb01ae68b6bca777d0e6e952e6609fb35bc3985c82
# gitleaks_8.27.2_linux_arm64.tar.gz  fd59a77b3d898ab14782264bf7a22db457871db56debc5d7ac3e30b64b379921
# gitleaks_8.27.2_linux_armv6.tar.gz  ccdc58d512d8430e08e20f95743c4688aa568bc7242d07c2ebe9633447a5c818
# gitleaks_8.27.2_linux_armv7.tar.gz  59227c8d32a4952cbaba3a4e5eecb98088bb8e2d799f9b3e3c6fd077e64dab3e
# gitleaks_8.27.2_darwin_x64.tar.gz   aa79c412d76872d4917e6c53f784fd247576ded0d06c17262dc0299e4cc8e79f
# gitleaks_8.27.2_darwin_arm64.tar.gz ae969ca6b04c8621bae4dbb707cb4293264904c0e890901f0643c266d5e02bea

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gobin="${GOBIN:-${root}/tools/bin}"
mkdir -p "${gobin}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

asset="gitleaks_${asset_version}_${platform}.tar.gz"
base="https://github.com/gitleaks/gitleaks/releases/download/${version}"
archive="${tmpdir}/${asset}"
checksums="${tmpdir}/gitleaks_${asset_version}_checksums.txt"

curl -fsSL "${base}/${asset}" -o "${archive}"
curl -fsSL "${base}/gitleaks_${asset_version}_checksums.txt" -o "${checksums}"
grep -E "^${expected_sha}[[:space:]]+${asset}$" "${checksums}" >/dev/null || {
  echo "pinned checksum for ${asset} does not match upstream checksums manifest" >&2
  exit 1
}

checksum_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "sha256sum or shasum is required to verify ${asset}" >&2
    exit 2
  fi
}

verify_checksum() {
  actual_sha="$(checksum_file "${archive}")"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "checksum mismatch for ${asset}: got ${actual_sha}, want ${expected_sha}" >&2
    exit 1
  fi
}

verify_checksum
tar -xzf "${archive}" -C "${tmpdir}" gitleaks
install -m 0755 "${tmpdir}/gitleaks" "${gobin}/gitleaks"
echo "${gobin}/gitleaks"
