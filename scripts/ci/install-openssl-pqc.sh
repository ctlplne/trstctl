#!/usr/bin/env bash
# Build the exact OpenSSL client used by the ML-DSA interoperability gates.
# Ubuntu runner images still ship an older OpenSSL, so relying on `openssl` from
# the mutable host silently turns product compatibility into runner luck.
set -euo pipefail

readonly pinned_version="3.5.7"
readonly pinned_sha256="a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
version="${TRSTCTL_OPENSSL_VERSION:-$pinned_version}"
install_dir="${TRSTCTL_OPENSSL_INSTALL_DIR:-}"

if [[ "$version" != "$pinned_version" ]]; then
  echo "::error::OpenSSL ${version} is not checksum-pinned by scripts/ci/install-openssl-pqc.sh" >&2
  exit 1
fi

archive="openssl-${version}.tar.gz"
url="https://github.com/openssl/openssl/releases/download/openssl-${version}/${archive}"
if [[ "${TRSTCTL_OPENSSL_DRY_RUN:-0}" == "1" ]]; then
  printf 'url=%s\nsha256=%s\n' "$url" "$pinned_sha256"
  exit 0
fi

if [[ -z "$install_dir" || "$install_dir" != /* ]]; then
  echo "::error::TRSTCTL_OPENSSL_INSTALL_DIR must name an absolute, writable, run-owned directory" >&2
  exit 1
fi
if [[ -e "$install_dir" ]]; then
  echo "::error::refusing to replace existing OpenSSL install directory $install_dir" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --proto '=https' --tlsv1.2 "$url" -o "$tmp/$archive"
printf '%s  %s\n' "$pinned_sha256" "$tmp/$archive" | sha256sum -c -
tar -xzf "$tmp/$archive" -C "$tmp"

(
  cd "$tmp/openssl-${version}"
  ./config --prefix="$install_dir" --openssldir="$install_dir/ssl" no-shared no-tests
  make -j2
  make install_sw
)

if ! "$install_dir/bin/openssl" list -signature-algorithms | grep -q 'ML-DSA-65'; then
  echo "::error::checksum-pinned OpenSSL ${version} was built without ML-DSA-65" >&2
  exit 1
fi
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$install_dir/bin" >> "$GITHUB_PATH"
fi
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'OPENSSL_CONF=/dev/null\n' >> "$GITHUB_ENV"
fi
"$install_dir/bin/openssl" version
