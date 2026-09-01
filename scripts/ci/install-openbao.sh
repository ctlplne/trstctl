#!/usr/bin/env bash
# Install the exact stock OpenBao CLI used by the Vault compatibility gate.
# Release assets use Go-style architecture names only for arm64; x86_64 keeps
# its native name. Every supported archive is checksum-pinned so a moved or
# corrupt upstream asset fails closed before extraction.
set -euo pipefail

version="${OPENBAO_VERSION:-2.0.0}"
install_dir="${TRSTCTL_OPENBAO_INSTALL_DIR:-}"
kernel="${TRSTCTL_OPENBAO_UNAME_S:-$(uname -s)}"
machine="${TRSTCTL_OPENBAO_UNAME_M:-$(uname -m)}"

if [[ "$version" != "2.0.0" ]]; then
  echo "::error::OpenBao ${version} is not checksum-pinned by scripts/ci/install-openbao.sh" >&2
  exit 1
fi

case "${kernel}/${machine}" in
  Linux/x86_64)
    asset="bao_${version}_Linux_x86_64.tar.gz"
    sha256="0c49fd54d133cf95bd4d916a4a6b8f1583d3293f31880371f7a4e1412234fec6"
    ;;
  Linux/aarch64|Linux/arm64)
    asset="bao_${version}_Linux_arm64.tar.gz"
    sha256="fa0efa60a04a75966f11c05cd21c572a86da5932de88f44c50788f889e887c3f"
    ;;
  *)
    echo "::error::unsupported OpenBao CI platform ${kernel}/${machine}" >&2
    exit 1
    ;;
esac

url="https://github.com/openbao/openbao/releases/download/v${version}/${asset}"
if [[ "${TRSTCTL_OPENBAO_DRY_RUN:-0}" == "1" ]]; then
  printf 'url=%s\nsha256=%s\n' "$url" "$sha256"
  exit 0
fi

if [[ -z "$install_dir" ]]; then
  echo "::error::TRSTCTL_OPENBAO_INSTALL_DIR must name a writable, run-owned directory" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
archive="$tmp/$asset"
mkdir -p "$install_dir"

curl -fsSL --proto '=https' --tlsv1.2 "$url" -o "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum -c -
tar -xzf "$archive" -C "$tmp" bao
install -m 0755 "$tmp/bao" "$install_dir/bao"
ln -sf bao "$install_dir/vault"

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
fi
"$install_dir/vault" version
