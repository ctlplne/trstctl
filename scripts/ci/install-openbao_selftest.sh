#!/usr/bin/env bash
# Prove the installer maps runner architectures to the real release asset names,
# pins both archives, and rejects unsupported platforms before any download.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="$here/install-openbao.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

TRSTCTL_OPENBAO_DRY_RUN=1 TRSTCTL_OPENBAO_UNAME_S=Linux TRSTCTL_OPENBAO_UNAME_M=x86_64 \
  "$installer" > "$tmp/x86"
grep -Fxq 'url=https://github.com/openbao/openbao/releases/download/v2.0.0/bao_2.0.0_Linux_x86_64.tar.gz' "$tmp/x86"
grep -Fxq 'sha256=0c49fd54d133cf95bd4d916a4a6b8f1583d3293f31880371f7a4e1412234fec6' "$tmp/x86"

TRSTCTL_OPENBAO_DRY_RUN=1 TRSTCTL_OPENBAO_UNAME_S=Linux TRSTCTL_OPENBAO_UNAME_M=aarch64 \
  "$installer" > "$tmp/arm64"
grep -Fxq 'url=https://github.com/openbao/openbao/releases/download/v2.0.0/bao_2.0.0_Linux_arm64.tar.gz' "$tmp/arm64"
grep -Fxq 'sha256=fa0efa60a04a75966f11c05cd21c572a86da5932de88f44c50788f889e887c3f' "$tmp/arm64"

if TRSTCTL_OPENBAO_DRY_RUN=1 TRSTCTL_OPENBAO_UNAME_S=Plan9 TRSTCTL_OPENBAO_UNAME_M=mips \
  "$installer" > "$tmp/unsupported.out" 2> "$tmp/unsupported.err"; then
  echo "expected unsupported OpenBao platform to fail" >&2
  exit 1
fi
grep -Fq 'unsupported OpenBao CI platform Plan9/mips' "$tmp/unsupported.err"

echo "install-openbao self-test: PASS"
