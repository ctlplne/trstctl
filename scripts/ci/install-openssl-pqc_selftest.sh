#!/usr/bin/env bash
# Prove the PQC OpenSSL installer pins one exact upstream source and refuses
# unreviewed versions or ambiguous install destinations before downloading.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="$here/install-openssl-pqc.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

TRSTCTL_OPENSSL_DRY_RUN=1 "$installer" > "$tmp/pins"
grep -Fxq 'url=https://github.com/openssl/openssl/releases/download/openssl-3.5.7/openssl-3.5.7.tar.gz' "$tmp/pins"
grep -Fxq 'sha256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8' "$tmp/pins"

if TRSTCTL_OPENSSL_VERSION=3.5.8 TRSTCTL_OPENSSL_DRY_RUN=1 "$installer" \
  > "$tmp/unpinned.out" 2> "$tmp/unpinned.err"; then
  echo "expected unpinned OpenSSL version to fail" >&2
  exit 1
fi
grep -Fq 'OpenSSL 3.5.8 is not checksum-pinned' "$tmp/unpinned.err"

if TRSTCTL_OPENSSL_INSTALL_DIR=relative/path "$installer" \
  > "$tmp/relative.out" 2> "$tmp/relative.err"; then
  echo "expected relative OpenSSL install directory to fail" >&2
  exit 1
fi
grep -Fq 'must name an absolute, writable, run-owned directory' "$tmp/relative.err"

echo "install-openssl-pqc self-test: PASS"
