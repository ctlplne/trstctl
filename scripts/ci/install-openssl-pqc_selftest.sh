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

# A cached install directory: accepted only with TRSTCTL_OPENSSL_ACCEPT_CACHED=1,
# this script's marker for the pinned source, and a binary reporting the pinned
# version with ML-DSA-65. GITHUB_PATH/GITHUB_ENV are cleared so the fake binary
# never reaches the CI job that runs this self-test.
fake_install() {
  local dir="$1" reported="$2" marker="$3"
  mkdir -p "$dir/bin"
  cat > "$dir/bin/openssl" <<FAKE
#!/usr/bin/env bash
case "\$1" in
  version) echo "OpenSSL $reported 1 Jul 2026 (Library: OpenSSL $reported 1 Jul 2026)" ;;
  list) echo "  { 2.16.840.1.101.3.4.3.18, id-ml-dsa-65, ML-DSA-65, MLDSA65 } @ default" ;;
esac
FAKE
  chmod +x "$dir/bin/openssl"
  printf '%s\n' "$marker" > "$dir/.trstctl-openssl-source"
}
cached() { env -u GITHUB_PATH -u GITHUB_ENV TRSTCTL_OPENSSL_INSTALL_DIR="$1" "${@:2}" "$installer"; }
pinned_marker='version=3.5.7 sha256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8'

fake_install "$tmp/good" 3.5.7 "$pinned_marker"
cached "$tmp/good" TRSTCTL_OPENSSL_ACCEPT_CACHED=1 > "$tmp/good.out" 2>&1
grep -Fq 'using the cached build of checksum-pinned OpenSSL 3.5.7' "$tmp/good.out"
grep -Fq 'OpenSSL 3.5.7 ' "$tmp/good.out"

if cached "$tmp/good" > "$tmp/noflag.out" 2>&1; then
  echo "expected an existing install directory without TRSTCTL_OPENSSL_ACCEPT_CACHED=1 to fail" >&2
  exit 1
fi
grep -Fq 'refusing to replace existing OpenSSL install directory' "$tmp/noflag.out"

fake_install "$tmp/other-source" 3.5.7 'version=3.5.7 sha256=0000000000000000000000000000000000000000000000000000000000000000'
if cached "$tmp/other-source" TRSTCTL_OPENSSL_ACCEPT_CACHED=1 > "$tmp/other-source.out" 2>&1; then
  echo "expected a cached build from another source to fail" >&2
  exit 1
fi
grep -Fq 'refusing to replace existing OpenSSL install directory' "$tmp/other-source.out"

fake_install "$tmp/other-version" 3.5.6 "$pinned_marker"
if cached "$tmp/other-version" TRSTCTL_OPENSSL_ACCEPT_CACHED=1 > "$tmp/other-version.out" 2>&1; then
  echo "expected a cached binary reporting another version to fail" >&2
  exit 1
fi
grep -Fq 'refusing to replace existing OpenSSL install directory' "$tmp/other-version.out"

echo "install-openssl-pqc self-test: PASS"
