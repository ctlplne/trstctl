#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# A250: check the release archives on a clean runner the way an operator
# installs them. For the CLI and the host agent built by
# scripts/release/cli-assets.sh and agent-assets.sh: verify every archive
# against its SHA256SUMS, unpack this runner's archive into an empty directory,
# and run the binary to confirm it starts on this OS and reports the commit it
# was built from.
#
# Usage: scripts/ci/os-package-check.sh <cli-dir> <agent-dir> <platform>
#   platform is this runner's os_arch, e.g. linux_amd64 or darwin_arm64.
set -euo pipefail

CLI_DIR="${1:?usage: os-package-check.sh <cli-dir> <agent-dir> <platform>}"
AGENT_DIR="${2:?usage: os-package-check.sh <cli-dir> <agent-dir> <platform>}"
PLATFORM="${3:?usage: os-package-check.sh <cli-dir> <agent-dir> <platform>}"
COMMIT="$(git rev-parse HEAD)"

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$1"; else shasum -a 256 -c "$1"; fi
}

check() {
  local dir="$1" product="$2" binary="$3"
  local sums archive unpack out
  sums="$(ls "$dir"/"${product}"_*_SHA256SUMS)"
  echo ">> ${product}: every archive matches $(basename "$sums")"
  (cd "$dir" && sha256_check "$(basename "$sums")")
  archive="$(ls "$dir"/"${product}"_*_"${PLATFORM}".tar.gz)"
  unpack="$(mktemp -d)"
  tar -xzf "$archive" -C "$unpack"
  echo ">> ${product}: $(basename "$archive") runs here"
  out="$("$unpack/$binary" --version 2>&1)"
  echo "$out"
  case "$out" in
    *"$COMMIT"*) ;;
    *) echo "os-package-check: ${binary} --version does not report commit ${COMMIT}" >&2; exit 1 ;;
  esac
  rm -rf "$unpack"
}

check "$CLI_DIR" trstctl-cli trstctl-cli
check "$AGENT_DIR" trstctl-agent trstctl-agent
echo "os-package-check: the CLI and agent archives for ${PLATFORM} verify and run"
