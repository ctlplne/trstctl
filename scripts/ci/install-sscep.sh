#!/usr/bin/env bash
set -euo pipefail

prefix="${1:?usage: install-sscep.sh <install-prefix>}"

version="0.10.0"
archive_sha256="489cc8e093986776eb3f15082bf766778f707176f3cd604bf0ef1008da06b8e5"
url="https://github.com/certnanny/sscep/archive/refs/tags/v${version}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

archive="${tmp}/sscep-v${version}.tar.gz"
curl -fsSL "${url}" -o "${archive}"
printf '%s  %s\n' "${archive_sha256}" "${archive}" | sha256sum -c -
tar -xzf "${archive}" -C "${tmp}"

cmake -S "${tmp}/sscep-${version}" -B "${tmp}/build" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
	-DCMAKE_INSTALL_PREFIX="${prefix}" \
	-DENABLE_ENGINES=OFF
cmake --build "${tmp}/build" --parallel 2
cmake --install "${tmp}/build"

"${prefix}/bin/sscep" >/dev/null 2>&1 || true
