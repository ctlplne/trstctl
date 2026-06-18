#!/usr/bin/env bash
set -euo pipefail

prefix="${1:?usage: install-libest.sh <install-prefix>}"

# cisco/libest commit a464ba8, after the r3.2.0 release. The archive is
# checksum-pinned so the CI reference client cannot float under us.
commit="a464ba8a66717419ba71d289ef82c7b2315b2006"
archive_sha256="2e5c46610f6a3c12c1916c8a84de77421a88c9722e776e862a716f4a48220f2a"
url="https://github.com/cisco/libest/archive/${commit}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

archive="${tmp}/libest-${commit}.tar.gz"
src="${tmp}/src"
mkdir -p "${src}"

curl -fsSL "${url}" -o "${archive}"
if command -v sha256sum >/dev/null 2>&1; then
	printf '%s  %s\n' "${archive_sha256}" "${archive}" | sha256sum -c -
else
	printf '%s  %s\n' "${archive_sha256}" "${archive}" | shasum -a 256 -c -
fi
tar -xzf "${archive}" -C "${src}" --strip-components=1

# libest predates OpenSSL 3 and newer duplicate-symbol defaults. These rewrites
# are deliberately tiny and only affect the CI-built reference client:
# - OpenSSL 3 removed FIPS_mode/FIPS_mode_set; this conformance client never uses
#   the deprecated -f FIPS option, so make those checks inert.
# - The example client utility duplicates an OpenSSL error helper that the linked
#   libest client library already exports; rename only the example helper.
perl -0pi -e 's/FIPS_mode\(\)/0/g; s/FIPS_mode_set\(1\)/0/g' \
	"${src}/src/est/est_client.c" \
	"${src}/example/client/estclient.c"
perl -0pi -e 's/\bossl_dump_ssl_errors\b/example_ossl_dump_ssl_errors/g' \
	"${src}/example/util/utils.c" \
	"${src}/example/util/utils.h"

configure_args=(
	--enable-client-only
	--disable-shared
	--disable-safec
	--prefix="${prefix}"
)
if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
	configure_args+=(--with-ssl-dir="${OPENSSL_ROOT_DIR}")
elif [[ -d /opt/homebrew/opt/openssl@3 ]]; then
	configure_args+=(--with-ssl-dir=/opt/homebrew/opt/openssl@3)
elif [[ -d /opt/homebrew/opt/openssl ]]; then
	configure_args+=(--with-ssl-dir=/opt/homebrew/opt/openssl)
elif [[ -d /usr/local/opt/openssl@3 ]]; then
	configure_args+=(--with-ssl-dir=/usr/local/opt/openssl@3)
fi

(
	cd "${src}"
	CFLAGS="${CFLAGS:-} -fcommon" ./configure "${configure_args[@]}"
	make -j "${MAKE_JOBS:-2}"
	make install
)

test -x "${prefix}/bin/estclient"
"${prefix}/bin/estclient" -? >/dev/null 2>&1 || true
