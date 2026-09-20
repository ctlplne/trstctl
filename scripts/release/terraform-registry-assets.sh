#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Package terraform-provider-trstctl in the exact release layout the Terraform
# Registry ingests: one zip per OS/arch whose only entry is the provider binary
# named terraform-provider-trstctl_v<VERSION>, the registry manifest declaring
# plugin protocol 6.0, a SHA256SUMS manifest over all of them, and a binary
# (not armored) detached GPG signature of that manifest. Unsigned output is
# refused: the Registry rejects it, so emitting it would only manufacture a
# false sense of shipped (CODE-005).
#
# Usage: terraform-registry-assets.sh <version-without-v> <outdir>
# Env:   TERRAFORM_GPG_PRIVATE_KEY   ASCII-armored private key (required)
#        TERRAFORM_GPG_PASSPHRASE    optional key passphrase
set -euo pipefail

VERSION="${1:?usage: terraform-registry-assets.sh <version-without-v> <outdir>}"
OUT="${2:?usage: terraform-registry-assets.sh <version-without-v> <outdir>}"

case "$VERSION" in
v*) echo "version must not carry the leading v: got $VERSION" >&2; exit 1 ;;
esac

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null || echo none)"
DATE="$(git show -s --format=%cI HEAD 2>/dev/null || echo unknown)"
LDFLAGS="-s -w -buildid= -X trstctl.com/trstctl/internal/buildinfo.version=v${VERSION} -X trstctl.com/trstctl/internal/buildinfo.commit=${COMMIT} -X trstctl.com/trstctl/internal/buildinfo.date=${DATE}"

for platform in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64; do
	os="${platform%%_*}"
	arch="${platform##*_}"
	bin="terraform-provider-trstctl_v${VERSION}"
	if [ "$os" = "windows" ]; then
		bin="${bin}.exe"
	fi
	workdir="$(mktemp -d)"
	echo ">> build ${platform}"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" \
		-o "${workdir}/${bin}" ./cmd/terraform-provider-trstctl
	# python3 zipfile keeps the packaging dependency surface at what the
	# runners and the sandbox already carry (no zip(1) requirement).
	python3 - "$workdir" "$bin" "${OUT}/terraform-provider-trstctl_${VERSION}_${platform}.zip" <<'PYEOF'
import os, sys, zipfile
workdir, name, dest = sys.argv[1], sys.argv[2], sys.argv[3]
src = os.path.join(workdir, name)
info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
info.external_attr = 0o755 << 16
with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
    with open(src, "rb") as fh:
        zf.writestr(info, fh.read())
PYEOF
	rm -rf "$workdir"
done

cat > "${OUT}/terraform-provider-trstctl_${VERSION}_manifest.json" <<EOF
{
  "version": 1,
  "metadata": {
    "protocol_versions": ["6.0"]
  }
}
EOF

(
	cd "$OUT"
	sha256sum \
		terraform-provider-trstctl_"${VERSION}"_*.zip \
		"terraform-provider-trstctl_${VERSION}_manifest.json" \
		> "terraform-provider-trstctl_${VERSION}_SHA256SUMS"
	sha256sum -c "terraform-provider-trstctl_${VERSION}_SHA256SUMS"
)

if [ -z "${TERRAFORM_GPG_PRIVATE_KEY:-}" ]; then
	echo "TERRAFORM_GPG_PRIVATE_KEY is not set; refusing to emit unsigned registry assets" >&2
	exit 1
fi

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
printf '%s' "$TERRAFORM_GPG_PRIVATE_KEY" | gpg --batch --quiet --import

sign_args=(--batch --yes --detach-sign)
if [ -n "${TERRAFORM_GPG_PASSPHRASE:-}" ]; then
	sign_args+=(--pinentry-mode loopback --passphrase "$TERRAFORM_GPG_PASSPHRASE")
fi
gpg "${sign_args[@]}" \
	--output "${OUT}/terraform-provider-trstctl_${VERSION}_SHA256SUMS.sig" \
	"${OUT}/terraform-provider-trstctl_${VERSION}_SHA256SUMS"
gpg --batch --verify \
	"${OUT}/terraform-provider-trstctl_${VERSION}_SHA256SUMS.sig" \
	"${OUT}/terraform-provider-trstctl_${VERSION}_SHA256SUMS"

echo "registry assets ready in ${OUT}:"
ls -1 "$OUT"
