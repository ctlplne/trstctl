#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# make trust-audit: build every image, collect what Go loads as system roots from each (Go's Linux rule, applied
# inside the exported image filesystem), and compare that with Mozilla's websites trust list and the shipped
# distrust list. The network is used here only (CCADB), never in ordinary builds or pull requests.
# Usage: scripts/ci/trust-audit.sh [--no-build] [--mozilla FILE] [--tag TAG]
#   --no-build   audit images already tagged TAG (default tag: trust-audit)
#   --mozilla    use a saved copy of the Mozilla list instead of downloading it
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
build=1; mozilla=""; tag="trust-audit"
while [ $# -gt 0 ]; do
  case "$1" in
    --no-build) build=0 ;;
    --mozilla) mozilla="$2"; shift ;;
    --tag) tag="$2"; shift ;;
    *) echo "trust-audit: unknown flag $1" >&2; exit 2 ;;
  esac
  shift
done
out="${TRUST_AUDIT_OUT:-$root/.sandbox-build/trust-audit}"; rm -rf "$out"; mkdir -p "$out"
if [ -z "$mozilla" ]; then
  mozilla="$out/mozilla-websites.pem"
  curl -fsSL --retry 3 -o "$mozilla" 'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites'
fi
grep -q 'BEGIN CERTIFICATE' "$mozilla" || { echo "trust-audit: the Mozilla list is empty" >&2; exit 1; }
go build -o "$out/trstctl-trustbundle" ./cmd/trstctl-trustbundle
# The HSM images take their bases as arguments; build them on the digests the release pins.
go_version="$(awk '/^toolchain / {sub(/^go/, "", $2); print $2}' go.mod)"
go_key="GOLANG_$(echo "$go_version" | tr '.' '_')_BOOKWORM"
pinned() { sed -n "s/^$1=//p" .github/base-image-digests.env | head -1; }
go_digest="$(pinned "$go_key")"; debian_digest="$(pinned DEBIAN_BOOKWORM_SLIM)"
[ -n "$go_digest" ] && [ -n "$debian_digest" ] || { echo "trust-audit: no pinned digest for $go_key or DEBIAN_BOOKWORM_SLIM in .github/base-image-digests.env" >&2; exit 1; }
hsm_args="--build-arg BUILD_IMAGE=golang:${go_version}-bookworm@${go_digest} --build-arg BASE_IMAGE=debian:bookworm-slim@${debian_digest}"
images=(
  "trstctl:$tag|deploy/docker/Dockerfile|--target release"
  "trstctl-signer-hsm:$tag|deploy/docker/Dockerfile.signer-hsm|$hsm_args"
  "trstctl-agent-pkcs11:$tag|deploy/docker/Dockerfile.agent-pkcs11|$hsm_args"
  "trstctl-nats-hardened:$tag|deploy/docker/Dockerfile.nats|"
  "trstctl-node-hardened:$tag|deploy/docker/Dockerfile.node|"
  "trstctl-postgres-hardened:$tag|deploy/docker/Dockerfile.postgres|"
  "trstctl-demo-seed:$tag|deploy/demo/Dockerfile.seed|"
  "trstctl-frontdoors:$tag|deploy/demo/lab/frontdoors/Dockerfile|--build-arg TRSTCTL_IMAGE=trstctl:$tag"
)
failed=0
for spec in "${images[@]}"; do
  image="${spec%%|*}"; rest="${spec#*|}"; dockerfile="${rest%%|*}"; args="${rest#*|}"; name="${image%%:*}"
  if [ "$build" = 1 ]; then
    # shellcheck disable=SC2086
    docker build -f "$dockerfile" $args -t "$image" . >"$out/build-$name.log" 2>&1 || { echo "trust-audit: build failed for $image (see $out/build-$name.log)" >&2; failed=1; continue; }
  fi
  fsdir="$out/fs/$name"; rm -rf "$fsdir"; mkdir -p "$fsdir"
  # The whole image filesystem, so a symlink in the trust store resolves to whatever it names inside the image.
  # The container is created, never started; the command only satisfies images without one.
  cid=$(docker create "$image" /trust-audit-never-started)
  docker export "$cid" | tar -x -C "$fsdir" --exclude 'dev/*' 2>/dev/null || true
  envargs=()
  while IFS= read -r kv; do [ -n "$kv" ] && envargs+=(-env "$kv"); done < <(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | grep -E '^SSL_CERT_(FILE|DIR)=' || true)
  docker rm -f "$cid" >/dev/null
  if ! "$out/trstctl-trustbundle" audit -root "$fsdir" -mozilla "$mozilla" -label "$image" -report "$out/$name.json" "${envargs[@]+"${envargs[@]}"}"; then failed=1; fi
  rm -rf "$fsdir"
done
if [ "$failed" = 0 ]; then
  echo "trust-audit: PASS (every image loads only Mozilla's websites roots and nothing on the distrust list)"
else
  echo "trust-audit: FAIL" >&2; exit 1
fi
