#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# TOOL-O1 lab: builds every stage that fetches pinned Alpine packages (deploy/supply-chain/
# alpine-packages.json) with ALPINE_MIRROR pointed at a local mirror kept by
# scripts/supply-chain/alpine-mirror.py, on a fresh docker-container builder with an empty cache
# (the locally cached moby/buildkit image), so every package comes from the mirror and no build
# names the Alpine CDN. Each package a build places must match a pinned digest, and the mirror
# must serve every pinned package. The mirror is filled from the CDN first (once; a filled one is
# kept). The builder is removed by its exact name at exit. Usage: alpine-mirror.sh [OUTDIR]
set -uo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT="${1:-$(mktemp -d "${TMPDIR:-/tmp}/trstctl-alpine-mirror.XXXXXX")}"
M="$OUT/mirror"; mkdir -p "$OUT"
cd "$REPO" || exit 2
echo ">> mirror: fetch from the Alpine CDN (once), then verify"
python3 -I scripts/supply-chain/alpine-mirror.py fetch "$M" || exit 1
python3 -I scripts/supply-chain/alpine-mirror.py verify "$M" || exit 1
python3 -I scripts/supply-chain/alpine-mirror.py serve "$M" --port 0 > "$OUT/serve.log" 2>&1 &
pid=$!
# A fresh builder with an empty cache (the locally cached moby/buildkit image), so every pinned
# package must come from the mirror; removed by its exact name at exit.
builder="trstctl-toolo1-$$"
trap 'kill "$pid" 2>/dev/null; docker buildx rm "$builder" >/dev/null 2>&1' EXIT
docker buildx create --name "$builder" --driver docker-container --bootstrap >/dev/null || { echo "FAIL: builder"; exit 1; }
for _ in $(seq 1 50); do grep -q '^serving ' "$OUT/serve.log" && break; sleep 0.1; done
port=$(sed -n 's#^serving .* on http://127.0.0.1:\([0-9]*\)$#\1#p' "$OUT/serve.log" | head -1)
[ -n "$port" ] || { echo "FAIL: mirror did not start"; cat "$OUT/serve.log"; exit 1; }
echo ">> mirror on 127.0.0.1:$port; builds use ALPINE_MIRROR=http://host.docker.internal:$port"
status=0
while read -r df stage; do
  dest="$OUT/out/$(basename "$df")-$stage"
  rm -rf "$dest"
  # The cgo images name their build and base images by argument (the Makefile's local
  # defaults); a trust-source target builds neither, so neither is pulled.
  extra=()
  case "$df" in *agent-pkcs11|*signer-hsm) extra=(--build-arg "BUILD_IMAGE=golang:$(awk '/^toolchain / {sub(/^go/, "", $2); print $2}' go.mod)-bookworm" --build-arg BASE_IMAGE=debian:bookworm-slim);; esac
  if docker buildx build --builder "$builder" --no-cache --progress=plain -f "$df" --target "$stage" --build-arg "ALPINE_MIRROR=http://host.docker.internal:$port" \
       ${extra[@]+"${extra[@]}"} -o "type=local,dest=$dest" . > "$OUT/build-$(basename "$df")-$stage.log" 2>&1; then
    n=$(find "$dest" -name '*.apk' | wc -l | tr -d ' ')
    cdn=$(grep -c 'dl-cdn.alpinelinux.org' "$OUT/build-$(basename "$df")-$stage.log")
    echo "  built $df --target $stage: $n packages, CDN mentions in the build log: $cdn"
    [ "$cdn" = 0 ] || status=1
  else
    echo "  FAIL $df --target $stage"; tail -5 "$OUT/build-$(basename "$df")-$stage.log"; status=1
  fi
done <<'LIST'
deploy/docker/Dockerfile trust-source
deploy/docker/Dockerfile.node trust-source
deploy/docker/Dockerfile.node patches
deploy/docker/Dockerfile.nats trust-source
deploy/docker/Dockerfile.nats patches
deploy/docker/Dockerfile.postgres trust-source
deploy/docker/Dockerfile.postgres patches
deploy/docker/Dockerfile.agent-pkcs11 trust-source
deploy/docker/Dockerfile.signer-hsm trust-source
deploy/demo/Dockerfile.seed trust-source
deploy/demo/Dockerfile.seed runtime-packages
LIST
echo ">> every package a build placed matches a pinned digest"
python3 - "$OUT/out" deploy/supply-chain/alpine-packages.json <<'PY'
import hashlib, json, sys, pathlib
pins = {p["sha256"] for p in json.load(open(sys.argv[2]))["packages"]}
files = list(pathlib.Path(sys.argv[1]).rglob("*.apk"))
bad = [str(f) for f in files if hashlib.sha256(f.read_bytes()).hexdigest() not in pins]
print(f"  {len(files)} placed packages, {len(bad)} not pinned")
sys.exit(1 if bad or not files else 0)
PY
[ $? = 0 ] || status=1
# The fresh builder fetches each pinned digest once and reuses it, so the mirror sees one request per package.
served=$(grep -o '"GET /v3.24/[^ ]* HTTP/1.1" 200' "$OUT/serve.log" | sort -u | wc -l | tr -d ' ')
pinned=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["packages"]))' deploy/supply-chain/alpine-packages.json)
echo ">> the mirror served $served of the $pinned pinned packages (200)"
[ "$served" = "$pinned" ] || status=1
echo ">> toolo1 lab exit=$status"
exit $status
