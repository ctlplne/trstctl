#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v docker >/dev/null 2>&1 || {
  echo "docker-context-audit: docker is required" >&2
  exit 1
}
command -v rg >/dev/null 2>&1 || {
  echo "docker-context-audit: rg is required" >&2
  exit 1
}

scratch="$(mktemp -d "${TMPDIR:-/tmp}/trstctl-docker-context.XXXXXX")"
canary_dir="$(mktemp -d "$root/.sandbox-build/docker-context-audit.XXXXXX")"
canary="TRSTCTL_DOCKER_CONTEXT_SECRET_CANARY_${RANDOM}_${RANDOM}_$$"
cleanup() {
  rm -rf "$scratch" "$canary_dir"
}
trap cleanup EXIT

printf '%s\n' "$canary" >"$canary_dir/operator-secret.tmp"

docker build \
  --file "$root/deploy/docker/Dockerfile" \
  --target context-audit \
  --output "type=local,dest=$scratch/export" \
  "$root" >/dev/null

if [ -e "$scratch/export/context/.sandbox-build" ]; then
  echo "docker-context-audit: ignored .sandbox-build entered the filtered context" >&2
  exit 1
fi
if rg -a -q --fixed-strings "$canary" "$scratch/export"; then
  echo "docker-context-audit: planted secret canary entered a Docker stage" >&2
  exit 1
fi

context_kib="$(du -sk "$scratch/export/context" | awk '{print $1}')"
max_context_kib=$((64 * 1024))
if [ "$context_kib" -gt "$max_context_kib" ]; then
  echo "docker-context-audit: filtered context is ${context_kib} KiB; limit is ${max_context_kib} KiB" >&2
  exit 1
fi

echo "docker-context-audit: PASS (${context_kib} KiB <= ${max_context_kib} KiB; planted secret excluded)"
