#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Compiles the host TLS session observer's BPF program (X5,
# internal/agent/sessionobserve/bpf/sessionobserve.bpf.c) for x86-64 and arm64
# with Debian bookworm's clang, in a pinned container, and writes the objects
# the agent embeds beside the source. The objects are committed, so building
# the agent needs no clang; rerun this after changing the program, then
# commit the objects and sessionobserve.bpf.c.sha256 (the source they were
# built from, checked by TestProbeObjectsMatchTheirSourceX5).
# `make sessionobserve-bpf` runs it.
set -euo pipefail

image="${TRSTCTL_BPF_BUILD_IMAGE:-debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3}"
root="$(cd "$(dirname "$0")/.." && pwd)"
dir=internal/agent/sessionobserve/bpf

docker run --rm -v "$root/$dir:/src" -w /src "$image" bash -ec '
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends clang llvm >/dev/null
dpkg-query -W clang llvm
for arch in x86 arm64; do
  clang -O2 -g -Wall -Werror -target bpfel -D__TARGET_ARCH_$arch -c sessionobserve.bpf.c -o sessionobserve_${arch}_bpfel.o
  llvm-strip -g sessionobserve_${arch}_bpfel.o
done
sha256sum sessionobserve.bpf.c | cut -d" " -f1 > sessionobserve.bpf.c.sha256
chown '"$(id -u):$(id -g)"' sessionobserve_*_bpfel.o sessionobserve.bpf.c.sha256
'
ls -l "$root/$dir"/sessionobserve_*_bpfel.o
