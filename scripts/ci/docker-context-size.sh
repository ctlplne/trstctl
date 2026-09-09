#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
umask 077

if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
  echo "docker-context-audit: expected one exported context directory" >&2
  exit 1
fi

# Count every exported path in an uncompressed portable archive. du measures
# host allocation blocks: the same source can exceed its ceiling on APFS while
# fitting on ext4. A plain ustar stream includes file data, names, headers and
# padding, and expands sparse files instead of undercounting their contents.
# ustar permits a 100-byte final name, a 155-byte directory prefix, and a
# 100-byte symlink target. Unsupported paths or metadata fail through pipefail.
# Ambient tar options must not inject compression, sparse encoding or exclusions.
diagnostics="$(mktemp "${TMPDIR:-/tmp}/trstctl-context-tar.XXXXXX")"
trap 'rm -f "$diagnostics"' EXIT
if ! context_bytes="$(TAR_OPTIONS= TAR_READER_OPTIONS= TAR_WRITER_OPTIONS= COPYFILE_DISABLE=1 tar --format=ustar -cf - -C "$1" . 2>"$diagnostics" | wc -c | tr -d '[:space:]')"; then
  cat "$diagnostics" >&2
  echo "docker-context-audit: context archive did not complete" >&2
  exit 1
fi
# Some bsdtar versions emit an unrepresentable-path diagnostic but exit zero.
# Such a stream omitted an entry and cannot establish a complete byte count.
if [ -s "$diagnostics" ]; then
  cat "$diagnostics" >&2
  echo "docker-context-audit: context archive reported an incomplete entry" >&2
  exit 1
fi
case "$context_bytes" in
  ''|*[!0-9]*) echo "docker-context-audit: invalid archive byte count" >&2; exit 1 ;;
esac
max_context_kib=$((64 * 1024))
max_context_bytes=$((max_context_kib * 1024))
if [ "$context_bytes" -gt "$max_context_bytes" ]; then
  echo "docker-context-audit: filtered context archive is ${context_bytes} bytes; limit is ${max_context_bytes} bytes" >&2
  exit 1
fi
printf '%s\n' "$(((context_bytes + 1023) / 1024))"
