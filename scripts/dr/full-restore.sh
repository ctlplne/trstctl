#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: full-restore.sh BACKUP_DIR" >&2
  exit 2
fi

TRSTCTL_BIN="${TRSTCTL_BIN:-trstctl}"
exec "$TRSTCTL_BIN" --full-restore-dir="$1"
