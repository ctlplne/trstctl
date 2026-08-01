#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# npm ci is intentionally destructive. Reuse only a tree produced by this
# script for the exact current lock digest. CI and exact-tip/full-clean callers
# always reinstall by setting CI=true or TRSTCTL_WEB_CLEAN_INSTALL=1.
set -euo pipefail

web_dir="${1:-web}"
lock_file="${web_dir}/package-lock.json"
modules_dir="${web_dir}/node_modules"
marker="${modules_dir}/.trstctl-package-lock.sha256"

[[ -f "$lock_file" ]] || { echo "missing npm lockfile: $lock_file" >&2; exit 2; }

lock_digest() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$lock_file" | awk '{print $1}'
	else
		shasum -a 256 "$lock_file" | awk '{print $1}'
	fi
}

digest="$(lock_digest)"
force_clean=false
if [[ "${TRSTCTL_WEB_CLEAN_INSTALL:-}" == "1" || "${CI:-}" == "true" || "${CI:-}" == "1" ]]; then
	force_clean=true
fi

if [[ "$force_clean" == false && -d "$modules_dir" && -f "$marker" && "$(<"$marker")" == "$digest" ]]; then
	echo ">> npm dependencies current for package-lock.json; reuse node_modules"
	exit
fi

echo ">> npm ci (clean dependency tree from package-lock.json)"
npm --prefix "$web_dir" ci
digest="$(lock_digest)"
printf '%s\n' "$digest" >"$marker"
