#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Checks the cross-compiled Windows signing adapter from its `objdump -p`
# listing (make signing-ksp-windows writes it): the DLL must export
# GetKeyStorageInterface, the entry point CNG calls after loading a key storage
# provider, and import only KERNEL32.dll and msvcrt.dll, which every Windows
# release ships, so it loads with nothing else installed.
#
# usage: check-ksp-dll.sh bin/trstctl-ksp.objdump
set -euo pipefail

listing="${1:?usage: check-ksp-dll.sh <objdump -p listing of trstctl-ksp.dll>}"
if ! grep -Eq '^[[:space:]]+\[ *[0-9]+\] GetKeyStorageInterface$' "$listing"; then
  echo "trstctl-ksp.dll does not export GetKeyStorageInterface" >&2
  exit 1
fi
imports="$(awk '/DLL Name:/ {print $3}' "$listing" | sort -u | paste -sd ' ' -)"
if [ "$imports" != "KERNEL32.dll msvcrt.dll" ]; then
  echo "trstctl-ksp.dll imports ${imports:-nothing}; want only KERNEL32.dll and msvcrt.dll" >&2
  exit 1
fi
echo "trstctl-ksp.dll exports GetKeyStorageInterface and imports only KERNEL32.dll and msvcrt.dll"
