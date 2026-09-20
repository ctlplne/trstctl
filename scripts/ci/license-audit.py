#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Dependency license audit for the SHIPPED binaries (D9).

What it does, in one breath: resolve every Go module actually linked into the
shipped commands, find each one's license file, classify it, and fail if a
strong-copyleft license (AGPL/GPL/SSPL and friends) is linked into a binary we
distribute under MPL-2.0 open core, or if a module ships no license text at
all.

Why it is not `grep -i gpl`: MPL-2.0's own Exhibit B names the GNU GPL as a
compatible secondary license, so a naive scan reports every MPL dependency as
GPL. This classifies by matching license *titles* in priority order and only
then looks for copyleft, which is why `github.com/go-sql-driver/mysql` (MPL-2.0)
is correctly reported as MPL rather than GPL.

Usage:
  scripts/ci/license-audit.py [--json receipt.json] [pkg ...]

With no packages it audits ./cmd/trstctl, ./cmd/trstctl-signer,
./cmd/trstctl-agent, ./cmd/trstctl-operator. Exit 1 on a finding.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

DEFAULT_PACKAGES = [
    "./cmd/trstctl",
    "./cmd/trstctl-signer",
    "./cmd/trstctl-agent",
    "./cmd/trstctl-operator",
]

LICENSE_FILENAMES = (
    "LICENSE", "LICENSE.md", "LICENSE.txt", "License.txt", "license.txt",
    "LICENCE", "LICENCE.txt", "COPYING", "COPYING.md",
    "LICENSE-APACHE-2.0.txt", "LICENSE-APACHE", "LICENSE-MIT", "LICENSE.BSD",
)

# Ordered: the first title that matches wins, so MPL's mention of the GPL in
# its secondary-license exhibit cannot be mistaken for a GPL grant.
LICENSE_TITLES = [
    ("MPL-2.0", r"Mozilla Public License,? Version 2\.0"),
    ("Apache-2.0", r"Apache License\s*\n?\s*Version 2\.0"),
    ("BSD-3-Clause", r"Redistribution and use in source and binary forms.*?"
                     r"name of .*?(contributors|copyright holder).*?endorse"),
    ("BSD-2-Clause", r"Redistribution and use in source and binary forms"),
    ("MIT", r"Permission is hereby granted, free of charge"),
    ("ISC", r"Permission to use, copy, modify, and(/or)? distribute this software"),
    ("Unlicense", r"This is free and unencumbered software released into the public domain"),
    # github.com/xi2/xz dedicates to the public domain in prose rather than
    # with a standard template; recognize the dedication itself.
    ("public-domain", r"have been put\s+into the public domain"),
    ("AGPL-3.0", r"GNU AFFERO GENERAL PUBLIC LICENSE"),
    ("GPL", r"GNU GENERAL PUBLIC LICENSE"),
    ("LGPL", r"GNU LESSER GENERAL PUBLIC LICENSE"),
    ("SSPL", r"Server Side Public License"),
    ("CDDL", r"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE"),
    ("EPL", r"Eclipse Public License"),
]

# Linking any of these into a distributed MPL-2.0 binary is the contamination
# diligence hunts for.
DENIED = {"AGPL-3.0", "GPL", "LGPL", "SSPL", "CDDL", "EPL"}

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VENDORED_EMBEDDED_POSTGRES = "trstctl.com/trstctl/third_party/embedded-postgres"


def linked_modules(packages: list[str]) -> dict[str, str]:
    out = subprocess.run(
        ["go", "list", "-deps", "-f",
         "{{if .Module}}{{.Module.Path}}\t{{.Module.Dir}}{{end}}", *packages],
        capture_output=True, text=True, check=True,
    )
    mods: dict[str, str] = {}
    for line in out.stdout.splitlines():
        if "\t" not in line:
            continue
        path, directory = line.split("\t", 1)
        if directory.strip():
            mods[path] = directory

    # Source copied into the root module has no separate .Module in `go list`,
    # but its upstream MIT license still ships in the binary and must not vanish
    # from the receipt merely because we removed the vulnerable upstream module
    # replacement. Only add it when the shipped dependency closure really links
    # the vendored package.
    imports = subprocess.run(
        ["go", "list", "-deps", "-f", "{{.ImportPath}}", *packages],
        capture_output=True, text=True, check=True,
    )
    if VENDORED_EMBEDDED_POSTGRES in imports.stdout.splitlines():
        manifest_path = os.path.join(
            REPO_ROOT, "deploy", "supply-chain", "embedded-postgres.json"
        )
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
        identity = f"{manifest['module']}@{manifest['moduleVersion']} (vendored source)"
        mods[identity] = os.path.join(REPO_ROOT, "third_party", "embedded-postgres")
    return mods


def license_file(directory: str) -> str | None:
    for name in LICENSE_FILENAMES:
        candidate = os.path.join(directory, name)
        if os.path.exists(candidate):
            return candidate
    return None


def classify(text: str) -> str:
    for name, pattern in LICENSE_TITLES:
        if re.search(pattern, text, re.I | re.S):
            return name
    return "UNKNOWN"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", dest="receipt")
    parser.add_argument("packages", nargs="*")
    args = parser.parse_args()
    packages = args.packages or DEFAULT_PACKAGES

    mods = linked_modules(packages)
    rows, denied, unlicensed = [], [], []
    for module, directory in sorted(mods.items()):
        if module == "trstctl.com/trstctl":
            continue
        path = license_file(directory)
        if path is None:
            unlicensed.append(module)
            rows.append({"module": module, "license": "MISSING", "file": None})
            continue
        with open(path, encoding="utf-8", errors="ignore") as handle:
            name = classify(handle.read())
        rows.append({"module": module, "license": name,
                     "file": os.path.basename(path)})
        if name in DENIED:
            denied.append(f"{module}: {name}")
        elif name == "UNKNOWN":
            unlicensed.append(f"{module}: unrecognized license text")

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["license"]] = counts.get(row["license"], 0) + 1
    print(f">> license audit: {len(rows)} modules linked into {' '.join(packages)}")
    for name, count in sorted(counts.items()):
        print(f"   {name}: {count}")

    if args.receipt:
        with open(args.receipt, "w", encoding="utf-8") as handle:
            json.dump({"packages": packages, "modules": rows, "counts": counts,
                       "denied": denied, "unlicensed": unlicensed},
                      handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f">> receipt: {args.receipt}")

    if denied:
        print("FAIL: copyleft license linked into a distributed binary:", file=sys.stderr)
        for item in denied:
            print(f"  {item}", file=sys.stderr)
    if unlicensed:
        print("FAIL: module ships no recognizable license text:", file=sys.stderr)
        for item in unlicensed:
            print(f"  {item}", file=sys.stderr)
    return 1 if denied or unlicensed else 0


if __name__ == "__main__":
    sys.exit(main())
