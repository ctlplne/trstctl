#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Dependency licence audit for the CONSOLE's shipped dependency tree.

The sibling `license-audit.py` answers this question for the Go binaries. It
cannot see the web tree at all, so until now a console dependency could carry
any licence at all and no gate would notice — `make sca` runs `npm audit`, which
is vulnerabilities, not licences. That gap matters most exactly when the loop is
inventing frontend features on its own.

What it does: read `web/package-lock.json` (lockfileVersion 3 carries a
`license` field and a `dev` marker per package), split the tree into what SHIPS
to users and what only builds it, and fail on a runtime dependency whose licence
would contaminate a BUSL-1.1 distribution or forbid the commercial motion this
product is built for.

Two classes of denial, for two different harms:
  * strong copyleft (AGPL/GPL/LGPL/SSPL/CDDL/EPL) contaminates distribution;
  * source-available (BUSL, Elastic, Confluent, RSAL, anything non-commercial)
    does not contaminate but restricts or taxes selling the software — and can
    be relicensed under us without warning, which is a supply-chain risk as much
    as a legal one.

Dev-only dependencies are reported but never fail the build: a build tool does
not ship, so its licence does not travel into the artifact.

Usage:
  scripts/ci/npm-license-audit.py [--lock web/package-lock.json]
                                  [--json receipt.json] [--strict-dev]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DENIED_PATTERNS = [
    (r"\bAGPL\b", "AGPL"),
    (r"(?<!L)\bGPL-?[0-9]", "GPL"),
    (r"\bGPL\b(?!-compatible)", "GPL"),
    (r"\bLGPL\b", "LGPL"),
    (r"\bSSPL\b", "SSPL"),
    (r"\bCDDL\b", "CDDL"),
    (r"\bEPL\b", "EPL"),
    (r"\bBUSL\b|Business Source", "BUSL"),
    (r"\bElastic-2\.0\b|\bElastic License\b", "Elastic-2.0"),
    (r"Confluent", "Confluent-Community"),
    (r"\bRSAL\b|Redis Source Available", "RSAL"),
    (r"\bCC-BY-NC|NonCommercial|non-commercial", "non-commercial"),
    (r"\bUNLICENSED\b", "UNLICENSED (proprietary, no grant)"),
]

# The permissive floor — anything a shipped dependency may carry.
ALLOWED = {
    "mit", "isc", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "0bsd",
    "bsd", "mpl-2.0", "unlicense", "cc0-1.0", "python-2.0", "wtfpl",
    "blueoak-1.0.0", "mit-0", "apache 2.0", "artistic-2.0",
    # OFL-1.1 (SIL Open Font License) is the standard license for open fonts and
    # is permissive for our purposes: it allows bundling, redistribution, and
    # commercial use, and it does not contaminate a BUSL-1.1 distribution. Its
    # one live obligation is the Reserved Font Name clause, so it earns an
    # advisory note rather than silence — see RESERVED_NAME_NOTE.
    "ofl-1.1",
}

RESERVED_NAME_NOTE = (
    "OFL-1.1 carries a Reserved Font Name clause: bundling and selling the "
    "product is fine, but a MODIFIED copy of the font may not keep the original "
    "name. Fork a font and you must rename it."
)


def deny_reason(expr: str) -> str | None:
    for pattern, name in DENIED_PATTERNS:
        if re.search(pattern, expr, re.I):
            return name
    return None


def atoms(expr: str) -> list[str]:
    """Split an SPDX expression into its licence atoms. `(MIT OR Apache-2.0)`
    is fine if ANY atom is on the floor, since we may choose; `MIT AND ISC`
    needs both, but both being permissive is the only case that matters."""
    cleaned = expr.replace("(", " ").replace(")", " ")
    return [a.strip() for a in re.split(r"\bOR\b|\bAND\b", cleaned, flags=re.I) if a.strip()]


def on_floor(expr: str) -> bool:
    parts = atoms(expr)
    return bool(parts) and any(p.lower() in ALLOWED for p in parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", default="web/package-lock.json")
    ap.add_argument("--json", dest="receipt")
    ap.add_argument("--strict-dev", action="store_true",
                    help="also fail on a denied license in a dev-only dependency")
    args = ap.parse_args()

    lock_path = Path(args.lock)
    if not lock_path.exists():
        print(f"FAIL: {lock_path} not found — cannot audit the console tree",
              file=sys.stderr)
        return 1

    lock = json.loads(lock_path.read_text())
    packages = lock.get("packages", {})
    if not packages:
        print(f"FAIL: {lock_path} has no `packages` map (need lockfileVersion 2+)",
              file=sys.stderr)
        return 1

    runtime_rows, dev_rows = [], []
    denied_runtime, denied_dev, unknown_runtime = [], [], []

    for path, meta in sorted(packages.items()):
        if not path or not isinstance(meta, dict):
            continue                       # the root project entry
        if meta.get("link"):
            continue                       # workspace symlink, not a dependency
        name = path.split("node_modules/")[-1]
        expr = meta.get("license") or meta.get("licenses") or ""
        if isinstance(expr, list):         # legacy `licenses: [{type: ...}]`
            expr = " OR ".join(
                x.get("type", "") if isinstance(x, dict) else str(x) for x in expr)
        is_dev = bool(meta.get("dev"))
        row = {"package": name, "license": expr or "MISSING", "dev": is_dev}
        (dev_rows if is_dev else runtime_rows).append(row)

        reason = deny_reason(expr) if expr else None
        if reason:
            (denied_dev if is_dev else denied_runtime).append(f"{name}: {expr} [{reason}]")
        elif not is_dev:
            if not expr:
                unknown_runtime.append(f"{name}: no license declared")
            elif not on_floor(expr):
                unknown_runtime.append(f"{name}: {expr} is not on the permissive floor")

    counts: dict[str, int] = {}
    for row in runtime_rows:
        counts[row["license"]] = counts.get(row["license"], 0) + 1

    print(f">> npm license audit: {len(runtime_rows)} shipped, "
          f"{len(dev_rows)} dev-only ({lock_path})")
    for name, count in sorted(counts.items()):
        print(f"   {name}: {count}")
    if any("ofl" in row["license"].lower() for row in runtime_rows):
        print(f"   note: {RESERVED_NAME_NOTE}")

    if args.receipt:
        Path(args.receipt).parent.mkdir(parents=True, exist_ok=True)
        Path(args.receipt).write_text(json.dumps({
            "lock": str(lock_path),
            "runtime": runtime_rows, "dev": dev_rows, "counts": counts,
            "denied_runtime": denied_runtime, "denied_dev": denied_dev,
            "unknown_runtime": unknown_runtime,
        }, indent=2, sort_keys=True) + "\n")
        print(f">> receipt: {args.receipt}")

    failed = False
    if denied_runtime:
        failed = True
        print("FAIL: a SHIPPED console dependency carries a license we cannot "
              "distribute or commercialize under:", file=sys.stderr)
        for item in denied_runtime:
            print(f"  {item}", file=sys.stderr)
    if unknown_runtime:
        failed = True
        print("FAIL: a SHIPPED console dependency is not on the permissive "
              "floor (MIT/ISC/Apache-2.0/BSD/MPL-2.0/Unlicense/0BSD):",
              file=sys.stderr)
        for item in unknown_runtime:
            print(f"  {item}", file=sys.stderr)
    if denied_dev:
        where = sys.stderr if args.strict_dev else sys.stdout
        label = "FAIL" if args.strict_dev else "note"
        print(f"{label}: dev-only dependency with a restrictive license "
              f"(does not ship, so it does not travel into the artifact):",
              file=where)
        for item in denied_dev:
            print(f"  {item}", file=where)
        if args.strict_dev:
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
