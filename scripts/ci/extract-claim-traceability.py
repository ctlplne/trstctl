#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Claim -> code -> test traceability extractor for the ee/ patent surface.

Target path in repo: scripts/ci/extract-claim-traceability.py

What it does, in one breath: walk ee/, find every patent-claim citation in a Go
comment, group them by patent family, and emit a traceability table plus a set of
integrity findings — claims implemented but never tested, claims tested but never
implemented, and claim numbers that collide across families without an application
qualifier.

Why it exists: 204 ee/ files already cite claim numbers. That is a rare asset and it
is currently unreadable except by grep. This turns it into a generated artifact that
CI can keep honest, the same way the OpenAPI golden and the console bundle are kept
honest.

Usage:
  scripts/ci/extract-claim-traceability.py                 # write ee/docs/claim-traceability.md
  scripts/ci/extract-claim-traceability.py --check         # fail if the committed file is stale
  scripts/ci/extract-claim-traceability.py --json out.json # machine-readable receipt
  scripts/ci/extract-claim-traceability.py --strict        # also fail on integrity findings

Exit codes: 0 ok · 1 stale (--check) or integrity findings (--strict) · 2 usage error.

NOTE ON QUALIFIED CITATIONS: once citations are namespaced as `PCAS-claim-5` /
`AGID-claim-5`, this script prefers the explicit qualifier over the directory-derived
family, and the collision finding disappears on its own. That is the intended
end state: the fix retires the finding.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict

# --- configuration ---------------------------------------------------------

EE_ROOT = "ee"
OUT_PATH = os.path.join("ee", "docs", "claim-traceability.md")

# Directory under ee/ -> patent family label. Extend as families are added.
FAMILY_BY_DIR = {
    "succession": "PCAS",
    "rpverify": "PCAS",
    "translog": "PCAS",
    "agentid": "AGID",
    "reconcile": "XREC",
    "decommission": "VDEC",
    "pqcmigration": "PQCM",
}

# Explicit, qualified form — preferred when present: PCAS-claim-5, AGID claim 12.
QUALIFIED = re.compile(
    r"\b(?P<fam>PCAS|AGID|XREC|VDEC|PQCM)[-_ ]?claims?\s*(?P<nums>\d+(?:\s*(?:,|and|/|&|-)\s*\d+)*)",
    re.IGNORECASE,
)
# Bare form — ambiguous across families; family is inferred from the path.
BARE = re.compile(r"\bclaims?\s+(?P<nums>\d+(?:\s*(?:,|and|/|&)\s*\d+)*)")
NUM = re.compile(r"\d+")


def family_for(path: str) -> str:
    parts = path.split(os.sep)
    if len(parts) > 1:
        return FAMILY_BY_DIR.get(parts[1], parts[1].upper())
    return "UNKNOWN"


def scan(root: str):
    """Return (records, qualified_count, bare_count).

    records[(family, claim)] = {"impl": {paths}, "test": {paths}, "qualified": bool}
    """
    records = defaultdict(lambda: {"impl": set(), "test": set(), "qualified": False})
    n_qualified = n_bare = 0

    for dirpath, _dirs, filenames in os.walk(root):
        for filename in sorted(filenames):
            if not filename.endswith(".go"):
                continue
            path = os.path.join(dirpath, filename)
            try:
                text = open(path, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue

            bucket = "test" if filename.endswith("_test.go") else "impl"
            inferred = family_for(path)

            hits: set[tuple[str, int, bool]] = set()
            for m in QUALIFIED.finditer(text):
                fam = m.group("fam").upper()
                for n in NUM.findall(m.group("nums")):
                    hits.add((fam, int(n), True))
                    n_qualified += 1
            # Bare citations only count where a qualified one did not already claim
            # that number in this file, so `PCAS-claim-5` is not double-counted.
            qualified_nums = {n for _f, n, _q in hits}
            for m in BARE.finditer(text):
                for n in NUM.findall(m.group("nums")):
                    if int(n) in qualified_nums:
                        continue
                    hits.add((inferred, int(n), False))
                    n_bare += 1

            for fam, claim, qualified in hits:
                rec = records[(fam, claim)]
                rec[bucket].add(path)
                rec["qualified"] = rec["qualified"] or qualified

    return records, n_qualified, n_bare


def findings(records) -> dict:
    families = sorted({f for f, _c in records})
    impl_only, test_only = [], []
    for (fam, claim), rec in sorted(records.items()):
        if rec["impl"] and not rec["test"]:
            impl_only.append(f"{fam}-{claim}")
        if rec["test"] and not rec["impl"]:
            test_only.append(f"{fam}-{claim}")

    # Bare claim numbers appearing in more than one family are ambiguous.
    bare_by_claim = defaultdict(set)
    for (fam, claim), rec in records.items():
        if not rec["qualified"]:
            bare_by_claim[claim].add(fam)
    collisions = sorted(c for c, fams in bare_by_claim.items() if len(fams) > 1)

    return {
        "families": families,
        "implemented_but_untested": impl_only,
        "tested_but_unimplemented": test_only,
        "ambiguous_claim_numbers": collisions,
        "ambiguous_families": sorted(
            {f for c in collisions for f in bare_by_claim[c]}
        ),
    }


def render(records, found, n_qualified, n_bare) -> str:
    out: list[str] = []
    w = out.append
    w("<!-- GENERATED FILE — do not edit by hand.")
    w("     Regenerate: scripts/ci/extract-claim-traceability.py")
    w("     CI verifies freshness with --check. -->")
    w("")
    w("# Patent claim traceability")
    w("")
    w("Every patent-claim citation in `ee/` Go source, grouped by family, with the")
    w("implementing files and the tests that exercise them. Generated from source, so")
    w("it cannot drift from the code it describes.")
    w("")
    w("> **Verification status.** This table proves a *citation* exists, not that the")
    w("> cited code practices the claim. The `Verified` column is maintained by counsel")
    w("> review and is the only column a human edits — in `claim-verification.yaml`,")
    w("> not here.")
    w("")
    w("## Applications")
    w("")
    w("| Family | Subject | Application / provisional no. | Filed | Converted by |")
    w("|---|---|---|---|---|")
    for fam in found["families"]:
        w(f"| {fam} | _[FILL]_ | _[FILL]_ | _[FILL]_ | _[FILL: filing + 12 months]_ |")
    w("")
    w(f"Citations parsed: **{n_qualified} qualified**, **{n_bare} bare** "
      "(bare citations infer their family from the directory — namespace them to remove the guesswork).")
    w("")

    for fam in found["families"]:
        claims = sorted(c for (f, c) in records if f == fam)
        if not claims:
            continue
        w(f"## {fam}")
        w("")
        w("| Claim | Implementation | Tests | Verified |")
        w("|---|---|---|---|")
        for claim in claims:
            rec = records[(fam, claim)]
            impl = sorted(rec["impl"])
            test = sorted(rec["test"])

            def cell(paths: list[str]) -> str:
                if not paths:
                    return "**— none —**"
                shown = ", ".join(f"`{p}`" for p in paths[:3])
                if len(paths) > 3:
                    shown += f" _(+{len(paths) - 3} more)_"
                return shown

            w(f"| {claim} | {cell(impl)} | {cell(test)} | _[counsel]_ |")
        w("")

    w("## Integrity findings")
    w("")
    if found["implemented_but_untested"]:
        w("**Implemented but no test cites the claim** — either add the citation to the "
          "test that already covers it, or the claim is not actually proven:")
        w("")
        for x in found["implemented_but_untested"]:
            w(f"- `{x}`")
        w("")
    if found["tested_but_unimplemented"]:
        w("**A test cites the claim but no implementation does** — the citation drifted, "
          "or the mechanism lives somewhere that does not say so:")
        w("")
        for x in found["tested_but_unimplemented"]:
            w(f"- `{x}`")
        w("")
    if found["ambiguous_claim_numbers"]:
        fams = ", ".join(found["ambiguous_families"])
        w(f"**Ambiguous claim numbers** — cited bare in more than one family ({fams}), so "
          "a reader cannot tell which application is meant. Namespace them "
          "(`PCAS-claim-N`, `AGID-claim-N`) to resolve:")
        w("")
        w("> " + ", ".join(str(c) for c in found["ambiguous_claim_numbers"]))
        w("")
    if not any(found[k] for k in
               ("implemented_but_untested", "tested_but_unimplemented", "ambiguous_claim_numbers")):
        w("None. Every cited claim has an implementation and a test, and no claim number "
          "is ambiguous across families.")
        w("")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed file differs from freshly generated output")
    ap.add_argument("--strict", action="store_true",
                    help="also fail when integrity findings are present")
    ap.add_argument("--json", metavar="PATH", help="write a machine-readable receipt")
    ap.add_argument("--out", default=OUT_PATH, help=f"output path (default {OUT_PATH})")
    args = ap.parse_args()

    if not os.path.isdir(EE_ROOT):
        print(f"error: run from the repository root ({EE_ROOT}/ not found)", file=sys.stderr)
        return 2

    records, n_qualified, n_bare = scan(EE_ROOT)
    if not records:
        print("error: no claim citations found — has the citation convention changed?",
              file=sys.stderr)
        return 2

    found = findings(records)
    rendered = render(records, found, n_qualified, n_bare)

    if args.json:
        payload = {
            "claims": {
                f"{fam}-{claim}": {
                    "implementation": sorted(rec["impl"]),
                    "tests": sorted(rec["test"]),
                    "qualified": rec["qualified"],
                }
                for (fam, claim), rec in sorted(records.items())
            },
            "findings": found,
            "citations": {"qualified": n_qualified, "bare": n_bare},
        }
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")

    if args.check:
        try:
            current = open(args.out, encoding="utf-8").read()
        except OSError:
            print(f"claim traceability: {args.out} is missing — run "
                  "scripts/ci/extract-claim-traceability.py and commit the result",
                  file=sys.stderr)
            return 1
        if current != rendered:
            print(f"claim traceability: {args.out} is stale — run "
                  "scripts/ci/extract-claim-traceability.py and commit the result",
                  file=sys.stderr)
            return 1
        print(f"claim traceability: {args.out} is current")
    else:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"claim traceability: wrote {args.out}")

    n_findings = sum(len(found[k]) for k in
                     ("implemented_but_untested", "tested_but_unimplemented",
                      "ambiguous_claim_numbers"))
    if n_findings:
        print(f"claim traceability: {n_findings} integrity finding(s) — see "
              f"'Integrity findings' in {args.out}", file=sys.stderr)
        if args.strict:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
