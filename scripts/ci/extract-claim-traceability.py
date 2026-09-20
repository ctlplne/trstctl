#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Claim -> code -> test traceability extractor for the ee/ patent surface.

Target path in repo: scripts/ci/extract-claim-traceability.py

What it does, in one breath: walk ee/, find every patent-claim citation in a Go
comment, group them by patent family, and emit a traceability table plus a set of
integrity findings — claims implemented but never tested, claims tested but never
implemented, claims whose whole implementation set is a package doc comment, and claim
numbers that collide across families without an application qualifier.

Why it exists: 204 ee/ files already cite claim numbers. That is a rare asset and it
is currently unreadable except by grep. This turns it into a generated artifact that
CI can keep honest, the same way the OpenAPI golden and the console bundle are kept
honest.

Usage:
  scripts/ci/extract-claim-traceability.py                 # write ee/docs/claim-traceability.md
  scripts/ci/extract-claim-traceability.py --check         # fail if the committed file is stale
  scripts/ci/extract-claim-traceability.py --json out.json # machine-readable receipt
  scripts/ci/extract-claim-traceability.py --strict        # also fail on integrity findings

The Applications table and the Verified column are NOT derived from source — they are
read from ee/docs/claim-verification.json, the one human-maintained input. Filing
dates, application serials and the provisional conversion deadline are recorded there;
nothing in this script hard-codes them.

Exit codes: 0 ok · 1 stale (--check), a configured family with zero citations
(always), or integrity findings (--strict) · 2 usage error.

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
from datetime import date

# --- configuration ---------------------------------------------------------

EE_ROOT = "ee"
OUT_PATH = os.path.join("ee", "docs", "claim-traceability.md")

# The one human-maintained input. Repo-relative POSIX form for prose, os-native for
# I/O, so the generated page reads the same on every platform.
VERIFICATION_REL = "ee/docs/claim-verification.json"
VERIFICATION_PATH = os.path.join(*VERIFICATION_REL.split("/"))

# Fields of an application entry, in the column order they are rendered.
APPLICATION_FIELDS = ("subject", "application_no", "filed", "converted_by")

# An unfilled sidecar field renders as this, so a missing serial is visible rather
# than a blank cell. Filling the sidecar is what removes it — nothing in this file
# can be edited to record a filing date.
PENDING_CELL = "_[counsel to supply]_"

# Marker for a claim counsel has not yet reviewed.
UNREVIEWED_CELL = "_[counsel]_"

# Directory under ee/ -> patent family label. Extend as families are added.
# The filed provisionals are PCAS, AGID, XREC, and VDEC — there is no PQCM
# application. ee/pqcmigration cites the PCAS mechanisms (the claim-9
# credential genus, the claim-23 policy_ref decision that PCAS-04/PCAS-05
# carry and verify), so it maps to PCAS.
FAMILY_BY_DIR = {
    "succession": "PCAS",
    "rpverify": "PCAS",
    "translog": "PCAS",
    "pqcmigration": "PCAS",
    "agentid": "AGID",
    "reconcile": "XREC",
    "decommission": "VDEC",
}

# Explicit, qualified form — preferred when present: PCAS-claim-5, AGID claim 12.
# (PQCM stays recognized here so a stray legacy qualifier surfaces visibly in
# the table instead of vanishing.) The `[-_ ]?` after `claims?` accepts the
# canonical hyphenated form PCAS-claim-5.
QUALIFIED = re.compile(
    r"\b(?P<fam>PCAS|AGID|XREC|VDEC|PQCM)[-_ ]?claims?[-_ ]?\s*(?P<nums>\d+(?:\s*(?:,|and|/|&|-)\s*\d+)*)",
    re.IGNORECASE,
)
# Bare form — ambiguous across families; family is inferred from the path.
# `(?:[-_]|\s+)` (not just whitespace) so the hyphenated `claim-9` style is
# seen too; a bare citation invisible to this scan silently falls out of the
# table, which is worse than an ambiguity finding.
BARE = re.compile(r"\bclaims?(?:[-_]|\s+)(?P<nums>\d+(?:\s*(?:,|and|/|&)\s*\d+)*)")
NUM = re.compile(r"\d+")


class SidecarError(Exception):
    """The human-maintained sidecar is missing or malformed."""


def conversion_deadline(filed: str) -> str:
    """Return the US provisional conversion deadline: filing date + 12 months.

    Accepts YYYY-MM-DD or YYYY-MM and answers at the same precision it was given, so
    a filing recorded only to the month never implies a day-precise deadline. An
    unparseable or empty value returns "" and the caller renders the pending-cell placeholder.
    """
    m = re.fullmatch(r"(\d{4})-(\d{2})(?:-(\d{2}))?", filed.strip())
    if not m:
        return ""
    year, month, day = int(m.group(1)), m.group(2), m.group(3)
    if day is None:
        return f"{year + 1}-{month}"
    try:
        return date(year + 1, int(month), int(day)).isoformat()
    except ValueError:
        # 29 February has no anniversary in a common year; the deadline is the last
        # day of that month, not a rollover into March.
        return date(year + 1, int(month), int(day) - 1).isoformat()


def load_verification(path: str) -> dict:
    """Read the sidecar that carries application metadata and counsel's verdicts.

    JSON rather than YAML on purpose: the standard library parses it, so the CI job
    that runs --check needs no third-party package installed.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise SidecarError(
            f"{path} is missing ({exc}) — it carries the Applications table and the "
            "Verified column; create it before generating"
        ) from exc
    except ValueError as exc:
        raise SidecarError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise SidecarError(f"{path} must contain a JSON object at the top level")

    apps = data.get("applications")
    if not isinstance(apps, dict) or not apps:
        raise SidecarError(f"{path} has no non-empty 'applications' object")
    for fam, entry in apps.items():
        if not isinstance(entry, dict):
            raise SidecarError(f"{path}: applications[{fam!r}] must be an object")
        unknown = sorted(set(entry) - set(APPLICATION_FIELDS))
        if unknown:
            raise SidecarError(
                f"{path}: applications[{fam!r}] has unknown field(s) {unknown}; "
                f"expected only {list(APPLICATION_FIELDS)}"
            )
        for field in APPLICATION_FIELDS:
            if not isinstance(entry.get(field, ""), str):
                raise SidecarError(
                    f"{path}: applications[{fam!r}][{field!r}] must be a string "
                    "(use \"\" for a value that is not known yet)"
                )

    verified = data.get("verified", {})
    if not isinstance(verified, dict):
        raise SidecarError(f"{path}: 'verified' must be an object mapping FAMILY-CLAIM to a note")
    for key, note in verified.items():
        if not isinstance(note, str):
            raise SidecarError(f"{path}: verified[{key!r}] must be a string")

    return {"applications": apps, "verified": verified}


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
    impl_only, test_only, doc_only = [], [], []
    for (fam, claim), rec in sorted(records.items()):
        if rec["impl"] and not rec["test"]:
            impl_only.append(f"{fam}-{claim}")
        if rec["test"] and not rec["impl"]:
            test_only.append(f"{fam}-{claim}")
        # A claim whose entire implementation set is package doc comments is cited
        # from prose, not from the code that carries its limbs. The table then sends
        # a reader — counsel, an examiner, a diligence reviewer — to a summary
        # instead of to the mechanism. Independent claims mislead most this way.
        if rec["impl"] and all(os.path.basename(p) == "doc.go" for p in rec["impl"]):
            doc_only.append(f"{fam}-{claim}")

    # Bare claim numbers appearing in more than one family are ambiguous.
    bare_by_claim = defaultdict(set)
    for (fam, claim), rec in records.items():
        if not rec["qualified"]:
            bare_by_claim[claim].add(fam)
    collisions = sorted(c for c, fams in bare_by_claim.items() if len(fams) > 1)

    # CLAIMTRACE-001. A family configured in FAMILY_BY_DIR that produced no citation
    # at all is the failure this table exists to catch: the family is absent from
    # every section below, so the artifact looks complete while silently omitting a
    # whole filing. Unlike the three findings above, this one is not gated behind
    # --strict; see main().
    uncovered = sorted(set(FAMILY_BY_DIR.values()) - set(families))

    return {
        "families": families,
        "uncovered_families": uncovered,
        "implemented_but_untested": impl_only,
        "tested_but_unimplemented": test_only,
        "implemented_only_in_doc_comments": doc_only,
        "ambiguous_claim_numbers": collisions,
        "ambiguous_families": sorted(
            {f for c in collisions for f in bare_by_claim[c]}
        ),
    }


def render(records, found, n_qualified, n_bare, verif) -> str:
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
    w("> cited code practices the claim. The application metadata below and the")
    w("> `Verified` column are the only human-maintained data; both are edited in")
    w(f"> `{VERIFICATION_REL}`, not here. `Converted by` is the deadline to")
    w("> convert a US provisional, computed as the filing date plus twelve months.")
    w("")
    w("## Applications")
    w("")
    w("| Family | Subject | Application / provisional no. | Filed | Converted by |")
    w("|---|---|---|---|---|")
    apps = verif["applications"]
    for fam in sorted(apps):
        entry = apps[fam]
        cells = [entry.get(f, "").strip() for f in APPLICATION_FIELDS]
        if not cells[3]:
            cells[3] = conversion_deadline(cells[2])
        w("| " + fam + " | " + " | ".join(c or PENDING_CELL for c in cells) + " |")
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

            verdict = verif["verified"].get(f"{fam}-{claim}", "").strip() or UNREVIEWED_CELL
            w(f"| {claim} | {cell(impl)} | {cell(test)} | {verdict} |")
        w("")

    w("## Integrity findings")
    w("")
    if found["uncovered_families"]:
        w("**Configured families with zero citations** — the family is configured in "
          "`FAMILY_BY_DIR` but no file under `ee/` cites a single one of its claims, so "
          "it is missing from every section above. This fails the gate unconditionally, "
          "not only under `--strict`:")
        w("")
        for x in found["uncovered_families"]:
            w(f"- `{x}`")
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
    if found["implemented_only_in_doc_comments"]:
        w("**Cited only from a package doc comment** — every path in the implementation "
          "column is a `doc.go`, so the table sends a reader to prose rather than to the "
          "code carrying the claim's limbs. Cite the implementing files themselves:")
        w("")
        for x in found["implemented_only_in_doc_comments"]:
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
               ("implemented_but_untested", "tested_but_unimplemented",
                "implemented_only_in_doc_comments", "ambiguous_claim_numbers")):
        w("None. Every cited claim has an implementation and a test, no implementation "
          "set is a package doc comment alone, and no claim number is ambiguous across "
          "families.")
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
    ap.add_argument("--verification", default=VERIFICATION_PATH,
                    help=f"human-maintained sidecar (default {VERIFICATION_PATH})")
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

    try:
        verif = load_verification(args.verification)
    except SidecarError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Every family cited in ee/ must have an application entry. Without this a newly
    # cited family would silently have no row, and no filing date or conversion
    # deadline anywhere — the defect this sidecar exists to remove.
    undeclared = [f for f in found["families"] if f not in verif["applications"]]
    if undeclared:
        print(f"error: {args.verification} has no application entry for cited "
              f"family/families {undeclared} — add one (empty strings are fine) so the "
              "filing date and the conversion deadline have somewhere to live",
              file=sys.stderr)
        return 2

    rendered = render(records, found, n_qualified, n_bare, verif)

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

    # CLAIMTRACE-001. A wholly uncited family fails the gate on its own, without
    # --strict: a configured family that produces zero rows makes the generated table
    # look complete while omitting an entire filing. --strict stays scoped to the
    # three within-family findings so its meaning does not change.
    if found["uncovered_families"]:
        print("CLAIMTRACE-001: configured famil(ies) with zero claim citations: "
              + ", ".join(found["uncovered_families"])
              + " — cite those claims in ee/ or remove the family from FAMILY_BY_DIR",
              file=sys.stderr)
        return 1

    # CLAIMTRACE-001. A wholly uncited family fails the gate on its own, without
    # --strict: a configured family that produces zero rows makes the generated table
    # look complete while omitting an entire filing. --strict stays scoped to the
    # three within-family findings so its meaning does not change.
    if found["uncovered_families"]:
        print("CLAIMTRACE-001: configured famil(ies) with zero claim citations: "
              + ", ".join(found["uncovered_families"])
              + " — cite those claims in ee/ or remove the family from FAMILY_BY_DIR",
              file=sys.stderr)
        return 1

    n_findings = sum(len(found[k]) for k in
                     ("implemented_but_untested", "tested_but_unimplemented",
                      "implemented_only_in_doc_comments", "ambiguous_claim_numbers"))
    if n_findings:
        print(f"claim traceability: {n_findings} integrity finding(s) — see "
              f"'Integrity findings' in {args.out}", file=sys.stderr)
        if args.strict:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
