#!/usr/bin/env python3
"""Render journey served badges from the shipped-binary wiring census.

The census is intentionally not committed because it contains runtime evidence.
This script reduces it to a deterministic, reviewable snapshot, injects the same
result into every journey page, and emits the console data module.  ``--check``
is the fail-closed CI mode: any red census row or stale generated file is an error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
JOURNEYS_DIR = ROOT / "docs" / "journeys"
MANIFEST_PATH = ROOT / "tools" / "dodcensus" / "manifest.json"
REQUIREMENTS_PATH = JOURNEYS_DIR / "census-requirements.json"
SNAPSHOT_PATH = JOURNEYS_DIR / "served-census.json"
WEB_PATH = ROOT / "web" / "src" / "lib" / "journeyCensus.gen.ts"
START = "<!-- trstctl:journey-census:start -->"
END = "<!-- trstctl:journey-census:end -->"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


class ContractError(RuntimeError):
    """The census or journey mapping cannot support an honest served badge."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractError(f"missing required input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain a JSON object")
    return value


def string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in value):
        raise ContractError(f"{label} must be an array of stable lowercase identifiers")
    if len(value) != len(set(value)):
        raise ContractError(f"{label} contains a duplicate identifier")
    return value


def validate_census(census: dict[str, Any]) -> tuple[dict[str, int], dict[str, dict[str, Any]]]:
    summary = census.get("summary")
    entries = census.get("entries")
    if not isinstance(summary, dict) or not isinstance(entries, dict):
        raise ContractError("wiring-census.json must contain summary and entries objects")

    numeric_keys = (
        "total",
        "served",
        "required",
        "required_failed",
        "library_only",
        "stub",
        "unknown",
        "pending",
        "inventory",
        "inventory_served",
    )
    clean_summary: dict[str, int] = {}
    for key in numeric_keys:
        value = summary.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ContractError(f"census summary.{key} must be a non-negative integer")
        clean_summary[key] = value

    total = clean_summary["total"]
    if total == 0 or clean_summary["served"] != total or clean_summary["required"] != total:
        raise ContractError(
            "journey badges require a fully green shipped-binary census: "
            f"served={clean_summary['served']} required={clean_summary['required']} total={total}"
        )
    for key in ("required_failed", "library_only", "stub", "unknown", "pending"):
        if clean_summary[key] != 0:
            raise ContractError(f"journey badges cannot render while census summary.{key}={clean_summary[key]}")
    if clean_summary["inventory_served"] != clean_summary["inventory"]:
        raise ContractError("journey badges require every inventoried backend to be served")
    if len(entries) != total:
        raise ContractError(f"census contains {len(entries)} entries but summary.total is {total}")

    clean_entries: dict[str, dict[str, Any]] = {}
    for row_id, row in entries.items():
        if not isinstance(row_id, str) or not ID_RE.fullmatch(row_id) or not isinstance(row, dict):
            raise ContractError(f"invalid census entry {row_id!r}")
        if row.get("status") != "served" or row.get("enforcement") != "required":
            raise ContractError(
                f"census row {row_id} is not usable by a journey: "
                f"status={row.get('status')!r}, enforcement={row.get('enforcement')!r}"
            )
        clean_entries[row_id] = row
    return clean_summary, clean_entries


def validate_requirements(requirements: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    if requirements.get("schema_version") != 1 or requirements.get("source") != "wiring-census.json":
        raise ContractError("journey census requirements must use schema_version 1 and source wiring-census.json")
    raw_journeys = requirements.get("journeys")
    if not isinstance(raw_journeys, dict) or not raw_journeys:
        raise ContractError("journey census requirements must contain a non-empty journeys object")

    doc_ids = {path.stem for path in JOURNEYS_DIR.glob("*.md")}
    requirement_ids = set(raw_journeys)
    if doc_ids != requirement_ids:
        missing = sorted(doc_ids - requirement_ids)
        extra = sorted(requirement_ids - doc_ids)
        raise ContractError(f"journey mapping/docs mismatch: missing={missing}, extra={extra}")

    clean: dict[str, dict[str, list[str]]] = {}
    for journey_id in sorted(raw_journeys):
        raw = raw_journeys[journey_id]
        if not ID_RE.fullmatch(journey_id) or not isinstance(raw, dict):
            raise ContractError(f"invalid journey mapping {journey_id!r}")
        rows = string_list(raw.get("census_rows"), f"{journey_id}.census_rows")
        core = string_list(raw.get("core_surfaces"), f"{journey_id}.core_surfaces")
        if not rows and not core:
            raise ContractError(f"journey {journey_id} has neither census rows nor tested core surfaces")
        clean[journey_id] = {"census_rows": rows, "core_surfaces": core}
    return clean


def build_snapshot(
    census: dict[str, Any], summary: dict[str, int], entries: dict[str, dict[str, Any]], journeys: dict[str, dict[str, list[str]]]
) -> dict[str, Any]:
    rendered: dict[str, Any] = {}
    for journey_id, requirement in journeys.items():
        rows: list[dict[str, str]] = []
        for row_id in requirement["census_rows"]:
            row = entries.get(row_id)
            if row is None:
                raise ContractError(f"journey {journey_id} references missing census row {row_id}")
            rows.append({"id": row_id, "status": row["status"], "enforcement": row["enforcement"]})
        rendered[journey_id] = {
            "census_rows": rows,
            "core_surfaces": requirement["core_surfaces"],
            "status": "served",
        }

    return {
        "schema_version": 1,
        "source": "wiring-census.json",
        "manifest_version": census.get("manifest_version"),
        "summary": summary,
        "journeys": rendered,
    }


def proof_mode_split() -> tuple[int, int]:
    """Count how the committed DoD manifest actually proves each census row.

    A ``launched-binary`` row gate-builds ``cmd/trstctl`` and takes its response
    from that live process.  An ``assembled-handler`` row drives production
    ``buildRunDeps`` output through the assembled ``Server.Handler`` in-process,
    with a hand-built ``Deps`` rejected -- production code through production
    wiring, but no binary launch.  The badge states the split so a reader never
    reads "shipped binary" for a row that never launched one.
    """
    manifest = load_json(MANIFEST_PATH)
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ContractError(f"{MANIFEST_PATH} must contain a non-empty entries array")
    launched = assembled = 0
    for entry in entries:
        mode = entry.get("runtime", {}).get("mode") if isinstance(entry, dict) else None
        if mode == "launched-binary":
            launched += 1
        elif mode == "assembled-handler":
            assembled += 1
        else:
            raise ContractError(f"DoD manifest row {entry.get('id')!r} has unusable runtime.mode {mode!r}")
    return launched, assembled


def badge(snapshot: dict[str, Any], journey_id: str, modes: tuple[int, int]) -> str:
    summary = snapshot["summary"]
    journey = snapshot["journeys"][journey_id]
    rows = [row["id"] for row in journey["census_rows"]]
    core = journey["core_surfaces"]
    launched, assembled = modes
    if launched + assembled != summary["total"]:
        raise ContractError(
            f"DoD manifest describes {launched + assembled} rows but the census reports {summary['total']}"
        )
    lines = [
        START,
        f'!!! success "Served path — wiring census {summary["served"]}/{summary["total"]}"',
        "",
        f"    The Definition-of-Done census reports **{summary['served']}/{summary['required']} required capabilities served**: "
        f"**{launched} of {summary['total']} census rows launch the shipped binary** and "
        f"**{assembled} of {summary['total']} are proved through the production-assembled handler**.",
        "    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.",
    ]
    if rows:
        lines.append("    Independently proof-gated capability rows used by this journey (all `required`, all `served`): " + ", ".join(f"`{row}`" for row in rows) + ".")
    else:
        lines.append("    This journey uses no separately proof-gated capability row; it stays on core served surfaces.")
    lines.append("    Core surfaces guarded by route and journey tests: " + ", ".join(f"`{surface}`" for surface in core) + ".")
    lines.extend(
        [
            "    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.",
            END,
        ]
    )
    return "\n".join(lines)


def render_doc(current: str, block: str, path: Path) -> str:
    if current.count(START) != current.count(END):
        raise ContractError(f"unbalanced generated census markers in {path}")
    if START in current:
        if current.count(START) != 1:
            raise ContractError(f"duplicate generated census markers in {path}")
        start = current.index(START)
        end = current.index(END, start) + len(END)
        return current[:start] + block + current[end:]

    lines = current.splitlines(keepends=True)
    if not lines or not lines[0].startswith("# "):
        raise ContractError(f"journey page {path} must begin with one H1")
    title = lines[0].rstrip("\r\n")
    rest = "".join(lines[1:]).lstrip("\r\n")
    return f"{title}\n\n{block}\n\n{rest}"


def ts_module(snapshot: dict[str, Any]) -> str:
    # Emit the small fixed schema in the repository's Prettier form without
    # requiring Node in the Go-only dod-gate CI job.
    lines = [
        "// Code generated by scripts/docs/render-journey-served.py from wiring-census.json; DO NOT EDIT.",
        "export const journeyCensus = {",
        "  journeys: {",
    ]
    for journey_id, journey in snapshot["journeys"].items():
        lines.append(f"    {json.dumps(journey_id, ensure_ascii=False)}: {{")
        rows = journey["census_rows"]
        if not rows:
            lines.append("      census_rows: [],")
        else:
            lines.append("      census_rows: [")
            for row in rows:
                lines.extend(
                    [
                        "        {",
                        f"          enforcement: {json.dumps(row['enforcement'])},",
                        f"          id: {json.dumps(row['id'])},",
                        f"          status: {json.dumps(row['status'])},",
                        "        },",
                    ]
                )
            lines.append("      ],")
        core = ", ".join(json.dumps(surface) for surface in journey["core_surfaces"])
        lines.append(f"      core_surfaces: [{core}],")
        lines.append(f"      status: {json.dumps(journey['status'])},")
        lines.append("    },")
    lines.extend(
        [
            "  },",
            f"  manifest_version: {json.dumps(snapshot['manifest_version'])},",
            f"  schema_version: {snapshot['schema_version']},",
            f"  source: {json.dumps(snapshot['source'])},",
            "  summary: {",
        ]
    )
    for key, value in sorted(snapshot["summary"].items()):
        lines.append(f"    {key}: {value},")
    lines.extend(
        [
            "  },",
            "} as const;",
            "",
            "export type JourneyCensusId = keyof typeof journeyCensus.journeys;",
            "",
        ]
    )
    return "\n".join(lines)


def expected_outputs(snapshot: dict[str, Any]) -> dict[Path, str]:
    outputs = {
        SNAPSHOT_PATH: json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        WEB_PATH: ts_module(snapshot),
    }
    modes = proof_mode_split()
    for journey_id in snapshot["journeys"]:
        path = JOURNEYS_DIR / f"{journey_id}.md"
        outputs[path] = render_doc(path.read_text(encoding="utf-8"), badge(snapshot, journey_id, modes), path)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail instead of updating stale generated files")
    parser.add_argument("--census", type=Path, default=ROOT / "wiring-census.json", help="path to a fresh wiring census")
    args = parser.parse_args()

    try:
        census = load_json(args.census.resolve())
        summary, entries = validate_census(census)
        journeys = validate_requirements(load_json(REQUIREMENTS_PATH))
        snapshot = build_snapshot(census, summary, entries, journeys)
        outputs = expected_outputs(snapshot)
    except (ContractError, OSError) as exc:
        print(f"journey-census: ERROR: {exc}", file=sys.stderr)
        return 1

    stale: list[Path] = []
    for path, expected in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current == expected:
            continue
        stale.append(path)
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")

    if args.check and stale:
        print("journey-census: generated outputs are stale:", file=sys.stderr)
        for path in stale:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        print("run: make journey-census", file=sys.stderr)
        return 1

    action = "verified" if args.check else "updated"
    print(f"journey-census: {action} {len(outputs)} outputs from {summary['served']}/{summary['total']} served rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
