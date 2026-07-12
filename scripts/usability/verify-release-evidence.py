#!/usr/bin/env python3
"""Validate usability evidence before CI/release notes can make outcome claims."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[2]
CLAIM_RE = re.compile(
    r"\b(nps|csat|operator[- ]satisfaction|satisfaction score|operator happiness)\b",
    re.IGNORECASE,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--first-run", default="scripts/usability/first-run-receipt.json")
    parser.add_argument("--operator-study", default="scripts/usability/operator-study-receipt.json")
    parser.add_argument("--release-notes", default="")
    parser.add_argument("--release-notes-text", default="")
    parser.add_argument("--max-first-run-age-days", type=int, default=180)
    args = parser.parse_args()

    first = load_json(args.first_run)
    study = load_json(args.operator_study)
    check_first_run(first, args.max_first_run_age_days)
    check_operator_study(study)
    check_release_notes(args, study)

    print(
        ">> usability evidence ok: "
        f"{args.first_run} and {args.operator_study} satisfy the release-note gate"
    )
    return 0


def load_json(path: str) -> dict:
    p = resolve(path)
    try:
        return json.loads(p.read_text())
    except FileNotFoundError:
        fail(f"missing usability evidence file: {p}")
    except json.JSONDecodeError as exc:
        fail(f"{p} is not valid JSON: {exc}")


def check_first_run(receipt: dict, max_age_days: int) -> None:
    if receipt.get("schema_version") != 1:
        fail("first-run receipt schema_version must be 1")
    if receipt.get("id") != "USABILITY-SLO-001":
        fail("first-run receipt id must be USABILITY-SLO-001")
    generated_at = parse_time(receipt.get("generated_at"), "first-run generated_at")
    age_days = (datetime.now(timezone.utc) - generated_at).total_seconds() / 86400
    if age_days > max_age_days:
        fail(
            "first-run receipt is stale: "
            f"{age_days:.1f} days old, max {max_age_days} days"
        )

    summary = receipt.get("summary") or {}
    if not summary.get("ok") or not summary.get("met"):
        fail(f"first-run receipt summary is not green: {summary}")

    target_ms = float((receipt.get("slo") or {}).get("target_ms") or 0)
    if target_ms <= 0:
        fail("first-run receipt must define a positive slo.target_ms")
    measurements = receipt.get("measurements") or []
    if not measurements:
        fail("first-run receipt must contain at least one measurement")
    for measurement in measurements:
        duration = float(measurement.get("duration_ms") or 0)
        if duration <= 0 or duration > target_ms or not measurement.get("met"):
            fail(f"first-run measurement does not meet the SLO: {measurement}")

    command = " ".join(receipt.get("command") or [])
    if "first-run.test.tsx" not in command:
        fail("first-run receipt must be generated from the first-run.test.tsx served-capability journey")
    test_anchor = receipt.get("test_anchor")
    if not test_anchor or not resolve(test_anchor).exists():
        fail(f"first-run receipt test_anchor does not exist: {test_anchor}")


def check_operator_study(receipt: dict) -> None:
    if receipt.get("schema_version") != 1:
        fail("operator-study receipt schema_version must be 1")
    if receipt.get("id") != "USABILITY-SLO-002":
        fail("operator-study receipt id must be USABILITY-SLO-002")
    status = receipt.get("status")
    if status == "measured":
        participants = int(receipt.get("participants") or 0)
        if participants < 5:
            fail("measured operator-study receipt needs at least 5 external operators")
        if not isinstance(receipt.get("nps_score"), (int, float)):
            fail("measured operator-study receipt needs numeric nps_score")
        return
    if status != "no_numeric_claim":
        fail("operator-study receipt status must be measured or no_numeric_claim")
    if receipt.get("participants") not in (0, None):
        fail("no_numeric_claim operator-study receipt must not imply participants")
    gate = " ".join(str(v) for v in receipt.values()).lower()
    for marker in ("release", "nps", "claim"):
        if marker not in gate:
            fail(f"operator-study guard receipt missing marker {marker!r}")


def check_release_notes(args: argparse.Namespace, study: dict) -> None:
    notes = args.release_notes_text
    if args.release_notes:
        notes = f"{notes}\n{resolve(args.release_notes).read_text()}"
    if CLAIM_RE.search(notes or "") and study.get("status") != "measured":
        fail(
            "release notes contain an NPS/operator-satisfaction claim, but "
            "scripts/usability/operator-study-receipt.json is not a measured study"
        )


def parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(f"{field} must be an RFC3339 timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        fail(f"{field} is not RFC3339: {value}")


def resolve(path: str) -> pathlib.Path:
    p = pathlib.Path(path)
    if not p.is_absolute():
        p = ROOT / p
    return p


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    raise SystemExit(main())
