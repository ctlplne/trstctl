#!/usr/bin/env python3
"""Stamp and compare live receipts from one physical test host.

The absolute SLO gate runs before comparison. This reports baseline deltas
without introducing a new, noise-sensitive performance budget.
"""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import sys


def machine_fingerprint():
    machine = "|".join(
        (platform.node(), platform.machine(), platform.processor(), str(os.cpu_count()))
    )
    return hashlib.sha256(machine.encode()).hexdigest()


def read(path):
    return json.loads(pathlib.Path(path).read_text())


def stamp(path):
    receipt = read(path)
    if receipt.get("profile") != "live" or not receipt.get("summary", {}).get("ok"):
        raise ValueError("only a passing live receipt can become a baseline")
    receipt["machine_fingerprint_sha256"] = machine_fingerprint()
    pathlib.Path(path).write_text(json.dumps(receipt, indent=2) + "\n")


def compare(baseline_path, candidate_path):
    baseline, candidate = read(baseline_path), read(candidate_path)
    host = machine_fingerprint()
    if baseline.get("machine_fingerprint_sha256") != host:
        raise ValueError("baseline was not stamped on this machine; capture a same-machine baseline")
    if candidate.get("machine_fingerprint_sha256") != host:
        raise ValueError("candidate was not stamped on this machine")
    if not baseline.get("summary", {}).get("ok") or not candidate.get("summary", {}).get("ok"):
        raise ValueError("baseline and candidate must both pass the unchanged absolute SLO gate")
    for key in ("profile", "stack_profile", "load_phases"):
        if baseline.get(key) != candidate.get(key):
            raise ValueError(f"incompatible live receipt: {key} differs")
    old = {(row["hot_path"], row["phase"]): row for row in baseline["results"]}
    new = {(row["hot_path"], row["phase"]): row for row in candidate["results"]}
    if not old or old.keys() != new.keys():
        raise ValueError("live hot-path and phase sets differ")
    deltas = []
    for key in sorted(old):
        before, after = old[key], new[key]
        if before["samples"] != after["samples"]:
            raise ValueError(f"sample count differs for {key}")
        deltas.append(
            {
                "hot_path": key[0],
                "phase": key[1],
                "p99_ms_baseline": before["p99_ms"],
                "p99_ms_candidate": after["p99_ms"],
                "throughput_per_second_baseline": before["throughput_per_second"],
                "throughput_per_second_candidate": after["throughput_per_second"],
            }
        )
    return {"same_machine": True, "absolute_slo_passed": True, "deltas": deltas}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("stamp").add_argument("receipt")
    comparison = commands.add_parser("compare")
    comparison.add_argument("baseline")
    comparison.add_argument("candidate")
    args = parser.parse_args()
    try:
        if args.command == "stamp":
            stamp(args.receipt)
        else:
            print(json.dumps(compare(args.baseline, args.candidate), indent=2))
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"live baseline: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
