#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Pick one CI shard of the Go test packages (owner decision 2026-11-02: split the Go test jobs).

Reads `go list` package paths on stdin and prints the units of shard --shard of --shards, one per line. A unit is a
package, or, for a package whose measured time exceeds --max-unit-seconds, one of K test slices written
`<package>#<i>/<K>` (scripts/ci/go-test-units.py runs every K-th test of the package's sorted list from i), so one
package can't hold a lane past its budget. Units are assigned longest-first to the shard with the least total weight
(seconds from a measured CI run, in --weights); a package with no measured weight counts as the median, so a new
package lands somewhere and is never dropped. Ties break by unit name, so every shard computes the same partition.
--selftest checks that the shards cover every package exactly once, whole or as all of its slices.
"""
import argparse
import json
import math
import statistics
import sys


def units_for(packages, weights, max_unit_seconds):
    known = [weights[p] for p in packages if p in weights]
    default = statistics.median(known) if known else 1.0
    units = {}
    for package in packages:
        weight = weights.get(package, default)
        slices = math.ceil(weight / max_unit_seconds) if max_unit_seconds and weight > max_unit_seconds else 1
        if slices == 1:
            units[package] = weight
        else:
            for i in range(slices):
                units[f"{package}#{i}/{slices}"] = weight / slices
    return units


def partition(packages, weights, shards, max_unit_seconds=0):
    units = units_for(packages, weights, max_unit_seconds)
    loads = [0.0] * shards
    owner = {}
    for unit in sorted(units, key=lambda u: (-units[u], u)):
        shard = min(range(shards), key=lambda i: (loads[i], i))
        owner[unit] = shard
        loads[shard] += units[unit]
    return owner, loads


def covers_exactly(packages, owner):
    """Every package is one unit, or exactly slices 0..K-1 of one K."""
    seen = {}
    for unit in owner:
        package, _, spec = unit.partition("#")
        seen.setdefault(package, []).append(spec)
    if sorted(seen) != sorted(packages):
        return False
    for specs in seen.values():
        if specs == [""]:
            continue
        if "" in specs:
            return False
        counts = {spec.split("/")[1] for spec in specs}
        if len(counts) != 1:
            return False
        k = int(counts.pop())
        if sorted(int(spec.split("/")[0]) for spec in specs) != list(range(k)):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--weights", required=True)
    parser.add_argument("--max-unit-seconds", type=float, default=0, help="split a package measured above this into test slices (0: never)")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if not 0 <= args.shard < args.shards:
        raise SystemExit("go-test-shard: --shard must be in [0, --shards)")
    packages = sorted({line.strip() for line in sys.stdin if line.strip()})
    if not packages:
        raise SystemExit("go-test-shard: no packages on stdin")
    weights = json.load(open(args.weights))["weights"]
    owner, loads = partition(packages, weights, args.shards, args.max_unit_seconds)
    if args.selftest:
        if not covers_exactly(packages, owner) or any(not 0 <= s < args.shards for s in owner.values()):
            raise SystemExit("go-test-shard: the shards do not cover the packages exactly once")
        for i, load in enumerate(loads):
            mine = [u for u, s in owner.items() if s == i]
            sliced = sum(1 for u in mine if "#" in u)
            print(f"shard {i}: {len(mine)} units ({sliced} test slices), {load / 60:.1f} min of measured test time", file=sys.stderr)
        return
    for unit in sorted(owner):
        if owner[unit] == args.shard:
            print(unit)


if __name__ == "__main__":
    main()
