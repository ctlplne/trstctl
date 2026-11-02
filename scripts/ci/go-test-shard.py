#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Pick one CI shard of the Go test packages (owner decision 2026-11-02: split the Go test jobs).

Reads `go list` package paths on stdin and prints those of shard --shard of --shards, one per line. Packages are
assigned longest-first to the shard with the least total weight (seconds from a measured CI run, in
--weights); a package with no measured weight counts as the median, so a new package lands somewhere and is
never dropped. Ties break by package path, so every shard computes the same partition. --selftest checks that
the shards partition the input exactly.
"""
import argparse
import json
import statistics
import sys


def partition(packages, weights, shards):
    known = [weights[p] for p in packages if p in weights]
    default = statistics.median(known) if known else 1.0
    loads = [0.0] * shards
    owner = {}
    for package in sorted(packages, key=lambda p: (-weights.get(p, default), p)):
        shard = min(range(shards), key=lambda i: (loads[i], i))
        owner[package] = shard
        loads[shard] += weights.get(package, default)
    return owner, loads


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--weights", required=True)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if not 0 <= args.shard < args.shards:
        raise SystemExit("go-test-shard: --shard must be in [0, --shards)")
    packages = sorted({line.strip() for line in sys.stdin if line.strip()})
    if not packages:
        raise SystemExit("go-test-shard: no packages on stdin")
    weights = json.load(open(args.weights))["weights"]
    owner, loads = partition(packages, weights, args.shards)
    if args.selftest:
        assigned = sorted(owner)
        if assigned != packages or any(not 0 <= s < args.shards for s in owner.values()):
            raise SystemExit("go-test-shard: the shards do not partition the packages exactly")
        for i, load in enumerate(loads):
            count = sum(1 for s in owner.values() if s == i)
            print(f"shard {i}: {count} packages, {load / 60:.1f} min of measured test time", file=sys.stderr)
        return
    for package in packages:
        if owner[package] == args.shard:
            print(package)


if __name__ == "__main__":
    main()
