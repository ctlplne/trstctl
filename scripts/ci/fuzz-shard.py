#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Pick one CI shard of the Go fuzz targets (owner decision 2026-11-02: split jobs that outgrow their limit).

stdin: "<package dir> <FuzzName>" lines, as make fuzz-smoke discovers them. A package's targets stay together (one
fuzz build per package per shard); packages are dealt largest first to the shard with the fewest targets (ties: lower
shard, then package name), so every run picks the same shards. --selftest checks that the shards hold every target
exactly once and prints their sizes; without it, the lines of --shard are printed in input order.
"""
import argparse
import sys


def assign(lines, shards):
    packages = {}
    for line in lines:
        package, _, name = line.partition(" ")
        if not package or not name:
            raise ValueError(f"bad fuzz target line {line!r}")
        packages.setdefault(package, []).append(line)
    loads = [0] * shards
    owner = {}
    for package in sorted(packages, key=lambda p: (-len(packages[p]), p)):
        shard = min(range(shards), key=lambda i: (loads[i], i))
        owner[package] = shard
        loads[shard] += len(packages[package])
    return [[line for line in lines if owner[line.partition(" ")[0]] == i] for i in range(shards)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.shards < 1 or not 0 <= args.shard < args.shards:
        parser.error("need 0 <= --shard < --shards")
    lines = [line.strip() for line in sys.stdin if line.strip()]
    if not lines:
        print("FAIL: no fuzz targets were discovered", file=sys.stderr)
        return 1
    parts = assign(lines, args.shards)
    if args.selftest:
        held = sorted(line for part in parts for line in part)
        if held != sorted(lines) or len(set(lines)) != len(lines):
            print("FAIL: fuzz shards do not hold every target exactly once", file=sys.stderr)
            return 1
        for i, part in enumerate(parts):
            print(f"fuzz shard {i}: {len(part)} targets in {len({line.partition(' ')[0] for line in part})} packages")
        return 0
    print("\n".join(parts[args.shard]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
