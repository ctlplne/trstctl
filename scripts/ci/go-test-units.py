#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Run one package lane's units (scripts/ci/go-test-shard.py) under race detection and merged coverage.

Plain packages run first, in one `go test` with the lane's package parallelism. Then each sliced package's tests
are listed with the same build flags (so the build is shared), one package at a time, and a slice
`<package>#<i>/<K>` runs every K-th name of the sorted list from i with an anchored -run; at most --parallelism slices
run at once, and each one's output is printed when it ends. The phases never overlap: a race-instrumented compile
and link is the memory peak, and running them side by side exhausted CI runners (CI 41439816582: three package
lanes shut down mid-compile). Every invocation's coverage profile must exist and be atomic; they merge into
--coverprofile. The exit status is non-zero if any invocation failed, and the summary names it.
"""
import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TEST_NAME = re.compile(r"^(Test|Example|Fuzz)\w*$")


def parse_units(units):
    plain, slices = [], []
    for unit in units:
        package, sep, spec = unit.partition("#")
        if not sep:
            plain.append(package)
            continue
        index, _, count = spec.partition("/")
        if not (index.isdigit() and count.isdigit() and 0 <= int(index) < int(count)):
            raise ValueError(f"bad test slice unit {unit!r}")
        slices.append((package, int(index), int(count)))
    return plain, slices


def slice_names(names, index, count):
    return sorted(names)[index::count]


def run_pattern(names):
    return "^(" + "|".join(names) + ")$"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--parallelism", type=int, required=True)
    parser.add_argument("--timeout", required=True)
    parser.add_argument("--coverpkg", required=True)
    parser.add_argument("--coverprofile", required=True)
    parser.add_argument("units", nargs="+")
    args = parser.parse_args()
    plain, slices = parse_units(args.units)
    base = [args.go, "test", "-race", "-count=1", f"-timeout={args.timeout}", "-covermode=atomic", f"-coverpkg={args.coverpkg}"]
    output = Path(args.coverprofile)
    output.unlink(missing_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="go-test-units-"))
    try:
        finished = []  # (label, exit code, profile, log path or None)
        if plain:
            profile = scratch / "plain.cover"
            print(f">> go test {len(plain)} packages (race + merged first-party coverage)", flush=True)
            code = subprocess.call(base + [f"-p={args.parallelism}", f"-coverprofile={profile}"] + plain)
            finished.append(("packages", code, profile, None))
        listed, queued = {}, []
        for n, (package, index, count) in enumerate(slices):
            if package not in listed:
                result = subprocess.run(base + ["-list", "^(Test|Example|Fuzz)", package], capture_output=True, text=True)
                names = [line.strip() for line in result.stdout.splitlines() if TEST_NAME.match(line.strip())]
                if result.returncode != 0 or not names:
                    print(result.stdout + result.stderr, flush=True)
                    print(f"FAIL: could not list the tests of {package} to slice it", flush=True)
                    return 1
                listed[package] = names
            mine = slice_names(listed[package], index, count)
            label = f"{package} slice {index} of {count} ({len(mine)} of {len(listed[package])} tests)"
            if not mine:
                print(f">> {label}: nothing to run", flush=True)
                continue
            queued.append((label, base + ["-run", run_pattern(mine), f"-coverprofile={scratch / f'slice-{n}.cover'}", package],
                           scratch / f"slice-{n}.cover", scratch / f"slice-{n}.log"))
        running = []
        for label, command, profile, log in queued:
            while sum(1 for _, process, _, _ in running if process.poll() is None) >= max(1, args.parallelism):
                time.sleep(0.2)
            print(f">> go test {label}", flush=True)
            with open(log, "w") as sink:
                running.append((label, subprocess.Popen(command, stdout=sink, stderr=subprocess.STDOUT), profile, log))
        for label, process, profile, log in running:
            code = process.wait()
            print(f">> {label}: exit={code}", flush=True)
            print(log.read_text(), end="", flush=True)
            finished.append((label, code, profile, log))
        failed = [label for label, code, _, _ in finished if code != 0]
        profiles = [profile for _, _, profile, _ in finished]
        bad = [str(p) for p in profiles if not p.exists() or not p.read_text().startswith("mode: atomic\n")]
        if not failed and not bad:
            body = "".join("".join(p.read_text().splitlines(keepends=True)[1:]) for p in profiles)
            output.write_text("mode: atomic\n" + body)
        if failed or bad:
            print(f"FAIL: package lane: failed {failed}; missing or non-atomic coverage {bad}", flush=True)
            return 1
        print(f">> package lane: {len(finished)} go test invocations passed; coverage merged into {output}", flush=True)
        return 0

    finally:
        shutil.rmtree(scratch, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
