#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise the package-lane runner and the shard picker's test slices without a Go build."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


units = load("go_test_units", "go-test-units.py")
shard = load("go_test_shard", "go-test-shard.py")

# A fake `go test`: -list prints the package's tests; a run records which tests it ran (by its -run pattern, or all),
# writes an atomic profile, and fails when FAKE_FAIL names one of them.
FAKE_GO = r'''
import os, re, sys
args = sys.argv[1:]
log = os.environ["FAKE_LOG"]
tests = {"example/big": ["TestA", "TestB", "TestC", "TestD", "TestE", "ExampleF"], "example/small": ["TestS"], "example/other": ["TestO"]}
if "-list" in args:
    pkg = args[-1]
    print("\n".join(tests[pkg]))
    print("ok  \t" + pkg + "\t0.01s")
    sys.exit(0)
pattern = args[args.index("-run") + 1] if "-run" in args else None
profile = next(a.split("=", 1)[1] for a in args if a.startswith("-coverprofile="))
pkgs = [a for a in args if a.startswith("example/")]
ran = []
for pkg in pkgs:
    ran += [pkg + "." + t for t in tests[pkg] if pattern is None or re.fullmatch(pattern, t)]
with open(log, "a") as f:
    f.write(" ".join(ran) + "\n")
if os.environ.get("FAKE_NO_PROFILE") != "1":
    with open(profile, "w") as f:
        f.write("mode: atomic\n" + "".join(r + ".go:1.1,2.2 1 1\n" for r in ran))
failing = os.environ.get("FAKE_FAIL", "")
sys.exit(1 if failing and any(r.endswith("." + failing) for r in ran) else 0)
'''


class UnitsTests(unittest.TestCase):
    def run_lane(self, unit_args, env=None):
        with tempfile.TemporaryDirectory(prefix="units-selftest-") as directory:
            root = Path(directory)
            fake = root / "fake-go"
            fake.write_text("#!" + sys.executable + "\n" + FAKE_GO)
            fake.chmod(0o700)
            log, out = root / "ran.log", root / "cover.out.main.0"
            result = subprocess.run([sys.executable, str(HERE / "go-test-units.py"), "--go", str(fake), "--parallelism", "2",
                                     "--timeout", "1m", "--coverpkg", "./...", "--coverprofile", str(out), *unit_args],
                                    env={**os.environ, "FAKE_LOG": str(log), **(env or {})}, capture_output=True, text=True)
            ran = log.read_text().split() if log.exists() else []
            return result, ran, out.read_text() if out.exists() else None

    def test_slices_run_every_test_once_beside_the_plain_packages(self):
        result, ran, profile = self.run_lane(["example/small", "example/other", "example/big#0/2", "example/big#1/2"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        big = sorted(r for r in ran if r.startswith("example/big."))
        self.assertEqual(big, ["example/big." + t for t in sorted(["TestA", "TestB", "TestC", "TestD", "TestE", "ExampleF"])])
        self.assertEqual(len(big), len(set(big)))
        self.assertIn("example/small.TestS", ran)
        self.assertTrue(profile.startswith("mode: atomic\n") and profile.count("mode:") == 1 and "example/big.TestA.go" in profile)

    def test_a_failing_slice_fails_the_lane_and_prints_its_output(self):
        # Sorted, the big package's tests are ExampleF TestA TestB TestC TestD TestE; slice 2 of 3 is TestB, TestE.
        result, _, profile = self.run_lane(["example/small", "example/big#2/3"], {"FAKE_FAIL": "TestB"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("example/big slice 2 of 3 (2 of 6 tests): exit=1", result.stdout)
        self.assertIn("FAIL: package lane", result.stdout)
        self.assertIsNone(profile)

    def test_a_missing_profile_fails_the_lane(self):
        result, _, profile = self.run_lane(["example/small"], {"FAKE_NO_PROFILE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing or non-atomic coverage", result.stdout)
        self.assertIsNone(profile)

    def test_a_malformed_slice_is_refused(self):
        for bad in ["example/big#2/2", "example/big#x/2", "example/big#1"]:
            with self.subTest(unit=bad), self.assertRaises(ValueError):
                units.parse_units([bad])

    def test_slices_partition_the_sorted_names(self):
        names = ["TestC", "TestA", "TestB", "TestE", "TestD"]
        parts = [units.slice_names(names, i, 3) for i in range(3)]
        self.assertEqual(sorted(sum(parts, [])), sorted(names))
        self.assertTrue(re.fullmatch(units.run_pattern(parts[0]), parts[0][0]))
        self.assertIsNone(re.fullmatch(units.run_pattern(["TestA"]), "TestAB"))


class ShardTests(unittest.TestCase):
    def test_a_package_over_budget_becomes_slices_spread_over_shards(self):
        packages = ["p/big", "p/mid", "p/small", "p/new"]
        weights = {"p/big": 900.0, "p/mid": 300.0, "p/small": 10.0}
        owner, loads = shard.partition(packages, weights, 3, max_unit_seconds=360)
        self.assertEqual(sorted(u for u in owner if u.startswith("p/big")), ["p/big#0/3", "p/big#1/3", "p/big#2/3"])
        self.assertEqual(len({owner[u] for u in owner if u.startswith("p/big")}), 3)
        self.assertTrue(shard.covers_exactly(packages, owner))
        self.assertAlmostEqual(sum(loads), 900 + 300 + 10 + 300)  # p/new counts as the median (300)
        whole, _ = shard.partition(packages, weights, 3)
        self.assertNotIn("p/big#0/3", whole)

    def test_coverage_check_refuses_a_lost_or_doubled_slice(self):
        packages = ["p/big", "p/small"]
        self.assertTrue(shard.covers_exactly(packages, {"p/big#0/2": 0, "p/big#1/2": 1, "p/small": 0}))
        self.assertFalse(shard.covers_exactly(packages, {"p/big#0/2": 0, "p/small": 0}))
        self.assertFalse(shard.covers_exactly(packages, {"p/big#0/2": 0, "p/big#1/2": 1, "p/big": 0, "p/small": 0}))
        self.assertFalse(shard.covers_exactly(packages, {"p/big#0/2": 0, "p/big#1/3": 1, "p/small": 0}))
        self.assertFalse(shard.covers_exactly(packages, {"p/big": 0}))


if __name__ == "__main__":
    unittest.main(verbosity=1)
