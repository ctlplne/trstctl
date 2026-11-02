#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise the fuzz shard picker: every target once, packages kept whole, balanced, stable."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("fuzz_shard", HERE / "fuzz-shard.py")
fuzz_shard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fuzz_shard)

LINES = ["./internal/a FuzzA1", "./internal/a FuzzA2", "./internal/a FuzzA3", "./internal/b FuzzB1",
         "./internal/b FuzzB2", "./internal/c FuzzC1", "./internal/d FuzzD1", "./internal/e FuzzE1"]


class FuzzShardTests(unittest.TestCase):
    def test_every_target_once_and_packages_whole(self):
        parts = fuzz_shard.assign(LINES, 3)
        self.assertEqual(sorted(sum(parts, [])), sorted(LINES))
        for part in parts:
            for package in {line.split()[0] for line in part}:
                self.assertTrue(all(line in part for line in LINES if line.split()[0] == package), package)

    def test_balanced_and_stable(self):
        parts = fuzz_shard.assign(LINES, 3)
        self.assertEqual(sorted(len(p) for p in parts), [2, 3, 3])
        self.assertEqual(parts, fuzz_shard.assign(list(LINES), 3))

    def test_one_shard_is_everything(self):
        self.assertEqual(fuzz_shard.assign(LINES, 1), [LINES])

    def test_cli_selftest_and_shard_output(self):
        run = lambda *a: subprocess.run([sys.executable, str(HERE / "fuzz-shard.py"), *a], input="\n".join(LINES),
                                        capture_output=True, text=True)
        ok = run("--shard", "0", "--shards", "3", "--selftest")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("fuzz shard 2:", ok.stdout)
        out = run("--shard", "0", "--shards", "3")
        self.assertEqual(out.stdout.split("\n")[0].split()[0], "./internal/a")
        self.assertNotEqual(run("--shard", "3", "--shards", "3").returncode, 0)
        empty = subprocess.run([sys.executable, str(HERE / "fuzz-shard.py"), "--shard", "0", "--shards", "2"],
                               input="", capture_output=True, text=True)
        self.assertNotEqual(empty.returncode, 0)


if __name__ == "__main__":
    unittest.main()
