#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise the fuzz outcome classifier: only the coordinator's own deadline after the budget passes."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("fuzz_outcome", HERE / "fuzz-outcome.py")
fuzz_outcome = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fuzz_outcome)

# CI 41571974614, fuzz / targets 2, verbatim apart from timestamps.
DEADLINE = """fuzz: elapsed: 0s, gathering baseline coverage: 0/4 completed
fuzz: elapsed: 0s, gathering baseline coverage: 4/4 completed, now fuzzing with 1 workers
fuzz: elapsed: 3s, execs: 39113 (13037/sec), new interesting: 4 (total: 8)
fuzz: elapsed: 15s, execs: 236484 (14264/sec), new interesting: 15 (total: 19)
fuzz: elapsed: 16s, execs: 236484 (0/sec), new interesting: 15 (total: 19)
--- FAIL: FuzzDestructionClaims (16.01s)
    context deadline exceeded
FAIL
exit status 1
FAIL\ttrstctl.com/trstctl/internal/eventprotect\t16.019s
"""

CRASH = """fuzz: elapsed: 3s, execs: 1200 (400/sec), new interesting: 2 (total: 6)
fuzz: minimizing 48-byte failing input file
fuzz: elapsed: 4s, minimizing
--- FAIL: FuzzParse (4.10s)
    --- FAIL: FuzzParse (0.00s)
        testing.go:1591: panic: runtime error: index out of range [3] with length 3

    Failing input written to testdata/fuzz/FuzzParse/4f2a
    To re-run:
    go test -run=FuzzParse/4f2a
FAIL
exit status 1
FAIL\ttrstctl.com/trstctl/internal/x\t4.2s
"""


class FuzzOutcomeTests(unittest.TestCase):
    def test_a_passing_run_passes(self):
        self.assertTrue(fuzz_outcome.classify("FuzzA", 0, "ok\n", "15s")[0])

    def test_the_coordinators_own_deadline_after_the_budget_completes(self):
        completed, reason = fuzz_outcome.classify("FuzzDestructionClaims", 1, DEADLINE, "15s")
        self.assertTrue(completed, reason)
        self.assertIn("CI-L25", reason)

    def test_a_crasher_fails(self):
        self.assertFalse(fuzz_outcome.classify("FuzzParse", 1, CRASH, "15s")[0])

    def test_the_deadline_before_the_budget_fails(self):
        self.assertFalse(fuzz_outcome.classify("FuzzDestructionClaims", 1, DEADLINE, "30s")[0])

    def test_another_target_or_message_fails(self):
        self.assertFalse(fuzz_outcome.classify("FuzzOther", 1, DEADLINE, "15s")[0])
        self.assertFalse(fuzz_outcome.classify("FuzzDestructionClaims", 1,
                                               DEADLINE.replace("context deadline exceeded", "seed#0 failed"), "15s")[0])

    def test_anything_after_the_deadline_line_fails(self):
        extra = DEADLINE.replace("FAIL\nexit status 1", "    fuzz_test.go:12: boom\nFAIL\nexit status 1")
        self.assertFalse(fuzz_outcome.classify("FuzzDestructionClaims", 1, extra, "15s")[0])
        failing = DEADLINE.replace("FAIL\nexit status 1", "    Failing input written to testdata/fuzz/x\nFAIL\nexit status 1")
        self.assertFalse(fuzz_outcome.classify("FuzzDestructionClaims", 1, failing, "15s")[0])

    def test_a_build_error_fails(self):
        self.assertFalse(fuzz_outcome.classify("FuzzA", 1, "# pkg\n./a_test.go:3:1: syntax error\nFAIL\tpkg [build failed]\n", "15s")[0])

    def test_minute_budgets(self):
        self.assertEqual(fuzz_outcome.budget_seconds("2m"), 120)
        with self.assertRaises(ValueError):
            fuzz_outcome.budget_seconds("1h")


if __name__ == "__main__":
    unittest.main()
