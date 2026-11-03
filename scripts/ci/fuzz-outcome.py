#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Classify one `go test -fuzz` run of the fuzz smoke (CI-L25).

Go's fuzz coordinator can report its own -fuzztime deadline as a failure: when
the budget ends it compares the expired context's error with its workers'
child context before that child is cancelled, and returns "context deadline
exceeded" with no failing input (CI: FuzzParseWrappedDomainKEK, FuzzResolve,
FuzzDestructionClaims). Exactly that shape, after the whole budget, counts as
completed. Every other non-zero exit fails: a crasher, a panic, a seed or
subtest failure, a build error, or a deadline before the budget ran out.
"""
import argparse
import re
import sys

ELAPSED = re.compile(r"^fuzz: elapsed: (\d+)s,")
BOILERPLATE = re.compile(r"^(FAIL|exit status 1|FAIL\t\S+\t[0-9.]+s)$")
FAILURE_MARKERS = ("Failing input written to", "panic:", "fuzz: minimizing", "--- FAIL: Fuzz")


def budget_seconds(budget):
    match = re.fullmatch(r"(\d+)(s|m)", budget)
    if not match:
        raise ValueError(f"unsupported fuzz budget {budget!r} (want Ns or Nm)")
    return int(match.group(1)) * (60 if match.group(2) == "m" else 1)


def classify(target, status, output, budget):
    """Return (completed, reason)."""
    if status == 0:
        return True, "passed"
    lines = output.splitlines()
    header = re.compile(r"^--- FAIL: " + re.escape(target) + r" \((\d+(?:\.\d+)?)s\)$")
    fails = [i for i, line in enumerate(lines) if line.startswith("--- FAIL:")]
    if len(fails) != 1 or not header.match(lines[fails[0]]):
        return False, "the target failed"
    first = fails[0]
    if lines[first + 1:first + 2] != ["    context deadline exceeded"]:
        return False, "the target failed"
    if any(marker in line for line in lines[:first] + lines[first + 2:] for marker in FAILURE_MARKERS):
        return False, "the target failed"
    if not all(BOILERPLATE.match(line) for line in lines[first + 2:] if line.strip()):
        return False, "the target failed"
    elapsed = [int(m.group(1)) for m in map(ELAPSED.match, lines[:first]) if m]
    ran = float(header.match(lines[first]).group(1))
    need = budget_seconds(budget)
    if not elapsed or max(elapsed) < need or ran < need:
        return False, "the deadline came before the budget ran out"
    return True, ("the Go fuzz coordinator reported its own -fuzztime deadline after the full "
                  f"{budget} budget with no failing input (CI-L25); counted as completed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--status", type=int, required=True)
    parser.add_argument("--budget", required=True)
    args = parser.parse_args()
    completed, reason = classify(args.target, args.status, sys.stdin.read(), args.budget)
    if args.status != 0 and completed:
        print(f"::notice::{args.target}: {reason}")
    if not completed:
        print(f"{args.target}: {reason}", file=sys.stderr)
    return 0 if completed else 1


if __name__ == "__main__":
    sys.exit(main())
