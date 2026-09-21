#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Require a complete golangci-lint JSON scan before comparing the EE baseline."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

REQUIRED_LINTERS = {"errcheck", "govet", "ineffassign", "staticcheck", "unused", "gosec"}
MAX_REPORT_BYTES = 64 * 1024 * 1024


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field: " + key)
        value[key] = item
    return value


def reject_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def run_scanner(command, timeout=1530):
    """Bound output and supervise the scanner's children on every exit path."""
    if os.name != "posix":
        raise ValueError("EE scanner supervision requires POSIX process groups")
    cancelled = 0
    previous = {}
    process = None

    def cancel(signum, _frame):
        nonlocal cancelled
        cancelled = signum

    def group_exists():
        process.poll()  # Reap the leader before probing its surviving children.
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def stop_group():
        # A separate scanner group prevents signaling Make or unrelated tools.
        # Forward cancellation promptly: an outer supervisor may escalate after
        # 150 ms. Escalate even when the scanner leader has already exited.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            process.poll()
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            if sig == signal.SIGTERM:
                time.sleep(0.025)
        process.wait(timeout=3)

    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostics:
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, cancel)
            process = subprocess.Popen(command, stdout=output, stderr=diagnostics,
                                       start_new_session=True)
            started = time.monotonic()
            while True:
                if cancelled:
                    raise ValueError("scanner canceled by signal " + str(cancelled))
                if os.fstat(output.fileno()).st_size + os.fstat(diagnostics.fileno()).st_size > MAX_REPORT_BYTES:
                    raise ValueError("scanner output exceeds 64 MiB")
                if process.poll() is not None:
                    # A final write can race the preceding output-size check.
                    if os.fstat(output.fileno()).st_size + os.fstat(diagnostics.fileno()).st_size > MAX_REPORT_BYTES:
                        raise ValueError("scanner output exceeds 64 MiB")
                    if group_exists():
                        raise ValueError("scanner exited with surviving children")
                    break
                if time.monotonic() - started >= timeout:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(0.01)
        finally:
            try:
                if process is not None and (process.poll() is None or group_exists()):
                    stop_group()
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
                output.seek(0)
                raw = output.read(MAX_REPORT_BYTES)
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
                diagnostics.seek(0)
                sys.stderr.buffer.write(diagnostics.read(MAX_REPORT_BYTES - len(raw)))
                sys.stderr.buffer.flush()
    return process.returncode, raw


def issue_count(report, exit_code):
    if not isinstance(report, dict) or not isinstance(report.get("Issues"), list):
        raise ValueError("missing or malformed Issues list")
    metadata = report.get("Report")
    if not isinstance(metadata, dict):
        raise ValueError("scanner report metadata is missing")
    error, warnings = metadata.get("Error", ""), metadata.get("Warnings", [])
    if not isinstance(error, str) or not isinstance(warnings, list) or any(
        not isinstance(warning, str) for warning in warnings
    ):
        raise ValueError("scanner report has malformed error/warning fields")
    if error or warnings:
        raise ValueError("scanner report is missing or records an error/warning")
    linters = metadata.get("Linters")
    if not isinstance(linters, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("Name"), str)
        or type(item.get("Enabled", False)) is not bool for item in linters
    ):
        raise ValueError("report has malformed linter identities")
    enabled = {item["Name"] for item in linters if item.get("Enabled") is True}
    if not REQUIRED_LINTERS.issubset(enabled):
        raise ValueError("report omits required enabled linters: " + ", ".join(sorted(REQUIRED_LINTERS - enabled)))
    for item in report["Issues"]:
        if (not isinstance(item, dict) or not isinstance(item.get("FromLinter"), str)
                or not item["FromLinter"] or not isinstance(item.get("Text"), str) or not item["Text"]):
            raise ValueError("malformed issue")
        position = item.get("Pos")
        if (not isinstance(position, dict) or not isinstance(position.get("Filename"), str)
                or not position["Filename"] or type(position.get("Line")) is not int
                or position["Line"] < 1):
            raise ValueError("issue has no valid source position")
    count = len(report["Issues"])
    if exit_code != (1 if count else 0):
        raise ValueError("scanner exit status disagrees with reported findings")
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    try:
        if not command:
            raise ValueError("scanner command required")
        with args.baseline.open("r", encoding="ascii") as source:
            raw_baseline = source.read(1025)
        if len(raw_baseline) > 1024:
            raise ValueError("baseline exceeds 1024 bytes")
        text = raw_baseline.strip()
        if not re.fullmatch(r"[0-9]{1,12}", text):
            raise ValueError("baseline must be a bare nonnegative count")
        baseline = int(text)
        exit_code, raw = run_scanner(command)
        if exit_code not in (0, 1):
            raise ValueError("scanner failed with exit status " + str(exit_code))
        report = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
        count = issue_count(report, exit_code)
        print("ee/ findings: {} (baseline {})".format(count, baseline))
        if count > baseline:
            raise ValueError("EE findings grew; fix findings without raising the baseline")
        if count < baseline:
            print("Baseline can tighten to {}; review and commit that change separately.".format(count))
        return 0
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as exc:
        print("FAIL: EE lint did not qualify: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
