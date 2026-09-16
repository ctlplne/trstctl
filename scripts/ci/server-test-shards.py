#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run a complete server-test census in two isolated processes under one wall.

Compilation/listing is outside the test wall, as it is for go test -timeout.
Database startup, execution, and final linking of both parts are inside it.
No result or merged coverage is accepted unless every selected top-level test,
example and fuzz seed target has exactly one start and one terminal event.
"""
import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time


def read_events(path):
    for line in Path(path).read_text().splitlines():
        try:
            yield json.loads(line)
        except ValueError:
            continue


def selected_tests(events, skip):
    # The existing fairness shard is one exact top-level test. Refuse a future
    # broader expression rather than interpreting a Go regexp with Python rules.
    match = re.fullmatch(r"\^([A-Za-z0-9_]+)\$", skip)
    if not match:
        raise ValueError("the excluded fairness test must be one anchored name")
    excluded = match.group(1)
    names = []
    for event in events:
        text = event.get("Output", "").strip()
        if re.fullmatch(r"(?:Test|Example|Fuzz)\w*", text):
            names.append(text)
    if len(names) < 3 or len(names) != len(set(names)) or excluded not in names:
        raise ValueError("compiled test census is empty, duplicated, or lacks the separate fairness test")
    return sorted(name for name in names if name != excluded)


def complete_run(events, expected):
    starts, terminal = [], []
    failed, skipped = [], []
    for event in events:
        name = event.get("Test", "")
        if not name or "/" in name:
            continue
        action = event.get("Action")
        if action == "run":
            starts.append(name)
        elif action in ("pass", "fail", "skip"):
            terminal.append(name)
            if action == "fail":
                failed.append(name)
            elif action == "skip":
                skipped.append(name)
    want = collections.Counter(expected)
    return {
        "complete": collections.Counter(starts) == want == collections.Counter(terminal),
        "expected": len(expected), "started": len(starts), "terminal": len(terminal),
        "missing": sorted(set(expected) - set(terminal)),
        "unexpected": sorted((set(starts) | set(terminal)) - set(expected)),
        "failed": failed, "skipped": skipped,
    }


def seed_public_archives(source, destination):
    # Copy compressed archives only, preserving platform/version/digest paths.
    # The product still verifies the committed digest and freshly extracts each
    # executable tree. No database, extracted program or session state is shared.
    for name in ("trstctl-pg-archives", "trstctl-pg-bin"):
        cache = source / name
        if not cache.is_dir() or cache.is_symlink():
            continue
        for archive in cache.rglob("*.txz"):
            # Verified-cache names retain the Maven artifact prefix; legacy
            # archives use the inner postgres-<platform> name.
            if not archive.name.startswith(("postgres-", "embedded-postgres-binaries-")):
                continue
            if archive.is_symlink() or not archive.is_file():
                continue
            target = destination / name / archive.relative_to(cache)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(archive, target)
            target.chmod(0o600)


def stop_owned_databases(root):
    """A timed-out Go test cannot run TestMain cleanup; stop only its exact PGs."""
    retained = []
    for pidfile in root.rglob("postmaster.pid"):
        try:
            lines = pidfile.read_text().splitlines()
            pid, data = int(lines[0]), pidfile.parent
            if pid <= 1 or pidfile.is_symlink() or pidfile.stat().st_uid != os.getuid() or Path(lines[1]).resolve() != data.resolve():
                retained.append(str(pidfile))
                continue
            process = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, check=False)
            if process.returncode:
                continue
            argv = shlex.split(process.stdout.strip())
            if not argv or Path(argv[0]).name != "postgres" or "-D" not in argv or Path(argv[argv.index("-D") + 1]).resolve() != data.resolve():
                retained.append(str(pidfile))
                continue
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while pidfile.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            if pidfile.exists():
                retained.append(str(pidfile))
        except (OSError, ValueError, IndexError):
            retained.append(str(pidfile))
    return retained


def timeout_seconds(value):
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", value)
    if not match:
        raise argparse.ArgumentTypeError("timeout must be a positive duration such as 15m or 0.5s")
    seconds = float(match.group(1)) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[match.group(2)]
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return seconds


def signal_group(child, sig):
    try:
        os.killpg(child.pid, sig)
    except ProcessLookupError:
        pass


def cancel_run(_signum, _frame):
    raise KeyboardInterrupt("server test run cancelled")


def run(args):
    output = Path(args.coverprofile).resolve()
    artifacts = output.with_name(output.name + ".shards")
    artifacts.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    # Short roots matter on macOS, where Unix socket paths are bounded to 104
    # bytes. Each Go process, signer helper and database has its own namespace.
    scratch = Path(tempfile.mkdtemp(prefix="trstctl-tests-", dir="/tmp")).resolve()
    commands = []
    children = []
    record = {"wall_seconds": args.seconds, "workers": 2, "package": args.package, "parts": [], "temporary_root": str(scratch)}
    base = [args.go, "test", "-json", "-race", "-count=1", "-p=1", "-covermode=atomic", "-coverpkg=" + args.coverpkg]
    success = False
    previous_signals = {sig: signal.signal(sig, cancel_run) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        census = artifacts / "census.ndjson"
        began = time.monotonic()
        with census.open("w") as log:
            census_child = subprocess.Popen(base + ["-list", "^(Test|Example|Fuzz)", args.package], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            children.append(census_child)
            census_exit = census_child.wait()
        if census_exit:
            raise RuntimeError("test census compilation failed: " + str(census))
        names = selected_tests(read_events(census), args.skip)
        groups = [names[::2], names[1::2]]
        record.update(census_seconds=time.monotonic() - began, census=names, partitions=groups,
                      census_sha256=hashlib.sha256(census.read_bytes()).hexdigest())
        print(f">> server census: {len(names)} selected tests, two isolated parts, one {args.seconds:g}s wall", flush=True)
        for index in range(2):
            root = scratch / str(index)
            root.mkdir(mode=0o700)
            seed_public_archives(Path(tempfile.gettempdir()), root)
        began = time.monotonic()
        deadline = began + args.seconds
        for index, names in enumerate(groups):
            logpath = artifacts / f"part-{index}.ndjson"
            profile = artifacts / f"part-{index}.cover"
            profile.unlink(missing_ok=True)
            env = {**os.environ, "TMPDIR": str(scratch / str(index))}
            expression = "^(" + "|".join(names) + ")$"
            command = base + ["-coverprofile=" + str(profile), "-run", expression, "-skip", args.skip, f"-timeout={args.seconds}s", args.package]
            log = logpath.open("w")
            child = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            children.append(child)
            commands.append((child, log, logpath, profile, names))
        while any(child.poll() is None for child, *_ in commands) and time.monotonic() < deadline:
            time.sleep(0.1)
        expired = any(child.poll() is None for child, *_ in commands)
        record["wall_expired"] = expired
        for child, *_ in commands:
            if child.poll() is None:
                signal_group(child, signal.SIGTERM)
        for child, log, logpath, profile, expected in commands:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                signal_group(child, signal.SIGKILL)
                child.wait()
            log.close()
            part = complete_run(read_events(logpath), expected)
            part.update(exit=child.returncode, log=str(logpath), log_sha256=hashlib.sha256(logpath.read_bytes()).hexdigest())
            body = profile.read_text() if profile.exists() else ""
            part["coverage_valid"] = body.startswith("mode: atomic\n") and len(body.splitlines()) > 1
            record["parts"].append(part)
            print(f">> server part: exit={child.returncode}, completed={part['terminal']}/{part['expected']}, failures={part['failed']}, log={logpath}", flush=True)
        record["execution_seconds"] = time.monotonic() - began
        success = not expired and all(p["exit"] == 0 and p["complete"] and not p["failed"] and p["coverage_valid"] for p in record["parts"])
        if success:
            # Existing make-test normalization merges repeated coverage blocks
            # across all its lanes; retain both complete first-party profiles.
            merged = "mode: atomic\n" + "".join("".join(profile.read_text().splitlines(keepends=True)[1:]) for _, _, _, profile, _ in commands)
            temporary = output.with_name(output.name + ".tmp")
            temporary.write_text(merged)
            temporary.replace(output)
    except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as error:
        record["error"] = str(error)
        print("FAIL: server test parts: " + str(error), flush=True)
    finally:
        # A second cancellation must not interrupt cleanup of owned processes.
        for sig in previous_signals:
            signal.signal(sig, signal.SIG_IGN)
        for child in children:
            if child.poll() is None:
                signal_group(child, signal.SIGTERM)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    signal_group(child, signal.SIGKILL)
                    child.wait()
        for _, log, *_ in commands:
            log.close()
        retained = stop_owned_databases(scratch)
        record["retained_databases"] = retained
        success = success and not retained
        if not retained:
            try:
                shutil.rmtree(scratch)
            except OSError as error:
                record["cleanup_error"] = str(error)
                success = False
        if not success:
            output.unlink(missing_ok=True)
        record["success"] = success
        (artifacts / "result.json").write_text(json.dumps(record, indent=2) + "\n")
        for sig, previous in previous_signals.items():
            signal.signal(sig, previous)
    return 0 if success else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--package", default="./internal/server")
    parser.add_argument("--coverpkg", required=True)
    parser.add_argument("--coverprofile", required=True)
    parser.add_argument("--skip", required=True)
    parser.add_argument("--timeout", dest="seconds", type=timeout_seconds, default="15m")
    options = parser.parse_args()
    raise SystemExit(run(options))
