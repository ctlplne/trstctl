#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Run a complete server-test census in two isolated processes under one wall.

Compilation/listing is outside the test wall, as it is for go test -timeout.
Database startup, execution, and final linking of both parts are inside it.
No result or merged coverage is accepted unless every selected top-level test,
example and fuzz seed target has exactly one start and one terminal event.

With --slice i --slices N a CI job runs only its share of the census (every
N-th name of the sorted census, from i), still in isolated parts under the
same accounting; --verify-slices then checks that the jobs' results ran one
census completely, each name in exactly one slice.
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


def census_digest(names):
    """The census identity every slice must agree on: its sorted test names (the raw listing carries timestamps)."""
    return hashlib.sha256("\n".join(names).encode()).hexdigest()


def slice_census(names, index, count):
    """This job's share of the census: every count-th name of the sorted census, from index."""
    if count < 1 or not 0 <= index < count:
        raise ValueError("--slice must be in [0, --slices)")
    return names[index::count]


def verify_slices(paths):
    """Check that slice results ran one census completely, each name in exactly one slice."""
    records = [json.loads(Path(p).read_text()) for p in paths]
    if not records:
        raise ValueError("no slice results")
    counts = {r.get("slices", 1) for r in records}
    digests = {r.get("census_sha256") for r in records}
    if len(counts) != 1 or len(digests) != 1 or None in digests:
        raise ValueError("slice results disagree on the census or the slice count")
    if len({r.get("test_binary_sha256") for r in records}) != 1:
        raise ValueError("slice results ran different test binaries")
    if any(census_digest(r.get("census", [])) != r["census_sha256"] for r in records):
        raise ValueError("a slice result's census does not match its digest")
    count = counts.pop()
    indices = sorted(r.get("slice", 0) for r in records)
    if indices != list(range(count)):
        raise ValueError(f"slice results {indices} are not exactly slices 0..{count - 1}")
    if not all(r.get("success") for r in records):
        raise ValueError("a slice did not complete successfully")
    census = records[0]["census"]
    union = collections.Counter(name for r in records for name in r.get("selected", []))
    if union != collections.Counter(census):
        raise ValueError("the slices' tests are not exactly the census, each once")
    return len(census), count


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


FAILURE_LINE = re.compile(r"\w\.go:\d+:|panic:|--- FAIL")


def failure_output(events, failed, limit=80, messages=40):
    """Each failed test's output (subtests included), in order: its first `messages` failure
    lines (file:line reports, panics, --- FAIL) wherever they are, and its last `limit` lines."""
    wanted = set(failed)
    lines = collections.defaultdict(list)
    for event in events:
        name = event.get("Test", "")
        if event.get("Action") == "output" and name.split("/", 1)[0] in wanted:
            lines[name.split("/", 1)[0]].append(event.get("Output", "").rstrip("\n"))
    out = {}
    for name in failed:
        text = lines[name]
        keep = {i for i, line in enumerate(text) if FAILURE_LINE.search(line)}
        keep = set(sorted(keep)[:messages]) | set(range(max(0, len(text) - limit), len(text)))
        out[name] = [text[i] for i in sorted(keep)]
    return out


def seed_public_archives(source, destination, library_cache=None):
    # Copy compressed archives only, preserving platform/version/digest paths.
    # The product still verifies the committed digest and freshly extracts each
    # executable tree. No database, extracted program or session state is shared.
    # The embedded-postgres library's own cache (~/.embedded-postgres-go, which
    # CI restores) holds the same pinned archive under the name the product
    # reads as its legacy source (trstctl-pg-bin/), so it is seeded there too:
    # without it every part downloaded the archive again, and parallel lanes
    # drew HTTP 429 from the archive host (CI run 41479056374).
    if library_cache is not None and library_cache.is_dir() and not library_cache.is_symlink():
        for archive in library_cache.glob("embedded-postgres-binaries-*.txz"):
            if archive.is_symlink() or not archive.is_file():
                continue
            target = destination / "trstctl-pg-bin" / archive.name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(archive, target)
            target.chmod(0o600)
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
    raise KeyboardInterrupt("server test run canceled")


def test_commands(args):
    """How the census and each part run: `go test` over the package, or a prebuilt race + coverage test binary
    (--test-binary, built once for every CI slice) run in the package directory through test2json, as go test itself
    runs it. Returns the census command, a part-command builder, the children's working directory, environment
    overrides for them, and the binary's digest (None for go test)."""
    if not args.test_binary:
        base = [args.go, "test", "-json", "-race", "-count=1", "-p=1", "-covermode=atomic", "-coverpkg=" + args.coverpkg]

        def part(profile, expression, executable=None):
            # go test builds a private binary for each part itself.
            return base + ["-coverprofile=" + str(profile), "-run", expression, "-skip", args.skip, f"-timeout={args.seconds}s", args.package]
        return base + ["-list", "^(Test|Example|Fuzz)", args.package], part, None, {}, None
    if not args.import_path:
        raise ValueError("--test-binary needs --import-path")
    binary = Path(args.test_binary).resolve()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    workdir = str(Path(args.package).resolve())
    # go test puts its own toolchain's bin first on PATH (and sets GOROOT) for the
    # test process, so a test that runs `go build` gets the matching compiler; do
    # the same, resolving the module's toolchain from the package directory.
    goroot = subprocess.run([args.go, "env", "GOROOT"], cwd=workdir, capture_output=True, text=True, check=True).stdout.strip()
    if not goroot:
        raise ValueError("go env GOROOT is empty")
    overrides = {"GOROOT": goroot, "PATH": os.path.join(goroot, "bin") + os.pathsep + os.environ.get("PATH", "")}
    wrap = [args.go, "tool", "test2json", "-t", "-p", args.import_path, str(binary), "-test.v=test2json"]

    def part(profile, expression, executable=None):
        command = list(wrap)
        if executable is not None:
            command[command.index(str(binary))] = str(executable)
        return command + ["-test.count=1", "-test.paniconexit0", "-test.coverprofile=" + str(profile), "-test.run=" + expression,
                          "-test.skip=" + args.skip, f"-test.timeout={args.seconds}s"]
    return wrap + ["-test.list", "^(Test|Example|Fuzz)"], part, workdir, overrides, digest


def private_test_binary(binary, root):
    """A part's own name for the prebuilt test binary, in its private scratch. The product starts its signer as a
    sibling of its own executable, and tests build that sibling next to the test binary and remove it afterwards
    (installSiblingSignerBinary); parts sharing one binary directory removed the signer another part was starting
    ("fork/exec .../trstctl-signer: no such file", CI run 41479056374). A hard link costs no space; a copy is the
    fallback across file systems."""
    directory = root / "bin"
    directory.mkdir(mode=0o700)
    target = directory / binary.name
    try:
        os.link(binary, target)
    except OSError:
        shutil.copy2(binary, target)
    return target


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
    record = {"wall_seconds": args.seconds, "workers": 2, "package": args.package, "parts": [], "temporary_root": str(scratch),
              "slice": args.slice, "slices": args.slices}
    listing, part_command, workdir, overrides, binary_digest = test_commands(args)
    record["test_binary_sha256"] = binary_digest
    success = False
    previous_signals = {sig: signal.signal(sig, cancel_run) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        census = artifacts / "census.ndjson"
        began = time.monotonic()
        with census.open("w") as log:
            census_child = subprocess.Popen(listing, cwd=workdir, env={**os.environ, **overrides}, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            children.append(census_child)
            census_exit = census_child.wait()
        if census_exit:
            raise RuntimeError("test census compilation failed: " + str(census))
        names = selected_tests(read_events(census), args.skip)
        selected = slice_census(names, args.slice, args.slices)
        groups = [group for group in (selected[::2], selected[1::2]) if group]
        record.update(census_seconds=time.monotonic() - began, census=names, selected=selected, partitions=groups,
                      workers=len(groups), census_sha256=census_digest(names))
        print(f">> server census: {len(names)} selected tests; slice index {args.slice} of {args.slices}: {len(selected)} tests "
              f"in {len(groups)} isolated parts, one {args.seconds:g}s wall", flush=True)
        for index in range(len(groups)):
            root = scratch / str(index)
            root.mkdir(mode=0o700)
            seed_public_archives(Path(tempfile.gettempdir()), root, Path.home() / ".embedded-postgres-go")
        binaries = {}
        if args.test_binary:
            binaries = {index: private_test_binary(Path(args.test_binary).resolve(), scratch / str(index)) for index in range(len(groups))}
        seeded = sorted(str(p.relative_to(scratch / "0")) for p in (scratch / "0").rglob("*.txz")) if groups else []
        print(f">> seeded public PostgreSQL archives into each part: {', '.join(seeded) or 'none (each part downloads its own)'}", flush=True)
        began = time.monotonic()
        deadline = began + args.seconds
        for index, names in enumerate(groups):
            logpath = artifacts / f"part-{index}.ndjson"
            profile = artifacts / f"part-{index}.cover"
            profile.unlink(missing_ok=True)
            env = {**os.environ, **overrides, "TMPDIR": str(scratch / str(index))}
            expression = "^(" + "|".join(names) + ")$"
            command = part_command(profile, expression, binaries.get(index))
            log = logpath.open("w")
            child = subprocess.Popen(command, cwd=workdir, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
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
            # A CI log is often all there is of a failure: print each failed test's own output.
            for name, lines in failure_output(read_events(logpath), part["failed"]).items():
                print(f"--- FAIL: {name} (last {len(lines)} output lines)", flush=True)
                for line in lines:
                    print("    " + line, flush=True)
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
    parser.add_argument("--coverpkg")
    parser.add_argument("--coverprofile")
    parser.add_argument("--skip")
    parser.add_argument("--timeout", dest="seconds", type=timeout_seconds, default="15m")
    parser.add_argument("--slice", type=int, default=0)
    parser.add_argument("--slices", type=int, default=1)
    parser.add_argument("--test-binary", help="a prebuilt race + coverage test binary of --package (CI builds it once for every slice)")
    parser.add_argument("--import-path", help="the package's import path, for test2json (with --test-binary)")
    parser.add_argument("--verify-slices", nargs="+", metavar="RESULT_JSON")
    options = parser.parse_args()
    if options.verify_slices:
        try:
            tests, slices = verify_slices(options.verify_slices)
        except (OSError, ValueError, KeyError) as error:
            raise SystemExit("FAIL: server test slices: " + str(error))
        print(f">> server census complete across {slices} slices: {tests} tests, each run exactly once")
        raise SystemExit(0)
    for name in ("coverpkg", "coverprofile", "skip"):
        if not getattr(options, name):
            parser.error(f"--{name} is required")
    raise SystemExit(run(options))
