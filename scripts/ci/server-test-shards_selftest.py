#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Exercise the server gate's pass/fail contract without a database or Go build."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name('server-test-shards.py')
spec = importlib.util.spec_from_file_location('server_shards', SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

FAKE_GO = r'''
import json, os, pathlib, subprocess, sys, time
args = sys.argv[1:]
scenario = os.environ.get('SHARDS_SELFTEST_SCENARIO', 'success')
def emit(**fields):
    print(json.dumps(fields), flush=True)
if '-list' in args:
    if scenario == 'census_cancel':
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        pathlib.Path(os.environ['TMPDIR'], 'census-child.json').write_text(json.dumps({'parent': os.getpid(), 'child': child.pid}))
        import signal
        def finish_census(*_):
            child.wait(timeout=2)
            raise SystemExit(1)
        signal.signal(signal.SIGTERM, finish_census)
        time.sleep(30)
    for name in ['TestAlpha', 'TestBeta', 'ExampleRoundTrip', 'FuzzDecode', 'TestFairness']:
        emit(Output=name + '\n')
    raise SystemExit(1 if scenario == 'census_failure' else 0)
assert all(flag in args for flag in ['-json', '-race', '-count=1', '-p=1', '-covermode=atomic'])
assert '-coverpkg=./internal/...' in args
assert args[args.index('-skip') + 1] == '^TestFairness$'
root = pathlib.Path(os.environ['TMPDIR'])
assert root.stat().st_mode & 0o777 == 0o700
profile = pathlib.Path(next(x.split('=', 1)[1] for x in args if x.startswith('-coverprofile=')))
profile.with_suffix('.metadata.json').write_text(json.dumps({'pid': os.getpid(), 'tmp': str(root)}))
if scenario in ('hang', 'cancel'):
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    profile.with_suffix('.child.json').write_text(json.dumps({'pid': child.pid}))
    def finish(*_):
        child.wait(timeout=2)
        raise SystemExit(1)
    import signal
    signal.signal(signal.SIGTERM, finish)
    time.sleep(30)
expression = args[args.index('-run') + 1]
names = expression[2:-2].split('|')
if scenario == 'missing':
    names = names[:-1]
if scenario == 'unexpected':
    names += ['TestUnselected']
if scenario == 'duplicate':
    names += names[:1]
for name in names:
    emit(Action='run', Test=name)
    emit(Action='skip' if scenario == 'skip' and name == 'TestAlpha' else 'pass', Test=name)
if scenario != 'no_profile':
    profile.write_text(('mode: set\n' if scenario == 'bad_profile' else 'mode: atomic\n') + 'trstctl.com/trstctl/internal/test.go:1.1,1.9 1 1\n')
raise SystemExit(1 if scenario == 'child_failure' else 0)
'''

class CensusTests(unittest.TestCase):
    def test_census_includes_examples_fuzz_and_unicode(self):
        names = ['TestAlpha', 'Test名字', 'ExampleRoundTrip', 'FuzzDecode', 'TestFairness']
        got = runner.selected_tests([{'Output': name + '\n'} for name in names], '^TestFairness$')
        self.assertEqual(got, sorted(names[:-1]))

    def test_census_refuses_broader_or_missing_exclusion_and_duplicates(self):
        for names, skip in [(['TestA', 'TestB'], '^TestFairness$'),
                            (['TestA', 'TestA', 'TestFairness'], '^TestFairness$'),
                            (['TestA', 'TestB', 'TestFairness'], 'TestFairness|TestA')]:
            with self.subTest(names=names, skip=skip), self.assertRaises(ValueError):
                runner.selected_tests([{'Output': x} for x in names], skip)

    def test_timeout_is_finite_positive_and_uses_make_duration(self):
        self.assertEqual(runner.timeout_seconds('15m'), 900)
        self.assertEqual(runner.timeout_seconds('0.5s'), 0.5)
        self.assertEqual(runner.timeout_seconds('100ms'), 0.1)
        for bad in ['0s', '-1s', 'nan', 'inf', '0', '1d', '9' * 500 + 's']:
            with self.subTest(value=bad), self.assertRaises(argparse.ArgumentTypeError):
                runner.timeout_seconds(bad)

class ProcessTests(unittest.TestCase):
    def run_gate(self, scenario, timeout='3s'):
        with tempfile.TemporaryDirectory(prefix='shards-selftest-') as directory:
            root = Path(directory)
            fake = root / 'fake-go'
            fake.write_text('#!' + sys.executable + '\n' + FAKE_GO)
            fake.chmod(0o700)
            output = root / 'cover.out'
            output.write_text('stale merged profile')
            artifacts = root / 'cover.out.shards'
            artifacts.mkdir()
            for index in range(2):
                (artifacts / f'part-{index}.cover').write_text('mode: atomic\nstale.go:1.1,1.2 1 1\n')
            began = time.monotonic()
            command = [sys.executable, str(SCRIPT), '--go', str(fake),
                                     '--coverpkg', './internal/...', '--coverprofile', str(output),
                                     '--skip', '^TestFairness$', '--timeout', timeout]
            child = subprocess.Popen(command,
                                     env={**os.environ, 'SHARDS_SELFTEST_SCENARIO': scenario, 'TMPDIR': str(root)},
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if scenario == 'cancel':
                deadline = time.monotonic() + 3
                while len(list(artifacts.glob('part-*.child.json'))) < 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                child.send_signal(signal.SIGTERM)
            stdout, stderr = child.communicate(timeout=10)
            result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
            elapsed = time.monotonic() - began
            record = json.loads((artifacts / 'result.json').read_text())
            self.assertFalse(Path(record['temporary_root']).exists(), result.stdout)
            metadata = [json.loads(p.read_text()) for p in artifacts.glob('part-*.metadata.json')]
            for row in metadata:
                with self.assertRaises(ProcessLookupError):
                    os.kill(row['pid'], 0)
            for path in artifacts.glob('part-*.child.json'):
                with self.assertRaises(ProcessLookupError):
                    os.kill(json.loads(path.read_text())['pid'], 0)
            return result, record, output.read_text() if output.exists() else None, metadata, elapsed

    def test_success_preserves_flags_census_isolation_and_both_profiles(self):
        result, record, profile, metadata, _ = self.run_gate('success')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(record['success'])
        self.assertEqual(len(record['census']), 4)
        self.assertEqual(len({row['tmp'] for row in metadata}), 2)
        self.assertEqual(profile.count('mode: atomic'), 1)
        self.assertEqual(profile.count('internal/test.go'), 2)
        self.assertNotIn('stale', profile)

    def test_environment_skip_is_retained_without_disappearing_from_census(self):
        result, record, _, _, _ = self.run_gate('skip')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sum(p['terminal'] for p in record['parts']), 4)
        self.assertEqual([name for p in record['parts'] for name in p['skipped']], ['TestAlpha'])

    def test_incomplete_duplicate_unexpected_exit_and_coverage_fail_closed(self):
        for scenario in ['missing', 'duplicate', 'unexpected', 'child_failure', 'no_profile', 'bad_profile', 'census_failure']:
            with self.subTest(scenario=scenario):
                result, record, profile, _, _ = self.run_gate(scenario)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(record['success'])
                self.assertIsNone(profile)

    def test_one_short_wall_terminates_both_process_groups(self):
        result, record, profile, _, elapsed = self.run_gate('hang', '0.5s')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(record['wall_expired'])
        self.assertIsNone(profile)
        self.assertLess(elapsed, 3)

    def test_cancellation_cleans_children_and_rejects_stale_coverage(self):
        result, record, profile, _, elapsed = self.run_gate('cancel')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('canceled', record['error'])
        self.assertIsNone(profile)
        self.assertLess(elapsed, 3)


    def test_census_cancellation_stops_compilation_children(self):
        with tempfile.TemporaryDirectory(prefix='shards-census-cancel-') as directory:
            root = Path(directory)
            fake = root / 'fake-go'
            fake.write_text('#!' + sys.executable + '\n' + FAKE_GO)
            fake.chmod(0o700)
            command = [sys.executable, str(SCRIPT), '--go', str(fake),
                       '--coverpkg', './internal/...', '--coverprofile', str(root / 'cover.out'),
                       '--skip', '^TestFairness$', '--timeout', '3s']
            child = subprocess.Popen(command, env={**os.environ, 'SHARDS_SELFTEST_SCENARIO': 'census_cancel', 'TMPDIR': str(root)},
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes = {}
            try:
                marker = root / 'census-child.json'
                deadline = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists(), 'census never began')
                processes = json.loads(marker.read_text())
                child.send_signal(signal.SIGTERM)
                stdout, stderr = child.communicate(timeout=8)
                self.assertNotEqual(child.returncode, 0, stdout + stderr)
                record = json.loads((root / 'cover.out.shards/result.json').read_text())
                self.assertFalse(record['success'])
                self.assertFalse((root / 'cover.out').exists())
                for name, pid in processes.items():
                    with self.subTest(process=name), self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=3)
                # Only these exact disposable helper PIDs were created above.
                for pid in reversed(list(processes.values())):
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass

class IsolationTests(unittest.TestCase):
    def test_only_compressed_archives_are_seeded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / 'source', root / 'dest'
            cache = source / 'trstctl-pg-archives' / 'test-platform' / 'pinned-digest'
            cache.mkdir(parents=True)
            (cache / 'postgres-test.txz').write_bytes(b'public archive')
            (cache / 'postgres').write_bytes(b'executable must not be shared')
            (cache / 'postgres-link.txz').symlink_to(cache / 'postgres-test.txz')
            runner.seed_public_archives(source, destination)
            files = sorted(str(p.relative_to(destination)) for p in destination.rglob('*') if p.is_file())
            self.assertEqual(files, ['trstctl-pg-archives/test-platform/pinned-digest/postgres-test.txz'])

    def test_verified_runtime_archive_filename_is_seeded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / 'source', root / 'dest'
            relative = Path('trstctl-pg-archives') / ('linux-arm64v8-16.15.0-' + 'a' * 64) / 'embedded-postgres-binaries-linux-arm64v8-16.15.0.txz'
            archive = source / relative
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b'compressed archive; runtime verifies the pin')
            archive.chmod(0o644)
            (archive.parent / 'embedded-postgres-binaries-untrusted.txz').symlink_to(archive)
            (archive.parent / 'postgres').write_bytes(b'executable must not be shared')
            runner.seed_public_archives(source, destination)
            copied = destination / relative
            self.assertTrue(copied.is_file(), 'offline shard lost the verified runtime archive')
            self.assertEqual(copied.read_bytes(), archive.read_bytes())
            self.assertEqual(copied.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sorted(str(p.relative_to(destination)) for p in destination.rglob('*') if p.is_file()), [str(relative)])

    def test_cleanup_refuses_other_data_or_other_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pidfile = root / 'postmaster.pid'
            pidfile.write_text('123456\n/not/owned\n')
            with mock.patch.object(runner.os, 'kill') as kill, mock.patch.object(runner.subprocess, 'run') as ps:
                self.assertEqual(runner.stop_owned_databases(root), [str(pidfile)])
                kill.assert_not_called()
                ps.assert_not_called()
            pidfile.write_text(f'123456\n{root}\n')
            for command in ['/usr/bin/python -D ' + str(root), '/owned/postgres -D /other/data']:
                with mock.patch.object(runner.os, 'kill') as kill, mock.patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, command)):
                    self.assertEqual(runner.stop_owned_databases(root), [str(pidfile)])
                    kill.assert_not_called()

    def test_cleanup_stops_only_matching_owned_postmaster(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pidfile = root / 'postmaster.pid'
            pidfile.write_text(f'123456\n{root}\n')
            def stop(pid, sig):
                self.assertEqual((pid, sig), (123456, signal.SIGTERM))
                pidfile.unlink()
            with mock.patch.object(runner.os, 'kill', side_effect=stop) as kill, mock.patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '/owned/postgres -D ' + str(root))):
                self.assertEqual(runner.stop_owned_databases(root), [])
                kill.assert_called_once()

if __name__ == '__main__':
    unittest.main()
