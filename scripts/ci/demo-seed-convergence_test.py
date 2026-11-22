#!/usr/bin/env python3
"""Exercise the preserved-volume check with retrying notifications."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("demo-seed-convergence.sh")


class DemoSeedConvergenceTest(unittest.TestCase):
    def run_convergence(self, *, notification_destination="notification.expiry", other_active=False, host_processing=False, agent_present=False, event_on_rerun=False, late_background_event=False, continuous_background_events=False, stream_rollback=False, background_event_on_rerun=False, background_outbox_after_rerun=False, seed_outbox_on_rerun=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(
                """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
if args[:2] == ['inspect', '--format']:
    print('exited' if 'Status' in args[2] else '0')
elif 'ps' in args:
    print('seed-container')
elif 'exec' in args and 'postgres' in args:
    sql = args[args.index('-c') + 1]
    outbox_count = 1
    if Path(os.environ['FAKE_DOCKER_STATE']).exists():
        counter = Path(os.environ['FAKE_DOCKER_STATE'] + '.postgres_reads')
        reads = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(reads))
        if os.environ.get('FAKE_SEED_OUTBOX_ON_RERUN') == '1' or (
                os.environ.get('FAKE_BACKGROUND_OUTBOX_AFTER_RERUN') == '1' and reads > 1):
            outbox_count = 2
    # Model one pending, unconfigured notification row and no other active work.
    active = int(os.environ.get('FAKE_OTHER_ACTIVE', '0'))
    destination = os.environ.get('FAKE_NOTIFICATION_DESTINATION', 'notification.expiry')
    excluded = "destination LIKE 'notification.%'" in sql or (destination == 'notification.expiry' and \
            "destination = 'notification.expiry'" in sql)
    if not excluded or "last_error = 'notification_receiver_not_configured'" not in sql:
        active += 1
    if os.environ.get('FAKE_HOST_PROCESSING') == '1':
        # A host deployment cannot finish before a host agent is enrolled.
        no_agent = os.environ.get('FAKE_AGENT_PRESENT') != '1'
        narrow_exclusion = all(fragment in sql for fragment in (
            "o.destination = 'connector.deploy'", "o.required_agent_role = 'host'",
            "a.tenant_id = o.tenant_id", "a.status <> 'offboarded'"))
        if not (no_agent and narrow_exclusion):
            active += 1
    print(json.dumps(dict(owners=[], owner_count=0, owner_logical_count=0,
        identities=[], certificates=0, members=[], secrets=[],
        api_token_count=0, outbox_count=outbox_count, outbox_active_retry_count=active)))
elif 'exec' in args and 'nats' in args:
    count = 8 if os.environ.get('FAKE_EVENT_ON_RERUN') == '1' and Path(os.environ['FAKE_DOCKER_STATE']).exists() else 7
    if os.environ.get('FAKE_BACKGROUND_EVENT_ON_RERUN') == '1' and Path(os.environ['FAKE_DOCKER_STATE']).exists():
        count = 8
    if any(os.environ.get(name) == '1' for name in ('FAKE_LATE_BACKGROUND_EVENT',
            'FAKE_CONTINUOUS_BACKGROUND_EVENTS', 'FAKE_STREAM_ROLLBACK')):
        counter = Path(os.environ['FAKE_DOCKER_STATE'] + '.nats_reads')
        reads = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(reads))
        if os.environ.get('FAKE_CONTINUOUS_BACKGROUND_EVENTS') == '1':
            count += reads
        elif os.environ.get('FAKE_STREAM_ROLLBACK') == '1':
            count = 8 if reads <= 3 else 7
        elif reads > 3:
            count = 8
    print(json.dumps({'account_details': [{'stream_detail': [
        {'config': {'name': 'TRSTCTL_EVENTS'}, 'state': {'messages': count}},
        {'config': {'name': 'TRSTCTL_EVENT_ID_INDEX'}, 'state': {'messages': 2}},
    ]}]}))
elif 'run' in args and '--entrypoint' in args:
    # The seed's actor-attributed event changes only for a seed-caused append.
    ids = ['seed-event-before']
    if os.environ.get('FAKE_EVENT_ON_RERUN') == '1' and Path(os.environ['FAKE_DOCKER_STATE']).exists():
        ids.append('seed-event-after')
    print(json.dumps(ids))
elif 'run' in args:
    Path(os.environ['FAKE_DOCKER_STATE']).touch()
else:
    raise SystemExit('unexpected docker command: ' + repr(args))
"""
            )
            docker.chmod(0o755)
            (root / "seq").write_text("#!/bin/sh\n/usr/bin/seq 1 100\n")
            (root / "sleep").write_text("#!/bin/sh\nexit 0\n")
            (root / "seq").chmod(0o755)
            (root / "sleep").chmod(0o755)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "FAKE_OTHER_ACTIVE": str(int(other_active)),
                   "FAKE_HOST_PROCESSING": str(int(host_processing)),
                   "FAKE_AGENT_PRESENT": str(int(agent_present)),
                   "FAKE_NOTIFICATION_DESTINATION": notification_destination,
                   "FAKE_EVENT_ON_RERUN": str(int(event_on_rerun)),
                   "FAKE_LATE_BACKGROUND_EVENT": str(int(late_background_event)),
                   "FAKE_CONTINUOUS_BACKGROUND_EVENTS": str(int(continuous_background_events)),
                   "FAKE_STREAM_ROLLBACK": str(int(stream_rollback)),
                   "FAKE_BACKGROUND_EVENT_ON_RERUN": str(int(background_event_on_rerun)),
                   "FAKE_BACKGROUND_OUTBOX_AFTER_RERUN": str(int(background_outbox_after_rerun)),
                   "FAKE_SEED_OUTBOX_ON_RERUN": str(int(seed_outbox_on_rerun)),
                   "FAKE_DOCKER_STATE": str(root / "reran")}
            return subprocess.run(
                ["bash", str(SCRIPT)], env=env, text=True,
                capture_output=True, timeout=20, check=False,
            )

    def test_unconfigured_expiry_retry_does_not_block_seed_checkpoint(self):
        result = self.run_convergence()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("convergence passed", result.stdout)

    def test_unconfigured_risk_retry_does_not_block_seed_checkpoint(self):
        result = self.run_convergence(notification_destination="notification.risk")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("convergence passed", result.stdout)

    def test_other_active_work_still_blocks_checkpoint(self):
        result = self.run_convergence(other_active=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not reach a stable", result.stderr)

    def test_processing_host_deployment_without_agent_does_not_block_seed_checkpoint(self):
        result = self.run_convergence(host_processing=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_processing_host_deployment_with_agent_still_blocks_checkpoint(self):
        result = self.run_convergence(host_processing=True, agent_present=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not reach a stable", result.stderr)

    def test_jetstream_event_change_still_fails_seed_checkpoint(self):
        result = self.run_convergence(event_on_rerun=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("seed snapshot changed", result.stderr)
        self.assertIn('"TRSTCTL_EVENTS": 7', result.stdout)
        self.assertIn('"TRSTCTL_EVENTS": 8', result.stdout)

    def test_checkpoint_waits_through_delayed_background_event(self):
        result = self.run_convergence(late_background_event=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_continuous_background_events_do_not_hide_settled_seed(self):
        result = self.run_convergence(continuous_background_events=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_checkpoint_refuses_a_stream_count_rollback(self):
        result = self.run_convergence(stream_rollback=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("event stream regressed", result.stderr)

    def test_background_event_after_seed_rerun_does_not_implicate_seed(self):
        result = self.run_convergence(background_event_on_rerun=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_background_outbox_after_replay_does_not_implicate_seed(self):
        result = self.run_convergence(background_outbox_after_rerun=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_seed_outbox_insert_during_replay_still_fails(self):
        result = self.run_convergence(seed_outbox_on_rerun=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("seed snapshot changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
