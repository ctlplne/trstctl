#!/usr/bin/env python3
"""Exercise the preserved-volume check with retrying notifications."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("demo-seed-convergence.sh")


class DemoSeedConvergenceTest(unittest.TestCase):
    def run_convergence(self, *, notification_destination="notification.expiry", other_active=False, event_on_rerun=False):
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
    # Model one pending, unconfigured notification row and no other active work.
    active = int(os.environ.get('FAKE_OTHER_ACTIVE', '0'))
    destination = os.environ.get('FAKE_NOTIFICATION_DESTINATION', 'notification.expiry')
    excluded = "destination LIKE 'notification.%'" in sql or (destination == 'notification.expiry' and \
            "destination = 'notification.expiry'" in sql)
    if not excluded or "last_error = 'notification_receiver_not_configured'" not in sql:
        active += 1
    print(json.dumps(dict(owners=[], owner_count=0, owner_logical_count=0,
        identities=[], certificates=0, members=[], secrets=[],
        api_token_count=0, outbox_count=1, outbox_active_retry_count=active)))
elif 'exec' in args and 'nats' in args:
    count = 8 if os.environ.get('FAKE_EVENT_ON_RERUN') == '1' and Path(os.environ['FAKE_DOCKER_STATE']).exists() else 7
    print(json.dumps({'account_details': [{'stream_detail': [
        {'config': {'name': 'TRSTCTL_EVENTS'}, 'state': {'messages': count}},
        {'config': {'name': 'TRSTCTL_EVENT_ID_INDEX'}, 'state': {'messages': 2}},
    ]}]}))
elif 'run' in args:
    Path(os.environ['FAKE_DOCKER_STATE']).touch()
else:
    raise SystemExit('unexpected docker command: ' + repr(args))
"""
            )
            docker.chmod(0o755)
            (root / "seq").write_text("#!/bin/sh\nprintf '1\\n2\\n3\\n4\\n'\n")
            (root / "sleep").write_text("#!/bin/sh\nexit 0\n")
            (root / "seq").chmod(0o755)
            (root / "sleep").chmod(0o755)
            env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "FAKE_OTHER_ACTIVE": str(int(other_active)),
                   "FAKE_NOTIFICATION_DESTINATION": notification_destination,
                   "FAKE_EVENT_ON_RERUN": str(int(event_on_rerun)),
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

    def test_jetstream_event_change_still_fails_seed_checkpoint(self):
        result = self.run_convergence(event_on_rerun=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("seed snapshot changed", result.stderr)
        self.assertIn('"TRSTCTL_EVENTS": 7', result.stdout)
        self.assertIn('"TRSTCTL_EVENTS": 8', result.stdout)


if __name__ == "__main__":
    unittest.main()
