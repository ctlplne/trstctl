#!/usr/bin/env python3
"""Contract test for same-machine live receipt comparisons."""

import importlib.util
import json
import pathlib
import tempfile


script = pathlib.Path(__file__).with_name("live-baseline.py")
spec = importlib.util.spec_from_file_location("live_baseline", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

fixture = {
    "profile": "live",
    "stack_profile": "eval-loopback-actual-listener-child-signer-uds",
    "load_phases": [{"name": "realistic", "samples": 4}],
    "summary": {"ok": True},
    "results": [
        {
            "hot_path": "api.issuance",
            "phase": "realistic",
            "samples": 4,
            "p99_ms": 10.0,
            "throughput_per_second": 100.0,
        }
    ],
}

with tempfile.TemporaryDirectory() as directory:
    baseline = pathlib.Path(directory) / "baseline.json"
    candidate = pathlib.Path(directory) / "candidate.json"
    baseline.write_text(json.dumps(fixture))
    candidate.write_text(json.dumps(fixture))
    module.stamp(baseline)
    module.stamp(candidate)
    assert module.compare(baseline, candidate)["absolute_slo_passed"]

    changed = json.loads(candidate.read_text())
    changed["machine_fingerprint_sha256"] = "different-host"
    candidate.write_text(json.dumps(changed))
    try:
        module.compare(baseline, candidate)
    except ValueError as exc:
        assert "not stamped on this machine" in str(exc)
    else:
        raise AssertionError("different-machine candidate passed")

    module.stamp(candidate)
    changed = json.loads(candidate.read_text())
    changed["load_phases"][0]["samples"] = 8
    candidate.write_text(json.dumps(changed))
    try:
        module.compare(baseline, candidate)
    except ValueError as exc:
        assert "load_phases differs" in str(exc)
    else:
        raise AssertionError("incompatible phase passed")

print("live baseline self-test passed")
