# SPDX-License-Identifier: BUSL-1.1
"""Prove both Go linter failures stop the Makefile gate immediately."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="trstctl-lint-go-gate-") as raw:
        directory = Path(raw)
        fake = directory / "golangci-lint"
        fake.write_text(
            '#!/bin/sh\n'
            'printf "%s\\n" "$PWD" >> "$TRSTCTL_LINT_PROBE_LOG"\n'
            'case "$TRSTCTL_LINT_PROBE_FAIL:$PWD" in\n'
            f'  first:{ROOT}) exit 31;;\n'
            f'  sdk:{ROOT}/clients/sdk/go) exit 32;;\n'
            'esac\n'
            'exit 0\n'
        )
        fake.chmod(0o700)
        log = directory / "calls"
        for failure, expected_calls, expected_success in (
            ("first", [str(ROOT)], False),
            ("sdk", [str(ROOT), str(ROOT / "clients/sdk/go")], False),
            ("none", [str(ROOT), str(ROOT / "clients/sdk/go")], True),
        ):
            log.write_text("")
            env = os.environ.copy()
            env["PATH"] = str(directory) + os.pathsep + env.get("PATH", "")
            env["TRSTCTL_LINT_PROBE_LOG"] = str(log)
            env["TRSTCTL_LINT_PROBE_FAIL"] = failure
            run = subprocess.run(
                ["make", "--no-print-directory", "-s", "lint-go", "GO_PACKAGE_DIRS=./internal/crypto/windependents"],
                cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            calls = log.read_text().splitlines()
            if (run.returncode == 0) != expected_success or calls != expected_calls:
                raise AssertionError(
                    f"Go lint gate case {failure}: exit={run.returncode} calls={calls}; "
                    f"stdout={run.stdout[-500:]} stderr={run.stderr[-500:]}"
                )


if __name__ == "__main__":
    main()
