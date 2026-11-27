#!/usr/bin/env python3
"""Regression checks for the release Go cache setting."""

from pathlib import Path
import tempfile
import unittest

from importlib.machinery import SourceFileLoader


GUARD = SourceFileLoader(
    "release_go_cache_guard", str(Path(__file__).with_name("check-release-go-cache.py"))
).load_module()


class ReleaseGoCacheTest(unittest.TestCase):
    def check_workflow(self, body: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.yml"
            path.write_text(body)
            return GUARD.check(path)

    def test_explicitly_disabled_cache_for_each_step(self):
        self.assertEqual(self.check_workflow("""
jobs:
  release:
    steps:
      - name: Set up Go
        uses: actions/setup-go@0123456789012345678901234567890123456789
        with:
          go-version-file: go.mod
          cache: false
      - uses: actions/setup-go@0123456789012345678901234567890123456789
        with:
          cache: false
"""), [])

    def test_each_step_requires_its_own_disabled_cache(self):
        problems = self.check_workflow("""
jobs:
  release:
    steps:
      - uses: actions/setup-go@0123456789012345678901234567890123456789
        with:
          cache: false
      - uses: actions/setup-go@0123456789012345678901234567890123456789
        with:
          go-version-file: go.mod
""")
        self.assertEqual(len(problems), 1)

    def test_enabled_and_duplicate_cache_settings_fail(self):
        for settings in ("cache: true", "cache: false\n          cache: true"):
            with self.subTest(settings=settings):
                problems = self.check_workflow("""
jobs:
  release:
    steps:
      - uses: actions/setup-go@0123456789012345678901234567890123456789
        with:
          """ + settings)
                self.assertEqual(len(problems), 1)

    def test_workflow_requires_go_setup(self):
        self.assertEqual(len(self.check_workflow("jobs:\n  release: {}\n")), 1)


if __name__ == "__main__":
    unittest.main()
