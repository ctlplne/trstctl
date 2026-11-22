#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Regression tests for sharing the pinned CI archive with legacy PG tests."""

import hashlib
import json
import runpy
import tempfile
import unittest
from pathlib import Path


seed = runpy.run_path(str(Path(__file__).with_name("seed-pg-legacy-cache.py")))["seed"]


class SeedLegacyCacheTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.verified = self.root / "trstctl-pg-archives"
        self.library = self.root / "home" / ".embedded-postgres-go"
        self.payload = b"archive bytes for a pinned CI fixture"
        self.digest = hashlib.sha256(self.payload).hexdigest()
        self.name = "embedded-postgres-binaries-linux-amd64-16.16.0.txz"
        self.parent = self.verified / f"linux-amd64-16.16.0-{self.digest}"
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({
            "postgresVersion": "16.16.0",
            "archives": [{"arch": "linux-amd64", "txz_sha256": self.digest}],
        }))

    def place(self, payload=None):
        self.parent.mkdir(parents=True, exist_ok=True)
        (self.parent / self.name).write_bytes(self.payload if payload is None else payload)

    def test_verified_cache_hit_feeds_legacy_tests_without_download(self):
        self.place()
        self.assertEqual(seed(self.manifest, self.verified, self.library), 1)
        target = self.library / self.name
        self.assertEqual(target.read_bytes(), self.payload)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.library.stat().st_mode & 0o777, 0o700)

    def test_cold_or_tampered_cache_never_seeds(self):
        self.assertEqual(seed(self.manifest, self.verified, self.library), 0)
        self.assertFalse(self.library.exists())
        self.place(b"tampered archive")
        with self.assertRaisesRegex(ValueError, "differs from committed pin"):
            seed(self.manifest, self.verified, self.library)
        self.assertFalse(self.library.exists())

    def test_symlink_sources_and_targets_are_refused(self):
        self.parent.mkdir(parents=True)
        outside = self.root / "outside.txz"
        outside.write_bytes(self.payload)
        (self.parent / self.name).symlink_to(outside)
        self.assertEqual(seed(self.manifest, self.verified, self.library), 0)
        (self.parent / self.name).unlink()
        self.place()
        self.library.mkdir(parents=True)
        (self.library / self.name).symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "legacy archive is a symlink"):
            seed(self.manifest, self.verified, self.library)
        self.assertEqual(outside.read_bytes(), self.payload)


if __name__ == "__main__":
    unittest.main()
