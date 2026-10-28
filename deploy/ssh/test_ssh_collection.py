# SPDX-License-Identifier: BUSL-1.1
"""Contract tests for the installed one-shot helper (no network or root needed)."""
import base64
import importlib.machinery
import importlib.util
import pathlib
import struct
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader("collector", str(pathlib.Path(__file__).with_name("trstctl-ssh-collect-v1")))
spec = importlib.util.spec_from_loader(loader.name, loader)
collector = importlib.util.module_from_spec(spec)
loader.exec_module(collector)


class PublicProfileTest(unittest.TestCase):
    def test_private_material_and_wire_type_mismatch_are_refused(self):
        for raw in (b"-----BEGIN PRIVATE KEY-----", b"ssh-ed25519 c2VjcmV0"):
            with self.assertRaises(ValueError):
                collector.public_material(raw, "ca")

    def test_public_key_comments_are_not_returned(self):
        name = b"ssh-ed25519"
        wire = struct.pack(">I", len(name)) + name + struct.pack(">I", 32) + b"x" * 32
        key = name + b" " + base64.b64encode(wire)
        self.assertEqual(collector.public_material(key + b" human comment\n", "ca"), key + b"\n")

    def test_unapproved_files_are_reported_without_opening_them(self):
        settings = {key: ["none"] for key in collector.KEYS}
        settings["trustedusercakeys"] = ["/etc/ssh/unapproved"]
        with patch.object(collector, "effective_settings", return_value=settings), patch.object(collector, "bounded_file") as read:
            result = collector.collect({"config_path": "/etc/ssh/sshd_config", "allowed_public_files": []})
        read.assert_not_called()
        self.assertEqual(result["files"], [{"path": "/etc/ssh/unapproved", "kind": "ca", "state": "not_allowed"}])
        self.assertEqual(set(result["settings"]), collector.KEYS)


if __name__ == "__main__":
    unittest.main()
