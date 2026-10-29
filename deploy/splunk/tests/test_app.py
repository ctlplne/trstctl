# SPDX-License-Identifier: BUSL-1.1
"""Contract checks for the owned app; these do not execute Splunk SPL."""

import copy
import io
from pathlib import Path
import sys
import tarfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


class AppContractTests(unittest.TestCase):
    def setUp(self):
        from contract import App

        self.app = App(ROOT / "trstctl")
        self.now = 1800000000.0

    def event(self, kind, number, tenant="tenant-a", when=None, identity="identity-a"):
        return {
            "index": "trstctl_lab",
            "sourcetype": "trstctl:audit",
            "_time": self.now - 30 if when is None else when,
            "event": {
                "tenant_id": tenant,
                "id": f"event-{number}",
                "type": kind,
                "data": {"identity_id": identity},
            },
        }

    def evaluate(self, name, events, tenant="tenant-a"):
        return self.app.evaluate(name, events, "trstctl_lab", tenant, self.now)

    def test_installable_assets_and_safe_defaults(self):
        self.app.validate()
        self.assertEqual(
            set(self.app.searches),
            {
                "trstctl - Repeated renewal failures",
                "trstctl - Certificate revocation burst",
            },
        )
        for search in self.app.searches.values():
            self.assertEqual(search["disabled"], "true")
            self.assertEqual(search["enableSched"], "0")
            self.assertEqual(search["actions"], "")
            self.assertEqual(search["dispatch.earliest_time"], "-15m")
        for forbidden in (
            "inputs.conf",
            "authorize.conf",
            "commands.conf",
            "alert_actions.conf",
        ):
            self.assertFalse(list((ROOT / "trstctl").rglob(forbidden)))
        view = ET.parse(ROOT / "trstctl/default/data/ui/views/overview.xml")
        self.assertEqual(view.getroot().tag, "dashboard")
        self.assertEqual(view.findall(".//script"), [])
        self.assertEqual(
            ET.parse(ROOT / "trstctl/default/data/ui/nav/default.xml").getroot().tag,
            "nav",
        )

    def test_installer_metadata_declares_build_and_manual_offline_setup(self):
        from contract import read_conf

        config = read_conf(ROOT / "trstctl/default/app.conf")
        self.assertRegex(config["install"].get("build", ""), r"^[1-9][0-9]*$")
        self.assertEqual(config["install"]["is_configured"], "true")
        self.assertEqual(config["ui"]["check_for_updates"], "false")
        self.assertNotIn("setup_view", config["ui"])

    def test_each_search_fires_only_at_its_unique_event_threshold(self):
        for name, kind, threshold in [
            ("trstctl - Repeated renewal failures", "identity.renewal_failed", 3),
            ("trstctl - Certificate revocation burst", "certificate.revoked", 5),
        ]:
            with self.subTest(name=name):
                events = [self.event(kind, i) for i in range(threshold)]
                self.assertEqual(self.evaluate(name, events[:-1]), [])
                rows = self.evaluate(name, events)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["event_count"], threshold)
                self.assertEqual(
                    set(rows[0]["event_ids"]), {f"event-{i}" for i in range(threshold)}
                )
                self.assertEqual(
                    self.evaluate(name, events + copy.deepcopy(events)), rows
                )
                self.assertEqual(self.evaluate(name, events[:1] * 20), [])

    def test_scopes_and_time_windows_do_not_mix(self):
        for name, kind, threshold in [
            ("trstctl - Repeated renewal failures", "identity.renewal_failed", 3),
            ("trstctl - Certificate revocation burst", "certificate.revoked", 5),
        ]:
            with self.subTest(name=name):
                events = [self.event(kind, i) for i in range(threshold - 1)]
                negative = [
                    self.event(kind, 50, tenant="tenant-b"),
                    self.event(kind, 51, when=self.now - 901),
                    self.event(kind, 52, when=self.now + 1),
                    self.event("trstctl.audit.chain_trailer", 53),
                ]
                wrong_index = self.event(kind, 54)
                wrong_index["index"] = "other_index"
                missing_id = self.event(kind, 55)
                missing_id["event"].pop("id")
                self.assertEqual(
                    self.evaluate(name, events + negative + [wrong_index, missing_id]),
                    [],
                )
                self.assertEqual(self.evaluate(name, events, tenant="tenant-b"), [])
                self.assertEqual(
                    self.app.evaluate(
                        name,
                        events,
                        "__trstctl_configure_index__",
                        "tenant-a",
                        self.now,
                    ),
                    [],
                )
        name = "trstctl - Repeated renewal failures"
        split = [
            self.event("identity.renewal_failed", i, identity=f"identity-{i}")
            for i in range(3)
        ]
        self.assertEqual(self.evaluate(name, split), [])
        same_ids = [
            self.event("identity.renewal_failed", i, tenant=tenant)
            for tenant in ("tenant-a", "tenant-b")
            for i in range(3)
        ]
        self.assertEqual(self.evaluate(name, same_ids)[0]["event_count"], 3)
        self.assertEqual(self.evaluate(name, same_ids, "tenant-b")[0]["event_count"], 3)

    def test_unknown_spl_cannot_silently_pass_the_scaffold(self):
        name = "trstctl - Repeated renewal failures"
        self.app.searches[name]["search"] += " | transaction tenant_id"
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.evaluate(name, [])

    def test_package_is_deterministic_and_contains_only_the_app(self):
        from package_app import archive

        first, second = io.BytesIO(), io.BytesIO()
        archive(ROOT / "trstctl", first)
        archive(ROOT / "trstctl", second)
        self.assertEqual(first.getvalue(), second.getvalue())
        with tarfile.open(fileobj=io.BytesIO(first.getvalue()), mode="r:gz") as package:
            names = package.getnames()
            self.assertIn("trstctl/default/savedsearches.conf", names)
            self.assertTrue(
                all(name == "trstctl" or name.startswith("trstctl/") for name in names)
            )
            self.assertFalse(
                any("local/" in name or "__pycache__" in name for name in names)
            )
            self.assertTrue(
                all(
                    member.mtime == 0 and member.uid == 0 and not member.issym()
                    for member in package
                )
            )


if __name__ == "__main__":
    unittest.main()
