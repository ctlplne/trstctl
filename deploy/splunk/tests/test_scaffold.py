# SPDX-License-Identifier: BUSL-1.1
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


class ScaffoldTransportTests(unittest.TestCase):
    def setUp(self):
        from contract import App
        from scaffold import Scaffold

        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name) / "records.ndjson"
        self.server = Scaffold(
            ("127.0.0.1", 0),
            App(ROOT / "trstctl"),
            self.state,
            b"disposable-fixture-token",
            fail_first=True,
        )
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_port)
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.assertFalse(self.thread.is_alive())
        self.directory.cleanup()

    def request(self, path, body, authorization="Splunk disposable-fixture-token"):
        request = Request(
            self.url + path,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": authorization,
            },
        )
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as response:
            with response:
                return response.code, json.load(response)

    def test_native_hec_retry_stores_duplicates_but_search_counts_stable_ids(self):
        now = 1800000000
        wire = b"\n".join(
            json.dumps(
                {
                    "source": "trstctl",
                    "sourcetype": "trstctl:audit",
                    "time": now - 10,
                    "event": {
                        "tenant_id": "tenant-a",
                        "id": f"failure-{i}",
                        "type": "identity.renewal_failed",
                        "data": {"identity_id": "identity-a"},
                    },
                }
            ).encode()
            for i in range(3)
        )
        self.assertEqual(self.request("/services/collector/event", wire)[0], 503)
        self.assertEqual(
            self.request("/services/collector/event", wire),
            (200, {"code": 0, "text": "Success"}),
        )
        query = {
            "name": "trstctl - Repeated renewal failures",
            "index": "trstctl_lab",
            "tenant_id": "tenant-a",
            "now": now,
        }
        status, result = self.request("/scaffold/search", json.dumps(query).encode())
        self.assertEqual(status, 200)
        self.assertEqual(result["execution"], "ad_hoc_contract")
        self.assertTrue(result["fired"])
        self.assertEqual(result["rows"][0]["event_count"], 3)
        self.assertEqual(len(self.state.read_text().splitlines()), 6)
        query["tenant_id"] = "tenant-b"
        self.assertEqual(
            self.request("/scaffold/search", json.dumps(query).encode())[1]["rows"], []
        )

    def test_rejects_generic_siem_bad_credentials_bad_envelopes_and_unsupported_queries(
        self,
    ):
        path = "/services/collector/event"
        self.assertEqual(
            self.request(path, b"{}", "Bearer disposable-fixture-token")[0], 401
        )
        self.assertEqual(self.request(path, b"{}")[0], 400)
        self.assertEqual(self.request(path, b"not-json")[0], 400)
        query = {
            "name": "unsupported",
            "index": "trstctl_lab",
            "tenant_id": "tenant-a",
            "now": 1800000000,
        }
        self.assertEqual(
            self.request("/scaffold/search", json.dumps(query).encode())[0], 400
        )
        self.assertFalse(self.state.exists())
        self.assertEqual(self.server.events, [])


if __name__ == "__main__":
    unittest.main()
