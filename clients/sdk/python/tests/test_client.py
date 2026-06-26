from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from trstctl_sdk import ProblemError, TrstctlClient


class Handler(BaseHTTPRequestHandler):
    calls: list[dict[str, Any]] = []
    secret_value = "initial-fixture-value"
    version = 1

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _read_json(self) -> Any:
        size = int(self.headers.get("Content-Length") or "0")
        return json.loads(self.rfile.read(size).decode("utf-8") or "{}")

    def _send(self, status: int, body: Any | None = None, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if body is None:
            self.end_headers()
            return
        raw = json.dumps(body).encode("utf-8")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _capture(self, body: Any | None = None) -> None:
        Handler.calls.append(
            {
                "method": self.command,
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "tenant": self.headers.get("X-Tenant-ID"),
                "idempotency": self.headers.get("Idempotency-Key"),
                "user_agent": self.headers.get("User-Agent"),
                "body": body,
            }
        )

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == "Bearer test-token"

    def do_GET(self) -> None:
        self._capture()
        if self.path == "/problem":
            self._send(429, {"title": "rate limited", "detail": "slow down"}, {"Retry-After": "7"})
            return
        if not self._authorized():
            self._send(401, {"title": "unauthorized"})
            return
        if self.path == "/api/v1/secrets/store":
            self._send(200, {"items": [{"name": "sdk/python/password", "version": Handler.version}]})
            return
        if self.path == "/api/v1/secrets/store/sdk/python/password":
            self._send(200, {"name": "sdk/python/password", "value": Handler.secret_value, "version": Handler.version})
            return
        self._send(404, {"title": "missing"})

    def do_POST(self) -> None:
        body = self._read_json()
        self._capture(body)
        if not self._authorized():
            self._send(401, {"title": "unauthorized"})
            return
        if self.path == "/api/v1/secrets/pki":
            self._send(201, {"serial": "01", "common_name": body["common_name"], "certificate": "-----BEGIN CERTIFICATE-----", "private_key": "-----BEGIN PRIVATE KEY-----"})
            return
        if self.path == "/api/v1/secrets/store":
            Handler.secret_value = body["value"]
            Handler.version = 1
            self._send(201, {"name": body["name"], "version": 1})
            return
        self._send(404, {"title": "missing"})

    def do_PUT(self) -> None:
        body = self._read_json()
        self._capture(body)
        if not self._authorized():
            self._send(401, {"title": "unauthorized"})
            return
        if self.path == "/api/v1/secrets/store/sdk/python/password":
            Handler.secret_value = body["value"]
            Handler.version += 1
            self._send(200, {"name": "sdk/python/password", "version": Handler.version})
            return
        self._send(404, {"title": "missing"})

    def do_DELETE(self) -> None:
        self._capture()
        if not self._authorized():
            self._send(401, {"title": "unauthorized"})
            return
        if self.path == "/api/v1/secrets/store/sdk/python/password":
            self._send(204)
            return
        self._send(404, {"title": "missing"})


class ClientTests(unittest.TestCase):
    def setUp(self) -> None:
        Handler.calls = []
        Handler.secret_value = "initial-fixture-value"
        Handler.version = 1
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_issue_and_secret_round_trip_sends_auth_and_idempotency(self) -> None:
        client = TrstctlClient(base_url=self.base_url, token="test-token", tenant="tenant-1", retry={"max_attempts": 1})
        issued = client.issue_pki_secret("sdk.test", ttl_seconds=300, idempotency_key="issue-key")
        self.assertEqual(issued["serial"], "01")
        client.create_secret("sdk/python/password", "initial-fixture-value", idempotency_key="create-key")
        self.assertEqual(client.get_secret("sdk/python/password")["value"], "initial-fixture-value")
        self.assertEqual(client.rotate_secret("sdk/python/password", "rotated-fixture-value", idempotency_key="rotate-key")["version"], 2)
        self.assertEqual(client.get_secret("sdk/python/password")["value"], "rotated-fixture-value")
        client.delete_secret("sdk/python/password", idempotency_key="delete-key")

        mutations = [c for c in Handler.calls if c["method"] != "GET"]
        self.assertEqual([c["idempotency"] for c in mutations], ["issue-key", "create-key", "rotate-key", "delete-key"])
        self.assertTrue(all(c["authorization"] == "Bearer test-token" for c in Handler.calls))
        self.assertTrue(all(c["tenant"] == "tenant-1" for c in Handler.calls))
        self.assertTrue(all(c["user_agent"] == "trstctl-python-sdk/1" for c in Handler.calls))

    def test_problem_error_parses_retry_after(self) -> None:
        client = TrstctlClient(base_url=self.base_url, retry={"max_attempts": 1})
        with self.assertRaises(ProblemError) as raised:
            client.request("GET", "/problem")
        self.assertEqual(raised.exception.http_status, 429)
        self.assertEqual(raised.exception.title, "rate limited")
        self.assertEqual(raised.exception.retry_after_seconds, 7)


if __name__ == "__main__":
    unittest.main()
