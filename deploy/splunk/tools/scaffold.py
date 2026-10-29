# SPDX-License-Identifier: BUSL-1.1
"""Owned HEC/limited-search fixture; never claim this is the Splunk product.

One request at a time, bounded input/state, no outbound calls, no request logging.
Use only disposable lab events and a fixture credential, on an isolated network.
"""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import os
import signal
from pathlib import Path

from contract import App

MAX_BODY = 1 << 20
MAX_RECORDS = 10000
MAX_STATE = 16 << 20


class Scaffold(HTTPServer):
    request_queue_size = 8

    def __init__(self, address, app, state, token, fail_first=False):
        self.app = app
        self.app.validate()
        self.state = Path(state)
        self.token = token
        self.fail_first = fail_first
        self.requests_stored = 0
        self.events = []
        if self.state.exists():
            if self.state.stat().st_size > MAX_STATE:
                raise ValueError("fixture state exceeds bound")
            with self.state.open(encoding="utf-8") as handle:
                self.events = [json.loads(line) for line in handle if line.strip()]
            if len(self.events) > MAX_RECORDS:
                raise ValueError("fixture event count exceeds bound")
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_args):
        pass

    def reply(self, status, value):
        wire = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)

    def authorized(self):
        # Deliberately a fixture credential check, not vendor authentication proof.
        supplied = self.headers.get("Authorization", "").encode()
        return supplied == b"Splunk " + self.server.token

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"model": "trstctl-owned-scaffold-v1", "ready": True})
            return
        if not self.authorized():
            self.reply(401, {"code": 4, "text": "fixture authorization refused"})
            return
        if self.path == "/scaffold/summary":
            self.reply(
                200,
                {
                    "model": "trstctl-owned-scaffold-v1",
                    "records": len(self.server.events),
                    "requests_stored": self.server.requests_stored,
                    "searches": sorted(self.server.app.searches),
                },
            )
        else:
            self.reply(404, {"error": "unknown fixture route"})

    def do_POST(self):
        if not self.authorized():
            self.reply(401, {"code": 4, "text": "fixture authorization refused"})
            return
        try:
            if self.headers.get("Transfer-Encoding") is not None:
                raise ValueError("chunked fixture input unsupported")
            size = int(self.headers.get("Content-Length", "-1"))
            if not 0 < size <= MAX_BODY:
                raise ValueError("fixture body outside bound")
            wire = self.rfile.read(size)
            if len(wire) != size:
                raise ValueError("incomplete fixture body")
            if self.path == "/services/collector/event":
                self.ingest(wire)
            elif self.path == "/scaffold/search":
                query = json.loads(wire)
                if set(query) != {"name", "index", "tenant_id", "now"}:
                    raise ValueError("explicit fixture search scope required")
                rows = self.server.app.evaluate(
                    query["name"],
                    self.server.events,
                    query["index"],
                    query["tenant_id"],
                    query["now"],
                )
                self.reply(
                    200,
                    {
                        "model": "trstctl-owned-scaffold-v1",
                        "search": query["name"],
                        "execution": "ad_hoc_contract",
                        "fired": bool(rows),
                        "rows": rows,
                    },
                )
            else:
                self.reply(404, {"error": "unknown fixture route"})
        except (ValueError, KeyError, TypeError, OverflowError):
            # Never echo received payloads, header values or credentials.
            self.reply(400, {"error": "fixture request rejected"})

    def ingest(self, wire):
        envelopes = [json.loads(line) for line in wire.splitlines() if line.strip()]
        if not envelopes or len(envelopes) > 501:
            raise ValueError("fixture batch count outside bound")
        rows = []
        for envelope in envelopes:
            if (
                not isinstance(envelope, dict)
                or envelope.get("source") != "trstctl"
                or envelope.get("sourcetype") != "trstctl:audit"
                or not isinstance(envelope.get("event"), dict)
                or isinstance(envelope.get("time"), bool)
                or not isinstance(envelope.get("time"), (int, float))
                or not math.isfinite(envelope["time"])
            ):
                raise ValueError("native audit HEC shape required")
            event = envelope["event"]
            if not isinstance(event.get("id"), str) or not isinstance(
                event.get("type"), str
            ):
                raise ValueError("native audit record identity required")
            if event["type"] != "trstctl.audit.chain_trailer" and not isinstance(
                event.get("tenant_id"), str
            ):
                raise ValueError("tenant audit scope required")
            rows.append(
                {
                    "index": "trstctl_lab",
                    "sourcetype": envelope["sourcetype"],
                    "_time": envelope["time"],
                    "event": event,
                }
            )
        retained = b"".join(
            json.dumps(row, allow_nan=False, separators=(",", ":")).encode() + b"\n"
            for row in rows
        )
        before = self.server.state.stat().st_size if self.server.state.exists() else 0
        if (
            before + len(retained) > MAX_STATE
            or len(self.server.events) + len(rows) > MAX_RECORDS
        ):
            self.reply(429, {"code": 9, "text": "fixture state full"})
            return
        with self.server.state.open("ab") as handle:
            handle.write(retained)
            handle.flush()
            os.fsync(handle.fileno())
        self.server.events.extend(rows)
        self.server.requests_stored += 1
        if self.server.fail_first:
            self.server.fail_first = False
            self.reply(
                503, {"code": 9, "text": "fixture acknowledgment loss after store"}
            )
        else:
            self.reply(200, {"code": 0, "text": "Success"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument(
        "--app", type=Path, default=Path(__file__).resolve().parents[1] / "trstctl"
    )
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--fail-first-after-store", action="store_true")
    args = parser.parse_args()
    fixture_token = args.token_file.read_bytes().strip()
    if (
        not fixture_token
        or len(fixture_token) > 4096
        or b"\r" in fixture_token
        or b"\n" in fixture_token
    ):
        raise ValueError("fixture token file is absent or malformed")

    def terminate_fixture(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate_fixture)
    server = Scaffold(
        (args.host, args.port),
        App(args.app),
        args.state,
        fixture_token,
        args.fail_first_after_store,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
