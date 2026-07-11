#!/usr/bin/env python3
"""Nonce-bound entitlement service for the connector.right_size DoD proof."""

from __future__ import annotations

import json
import os
import signal
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class LoopbackHTTPServer(ThreadingHTTPServer):
    """Bind without HTTPServer's reverse-DNS lookup on loopback."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing {name}")
    return value


def emit(value: dict) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


class State:
    def __init__(self, entry_id: str):
        self.entry_id = entry_id
        self.scopes = ["read", "write"]
        self.mutations: dict[str, dict] = {}
        self.patch_count = 0
        self.read_count = 0
        self.lock = threading.Lock()

    def passed(self) -> bool:
        with self.lock:
            return self.patch_count == 1 and self.read_count >= 1 and self.scopes == ["read"] and bool(self.mutations)

    def readback(self) -> bytes:
        with self.lock:
            return json.dumps({"scopes": self.scopes}, sort_keys=True, separators=(",", ":")).encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "trstctl-dod-right-size/1"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_args) -> None:
        return

    def send_json(self, status: int, value: dict) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authenticated(self) -> bool:
        return self.headers.get("Authorization") == "Bearer right-size-token" and bool(self.headers.get("Idempotency-Key"))

    def do_PATCH(self) -> None:
        if urlparse(self.path).path != "/v1/entitlements/service-1" or not self.authenticated():
            self.send_json(401, {"error": "authentication required"})
            return
        length = min(int(self.headers.get("Content-Length", "0") or "0"), 1 << 20)
        try:
            payload = json.loads(self.rfile.read(length))
        except Exception:
            self.send_json(400, {"error": "invalid JSON"})
            return
        tenant = self.headers.get("X-Trstctl-Tenant", "")
        if (
            payload.get("schema_version") != 1
            or payload.get("tenant_id") != tenant
            or payload.get("connector") != "least-privilege"
            or payload.get("target") != "service-1"
            or payload.get("remove_scopes") != ["write"]
            or payload.get("recommended_scopes") != ["read"]
        ):
            self.send_json(422, {"error": "wrong mutation contract"})
            return
        key = self.headers["Idempotency-Key"]
        with self.state.lock:
            existing = self.state.mutations.get(key)
            if existing is None:
                self.state.scopes = ["read"]
                self.state.patch_count += 1
                existing = {
                    "status": "applied",
                    "mutation_id": "right-size-mutation-1",
                    "removed_scopes": ["write"],
                    "rollback_ref": "restore-grants:service-1:read,write",
                }
                self.state.mutations[key] = existing
        self.send_json(200, existing)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/dod/readback":
            body = self.state.readback()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path != "/v1/entitlements/service-1" or not self.authenticated():
            self.send_json(401, {"error": "authentication required"})
            return
        with self.state.lock:
            self.state.read_count += 1
            scopes = list(self.state.scopes)
        self.send_json(200, {"scopes": scopes})


def serve() -> int:
    challenge = required("TRSTCTL_DOD_CHALLENGE")
    entry_id = required("TRSTCTL_DOD_ENTRY_ID")
    identity = required("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = required("TRSTCTL_DOD_CONTRACT_DIGEST")
    state = State(entry_id)
    server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
    server.state = state  # type: ignore[attr-defined]
    stopped = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    emit({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "ready": True, "endpoint": f"http://127.0.0.1:{server.server_port}",
    })
    stopped.wait()
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
    passed = state.passed()
    emit({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "passed": passed,
    })
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(serve())
