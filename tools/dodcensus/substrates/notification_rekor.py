#!/usr/bin/env python3
"""Nonce-bound high-fidelity PagerDuty/OpsGenie/Rekor emulator for the DoD gate."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import signal
import socketserver
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MAX_BODY = 1 << 20
PAGERDUTY_KEY = "dod-pagerduty-routing-key"
OPSGENIE_KEY = "dod-opsgenie-api-key"


class LoopbackHTTPServer(ThreadingHTTPServer):
    """Bind without HTTPServer's reverse-DNS lookup on loopback."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


class State:
    def __init__(self, mode: str, entry_id: str) -> None:
        self.mode = mode
        self.entry_id = entry_id
        self.lock = threading.Lock()
        self.accepted = 0
        self.failures = 0
        self.readback = b""
        self.entries: dict[bytes, tuple[str, bytes]] = {}
        self.entries_by_uuid: dict[str, bytes] = {}

    def accept(self, readback: bytes) -> None:
        with self.lock:
            self.accepted += 1
            self.readback = readback

    def fail(self) -> None:
        with self.lock:
            self.failures += 1

    def passed(self) -> bool:
        minimum = 2 if self.entry_id == "code_signing.default" else 1
        with self.lock:
            return self.accepted >= minimum and self.failures == 0 and len(self.readback) >= 16


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def token_hash(value: str) -> bool:
    if not value.startswith("trstctl-") or len(value) != len("trstctl-") + 64:
        return False
    try:
        bytes.fromhex(value[len("trstctl-") :])
    except ValueError:
        return False
    return True


def verify_signature(public_pem: bytes, signature: bytes, digest: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="trstctl-rekor-") as raw_dir:
        root = Path(raw_dir)
        (root / "public.pem").write_bytes(public_pem)
        (root / "signature.bin").write_bytes(signature)
        (root / "digest.bin").write_bytes(digest)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(root / "public.pem"),
                "-in",
                str(root / "digest.bin"),
                "-sigfile",
                str(root / "signature.bin"),
                "-pkeyopt",
                "digest:sha256",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
        return result.returncode == 0


def sign_set(payload: bytes, private_key: Path) -> bytes | None:
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key)],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    if result.returncode != 0 or not result.stdout:
        return None
    return result.stdout


def rekor_log_id(private_key: Path) -> str | None:
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    if result.returncode != 0 or not result.stdout:
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def handler_for(state: State, rekor_private_key: Path | None, log_id: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "trstctl-dod-vendor/1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def send_json(self, status: int, value: object) -> None:
            body = compact(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_rekor_conflict(self, entry_uuid: str) -> None:
            body = compact({"code": 409, "message": f"an equivalent entry already exists with UUID {entry_uuid}"})
            self.send_response(409)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Location", f"http://{self.headers.get('Host')}/api/v1/log/entries/{entry_uuid}")
            self.end_headers()
            self.wfile.write(body)

        def read_json(self) -> tuple[object | None, bytes]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None, b""
            if length <= 0 or length > MAX_BODY:
                return None, b""
            body = self.rfile.read(length)
            try:
                return json.loads(body), body
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None, body

        def do_GET(self) -> None:  # noqa: N802
            if self.path.startswith("/api/v1/log/entries/"):
                entry_uuid = self.path.removeprefix("/api/v1/log/entries/")
                with state.lock:
                    body = state.entries_by_uuid.get(entry_uuid, b"")
                if not body:
                    self.send_json(404, {"code": 404, "message": "entry not found"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path != "/dod/readback":
                self.send_json(404, {"error": "not found"})
                return
            with state.lock:
                body = state.readback
            if not body:
                self.send_json(404, {"error": "no accepted action"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if state.mode == "notification":
                self.handle_notification()
            else:
                self.handle_rekor()

        def handle_notification(self) -> None:
            value, _body = self.read_json()
            if not isinstance(value, dict):
                state.fail()
                self.send_json(400, {"status": "invalid event", "message": "malformed JSON"})
                return
            if state.entry_id == "notification_channel.opsgenie":
                valid = (
                    self.path == "/v2/alerts"
                    and self.headers.get("Authorization") == f"GenieKey {OPSGENIE_KEY}"
                    and isinstance(value.get("message"), str)
                    and 0 < len(value["message"]) <= 130
                    and token_hash(value.get("alias", ""))
                    and value.get("source") == "trstctl"
                    and value.get("priority") in {"P1", "P2", "P3", "P4", "P5"}
                )
                if not valid:
                    state.fail()
                    self.send_json(400, {"message": "invalid OpsGenie Alert API request", "took": 0.0})
                    return
                canonical = compact(value)
                state.accept(canonical)
                request_id = hashlib.sha256(canonical).hexdigest()
                self.send_json(202, {"result": "Request will be processed", "requestId": request_id})
                return

            payload = value.get("payload")
            valid = (
                self.path == "/v2/enqueue"
                and value.get("routing_key") == PAGERDUTY_KEY
                and value.get("event_action") == "trigger"
                and token_hash(value.get("dedup_key", ""))
                and isinstance(payload, dict)
                and isinstance(payload.get("summary"), str)
                and bool(payload.get("summary"))
                and payload.get("source") == "trstctl"
                and payload.get("severity") in {"critical", "error", "warning", "info"}
            )
            if not valid:
                state.fail()
                self.send_json(400, {"status": "invalid event", "message": "invalid PagerDuty Events v2 request"})
                return
            canonical = compact(value)
            state.accept(canonical)
            self.send_json(202, {"status": "success", "message": "Event processed", "dedup_key": value["dedup_key"]})

        def handle_rekor(self) -> None:
            value, _body = self.read_json()
            valid = (
                self.path == "/api/v1/log/entries"
                and isinstance(value, dict)
                and value.get("apiVersion") == "0.0.1"
                and value.get("kind") == "hashedrekord"
            )
            try:
                spec = value["spec"]
                hash_value = spec["data"]["hash"]
                signature = base64.b64decode(spec["signature"]["content"], validate=True)
                public_pem = base64.b64decode(spec["signature"]["publicKey"]["content"], validate=True)
                digest = bytes.fromhex(hash_value["value"])
                valid = valid and hash_value["algorithm"] == "sha256" and len(digest) == 32
                valid = valid and public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
                valid = valid and verify_signature(public_pem, signature, digest)
            except (KeyError, TypeError, ValueError):
                valid = False
            if not valid:
                state.fail()
                self.send_json(400, {"code": 400, "message": "invalid HashedRekord"})
                return
            canonical = compact(value)
            with state.lock:
                prior = state.entries.get(canonical)
                log_index = state.accepted
            if prior is not None:
                entry_uuid, _receipt = prior
                self.send_rekor_conflict(entry_uuid)
                return
            entry_uuid = hashlib.sha256(b"\x00" + canonical).hexdigest()
            integrated_time = 1770000000 + log_index
            body_b64 = base64.b64encode(canonical).decode("ascii")
            set_payload = compact(
                {
                    "body": body_b64,
                    "integratedTime": integrated_time,
                    "logID": log_id,
                    "logIndex": log_index,
                }
            )
            if rekor_private_key is None or log_id is None:
                state.fail()
                self.send_json(500, {"code": 500, "message": "Rekor log trust is unavailable"})
                return
            signed_entry = sign_set(set_payload, rekor_private_key)
            if signed_entry is None:
                state.fail()
                self.send_json(500, {"code": 500, "message": "failed to sign SET"})
                return
            receipt = {
                entry_uuid: {
                    "body": body_b64,
                    "integratedTime": integrated_time,
                    "logID": log_id,
                    "logIndex": log_index,
                    "verification": {"signedEntryTimestamp": base64.b64encode(signed_entry).decode("ascii")},
                }
            }
            encoded_receipt = compact(receipt)
            with state.lock:
                state.entries[canonical] = (entry_uuid, encoded_receipt)
                state.entries_by_uuid[entry_uuid] = encoded_receipt
            state.accept(encoded_receipt)
            # The code-signing DoD run forces the first integrated entry through
            # Rekor's real duplicate contract (409 + Location + GET readback).
            # This catches outbox clients that would retry an opaque 409 forever.
            if state.entry_id == "code_signing.default" and log_index == 0:
                self.send_rekor_conflict(entry_uuid)
                return
            self.send_json(201, receipt)

    return Handler


def serve(mode: str) -> int:
    challenge = os.environ.get("TRSTCTL_DOD_CHALLENGE", "")
    entry_id = os.environ.get("TRSTCTL_DOD_ENTRY_ID", "")
    identity = os.environ.get("TRSTCTL_DOD_SUBSTRATE_IDENTITY", "")
    contract_digest = os.environ.get("TRSTCTL_DOD_CONTRACT_DIGEST", "")
    if not all((challenge, entry_id, identity, contract_digest)):
        raise SystemExit("missing TRSTCTL_DOD_* environment")

    state = State(mode, entry_id)
    private_key: Path | None = None
    log_id: str | None = None
    if mode == "rekor":
        raw_key = os.environ.get("TRSTCTL_REKOR_EMULATOR_PRIVATE_KEY_FILE", "")
        private_key = Path(raw_key)
        if not private_key.is_absolute() or not private_key.is_file():
            raise SystemExit("missing absolute Rekor emulator private-key file")
        log_id = rekor_log_id(private_key)
        if log_id is None:
            raise SystemExit("cannot derive Rekor log identity from private key")
    server = LoopbackHTTPServer(("127.0.0.1", 0), handler_for(state, private_key, log_id))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    print(
        json.dumps(
            {
                "schema_version": 1,
                "challenge": challenge,
                "entry_id": entry_id,
                "identity": identity,
                "contract_digest": contract_digest,
                "pid": os.getpid(),
                "ready": True,
                "endpoint": endpoint,
            },
            separators=(",", ":"),
        ),
        flush=True,
    )

    stopped = threading.Event()
    signal.signal(signal.SIGINT, lambda *_args: stopped.set())
    signal.signal(signal.SIGTERM, lambda *_args: stopped.set())
    stopped.wait()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    print(
        json.dumps(
            {
                "schema_version": 1,
                "challenge": challenge,
                "entry_id": entry_id,
                "identity": identity,
                "contract_digest": contract_digest,
                "pid": os.getpid(),
                "passed": state.passed(),
            },
            separators=(",", ":"),
        ),
        flush=True,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("serve-notification", "serve-rekor"))
    args = parser.parse_args()
    return serve("notification" if args.mode == "serve-notification" else "rekor")


if __name__ == "__main__":
    raise SystemExit(main())
