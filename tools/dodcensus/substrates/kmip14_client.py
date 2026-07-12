#!/usr/bin/env python3
"""Nonce-bound independent OASIS KMIP 1.4 TTLV transcript verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import socketserver
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY = 1 << 20
MAX_FIELDS = 4096
MAX_DEPTH = 16

STRUCTURE = 0x01
INTEGER = 0x02
ENUMERATION = 0x05
TEXT = 0x07
BYTES = 0x08

TAG_BATCH_ITEM = 0x42000F
TAG_BLOCK_CIPHER_MODE = 0x420011
TAG_IV = 0x42003D
TAG_KEY_MATERIAL = 0x420043
TAG_KEY_VALUE = 0x420045
TAG_KEY_WRAPPING_DATA = 0x420046
TAG_MAC = 0x42004D
TAG_OPERATION = 0x42005C
TAG_PROFILE_NAME = 0x4200EC
TAG_PROTOCOL_VERSION = 0x420069
TAG_PROTOCOL_MAJOR = 0x42006A
TAG_PROTOCOL_MINOR = 0x42006B
TAG_RESPONSE_MESSAGE = 0x42007B
TAG_RESPONSE_PAYLOAD = 0x42007C
TAG_RESULT_STATUS = 0x42007F
TAG_UNIQUE_IDENTIFIER = 0x420094
TAG_WRAPPING_METHOD = 0x42009E
TAG_ENCODING_OPTION = 0x4200A3

OP_REGISTER = 0x03
OP_GET = 0x0A
OP_QUERY = 0x18
OP_DISCOVER = 0x1E
STATUS_SUCCESS = 0
STATUS_FAILED = 1
PROFILE_LIFECYCLE_14 = 0x82
PROFILE_FOUNDRY_14 = 0x8E


class LoopbackHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing {name}")
    return value


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def emit(value: dict[str, object]) -> None:
    print(compact(value).decode(), flush=True)


@dataclass
class Node:
    tag: int
    kind: int
    value: bytes
    children: list["Node"]


class Parser:
    def __init__(self) -> None:
        self.fields = 0

    def parse(self, raw: bytes) -> Node:
        if not raw or len(raw) > MAX_BODY:
            raise ValueError("TTLV frame is empty or oversized")
        node, used = self.item(raw, 1)
        if used != len(raw):
            raise ValueError("TTLV frame has trailing bytes")
        return node

    def item(self, raw: bytes, depth: int) -> tuple[Node, int]:
        if depth > MAX_DEPTH or len(raw) < 8:
            raise ValueError("TTLV depth/header bound exceeded")
        self.fields += 1
        if self.fields > MAX_FIELDS:
            raise ValueError("TTLV field bound exceeded")
        tag = int.from_bytes(raw[0:3], "big")
        kind = raw[3]
        length = int.from_bytes(raw[4:8], "big")
        padding = (8 - length % 8) % 8
        total = 8 + length + padding
        if length > MAX_BODY or total > len(raw):
            raise ValueError("TTLV length exceeds frame")
        value = raw[8 : 8 + length]
        children: list[Node] = []
        if kind == STRUCTURE:
            offset = 0
            while offset < len(value):
                child, used = self.item(value[offset:], depth + 1)
                children.append(child)
                offset += used
        elif kind in (INTEGER, ENUMERATION):
            if length != 4:
                raise ValueError("TTLV integer/enumeration has wrong length")
        elif kind not in (TEXT, BYTES, 0x03, 0x04, 0x06, 0x09, 0x0A):
            raise ValueError("TTLV type is unsupported")
        return Node(tag, kind, value, children), total


def decode_frame(payload: dict[str, object], name: str) -> tuple[Node, bytes]:
    encoded = payload.get(name)
    if not isinstance(encoded, str) or len(encoded) > 2 * MAX_BODY:
        raise ValueError(f"{name} is missing or oversized")
    raw = base64.b64decode(encoded, validate=True)
    root = Parser().parse(raw)
    if root.tag != TAG_RESPONSE_MESSAGE or root.kind != STRUCTURE:
        raise ValueError(f"{name} is not a KMIP ResponseMessage")
    return root, raw


def walk(node: Node):
    yield node
    for child in node.children:
        yield from walk(child)


def values(root: Node, tag: int, kind: int | None = None) -> list[bytes]:
    return [node.value for node in walk(root) if node.tag == tag and (kind is None or node.kind == kind)]


def enums(root: Node, tag: int) -> list[int]:
    return [int.from_bytes(value, "big") for value in values(root, tag, ENUMERATION)]


def integers(root: Node, tag: int) -> list[int]:
    return [int.from_bytes(value, "big", signed=True) for value in values(root, tag, INTEGER)]


def response_batch_item(root: Node, operation: int) -> Node:
    for item in (child for child in root.children if child.tag == TAG_BATCH_ITEM):
        # Batch metadata is direct-child scoped. Query's ResponsePayload also
        # contains Operation values describing the server's supported catalog;
        # recursively collecting them makes a valid Query batch look ambiguous.
        operations = [
            int.from_bytes(child.value, "big")
            for child in item.children
            if child.tag == TAG_OPERATION and child.kind == ENUMERATION
        ]
        if operations == [operation]:
            return item
    raise ValueError(f"response has no batch item for operation {operation:#x}")


def batch_status(root: Node, operation: int) -> int:
    item = response_batch_item(root, operation)
    statuses = [
        int.from_bytes(child.value, "big")
        for child in item.children
        if child.tag == TAG_RESULT_STATUS and child.kind == ENUMERATION
    ]
    if len(statuses) != 1:
        raise ValueError(f"response has no unique status for operation {operation:#x}")
    return statuses[0]


def batch_payload(root: Node, operation: int) -> Node:
    item = response_batch_item(root, operation)
    payloads = [child for child in item.children if child.tag == TAG_RESPONSE_PAYLOAD and child.kind == STRUCTURE]
    if len(payloads) != 1:
        raise ValueError(f"response has no unique payload for operation {operation:#x}")
    return payloads[0]


def verify_kmip(payload: dict[str, object]) -> bytes:
    if payload.get("protocol") != "oasis-kmip-1.4":
        raise ValueError("wrong protocol marker")
    key_encoded = payload.get("key_material_b64")
    if not isinstance(key_encoded, str):
        raise ValueError("missing key material witness")
    key_material = base64.b64decode(key_encoded, validate=True)
    if len(key_material) != 32:
        raise ValueError("key material witness is not AES-256")

    query, query_raw = decode_frame(payload, "query")
    if batch_status(query, OP_QUERY) != STATUS_SUCCESS:
        raise ValueError("Query did not succeed")
    operations = set(enums(query, TAG_OPERATION))
    profiles = set(enums(query, TAG_PROFILE_NAME))
    if not {OP_REGISTER, OP_DISCOVER}.issubset(operations):
        raise ValueError("Query omitted Register or DiscoverVersions")
    if not {PROFILE_LIFECYCLE_14, PROFILE_FOUNDRY_14}.issubset(profiles):
        raise ValueError("Query omitted required KMIP 1.4 profiles")

    discover, discover_raw = decode_frame(payload, "discover")
    if batch_status(discover, OP_DISCOVER) != STATUS_SUCCESS:
        raise ValueError("DiscoverVersions did not succeed")
    versions = []
    for node in walk(batch_payload(discover, OP_DISCOVER)):
        if node.tag == TAG_PROTOCOL_VERSION and node.kind == STRUCTURE:
            major = integers(node, TAG_PROTOCOL_MAJOR)
            minor = integers(node, TAG_PROTOCOL_MINOR)
            if len(major) == 1 and len(minor) == 1:
                versions.append((major[0], minor[0]))
    if versions != [(1, 4)]:
        raise ValueError(f"DiscoverVersions negotiated {versions!r}, not only 1.4")

    register, register_raw = decode_frame(payload, "register")
    if batch_status(register, OP_REGISTER) != STATUS_SUCCESS:
        raise ValueError("Register did not succeed")
    identifiers = values(register, TAG_UNIQUE_IDENTIFIER, TEXT)
    if len(identifiers) != 1 or not identifiers[0]:
        raise ValueError("Register returned no unique identifier")

    wrapped, wrapped_raw = decode_frame(payload, "wrapped_get")
    if batch_status(wrapped, OP_GET) != STATUS_SUCCESS:
        raise ValueError("wrapped Get did not succeed")
    wrapping_nodes = [node for node in walk(wrapped) if node.tag == TAG_KEY_WRAPPING_DATA and node.kind == STRUCTURE]
    if len(wrapping_nodes) != 1:
        raise ValueError("wrapped Get has no unique KeyWrappingData")
    wrapping = wrapping_nodes[0]
    if enums(wrapping, TAG_WRAPPING_METHOD) != [1] or enums(wrapping, TAG_ENCODING_OPTION) != [1]:
        raise ValueError("wrapped Get did not use Encrypt + NoEncoding")
    if [len(value) for value in values(wrapping, TAG_IV, BYTES)] != [12]:
        raise ValueError("wrapped Get does not carry a 12-byte GCM nonce")
    if [len(value) for value in values(wrapping, TAG_MAC, BYTES)] != [16]:
        raise ValueError("wrapped Get does not carry a 16-byte GCM tag")
    wrapped_values = values(wrapped, TAG_KEY_VALUE, BYTES)
    if len(wrapped_values) != 1 or len(wrapped_values[0]) != 32 or wrapped_values[0] == key_material:
        raise ValueError("wrapped KeyValue is missing, wrong-sized, or plaintext")

    clone, clone_raw = decode_frame(payload, "clone_get")
    if batch_status(clone, OP_GET) != STATUS_SUCCESS or values(clone, TAG_KEY_MATERIAL, BYTES) != [key_material]:
        raise ValueError("wrapped Register did not reproduce exact AES key material")
    revoked, revoked_raw = decode_frame(payload, "replayed_revoked_get")
    destroyed, destroyed_raw = decode_frame(payload, "replayed_destroyed_get")
    if batch_status(revoked, OP_GET) != STATUS_FAILED or batch_status(destroyed, OP_GET) != STATUS_FAILED:
        raise ValueError("restart replay did not preserve revoke/destroy states")

    transcript = b"".join((query_raw, discover_raw, register_raw, wrapped_raw, clone_raw, revoked_raw, destroyed_raw))
    return compact({
        "protocol": "oasis-kmip-1.4",
        "checks": 7,
        "transcript_sha256": hashlib.sha256(transcript).hexdigest(),
        "wrapped_key_sha256": hashlib.sha256(wrapped_values[0]).hexdigest(),
    })


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.readback = b""
        self.accepted = 0
        self.failures = 0

    def passed(self) -> bool:
        with self.lock:
            return self.accepted == 1 and self.failures == 0 and len(self.readback) >= 16


class Handler(BaseHTTPRequestHandler):
    server_version = "trstctl-dod-kmip-client/1"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_args: object) -> None:
        return

    def send_json(self, status: int, value: object) -> None:
        body = value if isinstance(value, bytes) else compact(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/dod/readback":
            self.send_json(404, {"error": "not found"})
            return
        with self.state.lock:
            body = self.state.readback
        self.send_json(200 if body else 404, body or compact({"error": "no verified transcript"}))

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/verify":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid body length")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("body is not an object")
            readback = verify_kmip(payload)
        except Exception as exc:
            with self.state.lock:
                self.state.failures += 1
            self.send_json(422, {"error": str(exc)})
            return
        with self.state.lock:
            self.state.readback = readback
            self.state.accepted += 1
        self.send_json(200, readback)


def serve() -> int:
    challenge = required("TRSTCTL_DOD_CHALLENGE")
    entry_id = required("TRSTCTL_DOD_ENTRY_ID")
    identity = required("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = required("TRSTCTL_DOD_CONTRACT_DIGEST")
    if entry_id != "secrets_residuals.kmip_wrapping_profile_negotiation":
        raise SystemExit("wrong entry id")
    state = State()
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
