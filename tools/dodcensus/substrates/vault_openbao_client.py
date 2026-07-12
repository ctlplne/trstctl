#!/usr/bin/env python3
"""Nonce-bound independent Vault/OpenBao v1 transcript verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY = 1 << 20


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


def decoded_response(payload: dict[str, object], name: str) -> tuple[dict[str, object], bytes]:
    encoded = payload.get(name)
    if not isinstance(encoded, str) or len(encoded) > 2 * MAX_BODY:
        raise ValueError(f"{name} is missing or oversized")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_BODY:
        raise ValueError(f"{name} response is empty or oversized")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{name} response is not an object")
    return value, raw


def envelope_data(response: dict[str, object], name: str) -> dict[str, object]:
    data = response.get("data")
    if not isinstance(data, dict):
        raise ValueError(f"{name} has no Vault data object")
    return data


def verify_vault(payload: dict[str, object]) -> bytes:
    if payload.get("protocol") != "vault-openbao-v1":
        raise ValueError("wrong protocol marker")
    plaintext = payload.get("plaintext_b64")
    if not isinstance(plaintext, str) or len(base64.b64decode(plaintext, validate=True)) < 16:
        raise ValueError("invalid transit plaintext witness")

    acl_authored, acl_authored_raw = decoded_response(payload, "acl_authored")
    authored_data = envelope_data(acl_authored, "acl_authored")
    if authored_data.get("name") != "api-token" or 'path "*"' not in str(authored_data.get("policy", "")):
        raise ValueError("authored token ACL cannot be read back exactly")
    acl_list_before, acl_list_before_raw = decoded_response(payload, "acl_list_before_delete")
    before_keys = envelope_data(acl_list_before, "acl_list_before_delete").get("keys")
    if not isinstance(before_keys, list) or not {"api-token", "lifecycle"}.issubset(set(before_keys)):
        raise ValueError("ACL list does not contain both authored policies")
    acl_read, acl_read_raw = decoded_response(payload, "acl_read")
    read_data = envelope_data(acl_read, "acl_read")
    if read_data.get("name") != "lifecycle" or read_data.get("policy") != authored_data.get("policy"):
        raise ValueError("ACL read does not return the exact authored lifecycle policy")
    acl_list_after, acl_list_after_raw = decoded_response(payload, "acl_list_after_delete")
    after_keys = envelope_data(acl_list_after, "acl_list_after_delete").get("keys")
    if not isinstance(after_keys, list) or "api-token" not in after_keys or "lifecycle" in after_keys:
        raise ValueError("ACL delete did not remove exactly the lifecycle policy")

    mounts, mounts_raw = decoded_response(payload, "mounts")
    mount_data = envelope_data(mounts, "mounts")
    expected_mounts = {
        "application-secrets/": "kv",
        "application-transit/": "transit",
        "application-pki/": "pki",
    }
    for path, kind in expected_mounts.items():
        item = mount_data.get(path)
        if not isinstance(item, dict) or item.get("type") != kind:
            raise ValueError(f"mount {path} is absent or has the wrong type")
    mounts_after_disable, mounts_after_disable_raw = decoded_response(payload, "mounts_after_disable")
    disabled_data = envelope_data(mounts_after_disable, "mounts_after_disable")
    if "application-secrets/" in disabled_data:
        raise ValueError("disabled KV mount remains listed")
    for path in ("application-transit/", "application-pki/"):
        if path not in disabled_data:
            raise ValueError("mount disable removed an unrelated authored mount")

    discovery, discovery_raw = decoded_response(payload, "discovery")
    discovery_data = envelope_data(discovery, "discovery")
    if discovery_data.get("path") != "application-transit/" or discovery_data.get("type") != "transit":
        raise ValueError("mount discovery did not resolve the authored transit mount")

    builtin, builtin_raw = decoded_response(payload, "builtin_kv")
    mounted, mounted_raw = decoded_response(payload, "mounted_kv")
    builtin_value = envelope_data(builtin, "builtin_kv").get("data")
    mounted_value = envelope_data(mounted, "mounted_kv").get("data")
    if not isinstance(builtin_value, dict) or builtin_value.get("source") != "builtin":
        raise ValueError("built-in KV response has the wrong value")
    if not isinstance(mounted_value, dict) or mounted_value.get("source") != "mounted":
        raise ValueError("authored KV mount is not independently namespaced")

    encrypted_v1, encrypted_v1_raw = decoded_response(payload, "encrypt_v1")
    ciphertext_v1 = envelope_data(encrypted_v1, "encrypt_v1").get("ciphertext")
    if not isinstance(ciphertext_v1, str) or not ciphertext_v1.startswith("vault:v1:") or len(ciphertext_v1) < 32:
        raise ValueError("pre-rotation transit ciphertext is not a Vault v1 wire value")
    encrypted_v2, encrypted_v2_raw = decoded_response(payload, "encrypt_v2")
    ciphertext_v2 = envelope_data(encrypted_v2, "encrypt_v2").get("ciphertext")
    if not isinstance(ciphertext_v2, str) or not ciphertext_v2.startswith("vault:v2:") or ciphertext_v2 == ciphertext_v1:
        raise ValueError("transit rotate did not advance new ciphertext to key version 2")
    rewrapped, rewrapped_raw = decoded_response(payload, "rewrap")
    rewrapped_ciphertext = envelope_data(rewrapped, "rewrap").get("ciphertext")
    if not isinstance(rewrapped_ciphertext, str) or not rewrapped_ciphertext.startswith("vault:v2:") or rewrapped_ciphertext in (ciphertext_v1, ciphertext_v2):
        raise ValueError("transit rewrap did not produce fresh Vault v2 ciphertext")
    decrypted, decrypted_raw = decoded_response(payload, "decrypt_rewrapped")
    if envelope_data(decrypted, "decrypt_rewrapped").get("plaintext") != plaintext:
        raise ValueError("transit decrypt of rewrapped ciphertext did not reproduce the exact input")

    hmac_response, hmac_raw = decoded_response(payload, "hmac")
    hmac_value = envelope_data(hmac_response, "hmac").get("hmac")
    if not isinstance(hmac_value, str) or not hmac_value.startswith("vault:v1:"):
        raise ValueError("transit HMAC is not a Vault versioned wire value")
    hmac_bytes = base64.b64decode(hmac_value.split(":", 2)[2], validate=True)
    if len(hmac_bytes) != 32:
        raise ValueError("transit HMAC is not SHA2-256 length")
    signed, signed_raw = decoded_response(payload, "sign")
    signature = envelope_data(signed, "sign").get("signature")
    if not isinstance(signature, str) or not signature.startswith("vault:v1:"):
        raise ValueError("transit signature is not a Vault versioned wire value")
    packed_signature = base64.b64decode(signature.split(":", 2)[2], validate=True)
    if len(packed_signature) < 8:
        raise ValueError("transit signature payload is truncated")
    public_length = int.from_bytes(packed_signature[:4], "big")
    if public_length < 16 or public_length >= len(packed_signature) - 4:
        raise ValueError("transit signature public-key framing is invalid")
    verified, verified_raw = decoded_response(payload, "verify")
    if envelope_data(verified, "verify").get("valid") is not True:
        raise ValueError("transit verify did not accept the exact signed input")

    pki, pki_raw = decoded_response(payload, "pki")
    pki_data = envelope_data(pki, "pki")
    if "BEGIN CERTIFICATE" not in str(pki_data.get("certificate", "")):
        raise ValueError("PKI response has no PEM certificate")
    if "BEGIN PRIVATE KEY" not in str(pki_data.get("private_key", "")):
        raise ValueError("PKI response has no PEM private key")
    if not str(pki_data.get("serial_number", "")):
        raise ValueError("PKI response has no serial number")

    denied, denied_raw = decoded_response(payload, "acl_denied")
    errors = denied.get("errors")
    if not isinstance(errors, list) or not any("ACL policy" in str(item) for item in errors):
        raise ValueError("authored ACL did not produce an explicit denial")

    transcript = b"".join((
        acl_authored_raw, acl_list_before_raw, acl_read_raw, acl_list_after_raw,
        mounts_raw, mounts_after_disable_raw, discovery_raw, builtin_raw, mounted_raw,
        encrypted_v1_raw, encrypted_v2_raw, rewrapped_raw, decrypted_raw,
        hmac_raw, signed_raw, verified_raw, pki_raw, denied_raw,
    ))
    return compact({
        "protocol": "vault-openbao-v1",
        "checks": 18,
        "transcript_sha256": hashlib.sha256(transcript).hexdigest(),
        "rewrapped_ciphertext_sha256": hashlib.sha256(rewrapped_ciphertext.encode()).hexdigest(),
        "signature_sha256": hashlib.sha256(signature.encode()).hexdigest(),
    })


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.readback = b""
        self.accepted = 0
        self.failures = 0

    def accept(self, readback: bytes) -> None:
        with self.lock:
            self.readback = readback
            self.accepted += 1

    def fail(self) -> None:
        with self.lock:
            self.failures += 1

    def passed(self) -> bool:
        with self.lock:
            return self.accepted == 1 and self.failures == 0 and len(self.readback) >= 16


class Handler(BaseHTTPRequestHandler):
    server_version = "trstctl-dod-vault-client/1"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_args: object) -> None:
        return

    def send_bytes(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/dod/readback":
            self.send_bytes(404, compact({"error": "not found"}))
            return
        with self.state.lock:
            body = self.state.readback
        self.send_bytes(200 if body else 404, body or compact({"error": "no verified transcript"}))

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/verify":
            self.send_bytes(404, compact({"error": "not found"}))
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid body length")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("body is not an object")
            readback = verify_vault(payload)
        except Exception as exc:  # independent verifier must fail closed
            self.state.fail()
            self.send_bytes(422, compact({"error": str(exc)}))
            return
        self.state.accept(readback)
        self.send_bytes(200, readback)


def serve() -> int:
    challenge = required("TRSTCTL_DOD_CHALLENGE")
    entry_id = required("TRSTCTL_DOD_ENTRY_ID")
    identity = required("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = required("TRSTCTL_DOD_CONTRACT_DIGEST")
    if entry_id != "secrets_residuals.vault_shim_acl_transit":
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
