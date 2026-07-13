#!/usr/bin/env python3
"""Independent OpenSSL verifier for break-glass rotation and cross-signing."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import signal
import socketserver
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MAX_BODY = 2 << 20


class LoopbackHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing {name}")
    return value


def emit(value: dict[str, object]) -> None:
    print(compact(value).decode(), flush=True)


def decode_json_response(payload: dict[str, object], name: str) -> tuple[dict[str, object], bytes]:
    encoded = payload.get(name)
    if not isinstance(encoded, str) or len(encoded) > 2 * MAX_BODY:
        raise ValueError(f"{name} is absent or oversized")
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > MAX_BODY or b"PRIVATE KEY" in raw:
        raise ValueError(f"{name} is empty, oversized, or contains private key material")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{name} is not a JSON object")
    return value, raw


def decode_pem(payload: dict[str, object], name: str) -> tuple[bytes, bytes]:
    encoded = payload.get(name)
    if not isinstance(encoded, str) or len(encoded) > 2 * MAX_BODY:
        raise ValueError(f"{name} is absent or oversized")
    raw = base64.b64decode(encoded, validate=True)
    if b"BEGIN CERTIFICATE" not in raw or b"PRIVATE KEY" in raw:
        raise ValueError(f"{name} is not public certificate PEM")
    return raw, ssl.PEM_cert_to_DER_cert(raw.decode())


def der_to_pem(der: bytes) -> bytes:
    encoded = base64.b64encode(der).decode()
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


def openssl_verify(work: Path, anchor: bytes, certificate: bytes, label: str) -> None:
    anchor_path = work / f"{label}-anchor.pem"
    cert_path = work / f"{label}-certificate.pem"
    anchor_path.write_bytes(anchor)
    cert_path.write_bytes(certificate)
    completed = subprocess.run(
        ["openssl", "verify", "-purpose", "any", "-CAfile", str(anchor_path), str(cert_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
    )
    if completed.returncode != 0 or b": OK" not in completed.stdout:
        raise ValueError(f"OpenSSL rejected {label}: {completed.stdout.decode(errors='replace')}")


def openssl_verify_chain(work: Path, anchor: bytes, intermediate: bytes, certificate: bytes, label: str) -> None:
    anchor_path = work / f"{label}-anchor.pem"
    intermediate_path = work / f"{label}-intermediate.pem"
    cert_path = work / f"{label}-certificate.pem"
    anchor_path.write_bytes(anchor)
    intermediate_path.write_bytes(intermediate)
    cert_path.write_bytes(certificate)
    completed = subprocess.run(
        ["openssl", "verify", "-purpose", "any", "-CAfile", str(anchor_path), "-untrusted", str(intermediate_path), str(cert_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
    )
    if completed.returncode != 0 or b": OK" not in completed.stdout:
        raise ValueError(f"OpenSSL rejected {label}: {completed.stdout.decode(errors='replace')}")


class State:
    def __init__(self, material: dict[str, bytes], work: Path) -> None:
        self.material = material
        self.target_pem = material["target_certificate_pem"]
        self.work = work
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


def verify_transcript(state: State, payload: dict[str, object]) -> bytes:
    if payload.get("protocol") != "trstctl-breakglass-rotation-v1":
        raise ValueError("wrong protocol marker")
    initial_ca, _ = decode_pem(payload, "initial_ca_pem")
    bootstrap, bootstrap_raw = decode_json_response(payload, "bootstrap_authority")
    if not bootstrap.get("signer_handle") or str(bootstrap.get("certificate_pem", "")).encode().strip() != initial_ca.strip():
        raise ValueError("served CA bootstrap did not return the configured persisted handle and certificate")
    target_ca, target_der = decode_pem(payload, "target_ca_pem")
    if target_ca.strip() != state.target_pem.strip():
        raise ValueError("control plane did not cross-sign the substrate-owned target CA")
    issue_request, issue_request_raw = decode_json_response(payload, "issue_request")
    if "approvals" in issue_request or not issue_request.get("ceremony_id"):
        raise ValueError("online issue execution accepted caller-authored approvers or omitted ceremony binding")
    subquorum, subquorum_raw = decode_json_response(payload, "subquorum")
    mismatch, mismatch_raw = decode_json_response(payload, "exact_mismatch")
    consumed, consumed_raw = decode_json_response(payload, "consumed_replay")
    unauthorized, unauthorized_raw = decode_json_response(payload, "unauthorized_roster")
    cross_tenant, cross_tenant_raw = decode_json_response(payload, "cross_tenant")
    if "quorum" not in str(subquorum.get("detail", "")).lower():
        raise ValueError("sub-quorum request did not fail explicitly")
    if not any(word in str(mismatch.get("detail", "")).lower() for word in ("purpose", "binding", "mismatch")):
        raise ValueError("altered approved request did not fail exact binding")
    if "not pending" not in str(consumed.get("detail", "")).lower():
        raise ValueError("consumed ceremony replay did not fail single-use enforcement")
    unauthorized_detail = str(unauthorized.get("detail", "")).lower()
    if "not an authorized break-glass operator" not in unauthorized_detail:
        raise ValueError("authenticated actor outside the configured roster gained quorum authority")
    cross_tenant_wire = json.dumps(cross_tenant, sort_keys=True).lower()
    if (cross_tenant.get("code") != "problem.internal.error" or cross_tenant.get("status") != 500 or
            "internal error" not in str(cross_tenant.get("detail", "")).lower()):
        raise ValueError("cross-tenant request did not fail closed with the stable redacted problem")
    if "configured online break-glass tenant" in cross_tenant_wire or "d0d00000" in cross_tenant_wire:
        raise ValueError("cross-tenant failure leaked configured tenant identity")

    initial_issue, initial_issue_raw = decode_json_response(payload, "initial_issue")
    rotation, rotation_raw = decode_json_response(payload, "rotation")
    restarted_issue, restarted_issue_raw = decode_json_response(payload, "restarted_issue")
    cross_sign, cross_sign_raw = decode_json_response(payload, "cross_sign")
    signer_ca, signer_ca_raw = decode_json_response(payload, "signer_ca")
    signer_ca_cross, signer_ca_cross_raw = decode_json_response(payload, "signer_ca_cross")
    offline_rekey, offline_rekey_raw = decode_json_response(payload, "offline_rekey")
    offline_cross, offline_cross_raw = decode_json_response(payload, "offline_cross_import")
    if rotation.get("previous_signer_handle") == rotation.get("active_signer_handle"):
        raise ValueError("rotation did not advance the signer handle")
    request_digest = rotation.get("request_digest")
    if not isinstance(request_digest, str) or len(request_digest) != 64:
        raise ValueError("rotation has no exact SHA-256 request binding")

    old_pem = str(rotation.get("previous_certificate_pem", "")).encode()
    new_pem = str(rotation.get("active_certificate_pem", "")).encode()
    new_by_old = str(rotation.get("new_signed_by_previous_pem", "")).encode()
    old_by_new = str(rotation.get("previous_signed_by_new_pem", "")).encode()
    if old_pem.strip() != initial_ca.strip():
        raise ValueError("rotation predecessor differs from configured CA")
    for name, value in (("new CA", new_pem), ("new-by-old", new_by_old), ("old-by-new", old_by_new)):
        if b"BEGIN CERTIFICATE" not in value or b"PRIVATE KEY" in value:
            raise ValueError(f"{name} is not public certificate PEM")
    openssl_verify(state.work, old_pem, new_by_old, "new-by-previous")
    openssl_verify(state.work, new_pem, old_by_new, "previous-by-new")

    initial_bundle = initial_issue.get("bundle")
    restarted_bundle = restarted_issue.get("bundle")
    if not isinstance(initial_bundle, dict) or not isinstance(restarted_bundle, dict):
        raise ValueError("issue response has no signed bundle")
    initial_leaf = der_to_pem(base64.b64decode(str(initial_bundle.get("cert_der", "")), validate=True))
    restarted_leaf = der_to_pem(base64.b64decode(str(restarted_bundle.get("cert_der", "")), validate=True))
    openssl_verify(state.work, old_pem, initial_leaf, "initial-emergency-leaf")
    openssl_verify(state.work, new_pem, restarted_leaf, "restarted-rotated-emergency-leaf")
    openssl_verify_chain(state.work, old_pem, new_by_old, restarted_leaf, "restarted-leaf-through-new-by-previous")
    openssl_verify_chain(state.work, new_pem, old_by_new, initial_leaf, "initial-leaf-through-previous-by-new")
    if sorted(restarted_bundle.get("approvals", [])) != ["dod-operator-a", "dod-operator-b"]:
        raise ValueError("restarted issuance did not derive the immutable configured approvers")

    cross_pem = str(cross_sign.get("certificate_pem", "")).encode()
    if cross_sign.get("target_sha256") != hashlib.sha256(target_der).hexdigest():
        raise ValueError("cross-sign response is not bound to the substrate target")
    openssl_verify(state.work, new_pem, cross_pem, "external-target-cross-certificate")
    openssl_verify_chain(state.work, new_pem, cross_pem, state.material["target_leaf_pem"], "external-target-leaf-through-breakglass-cross")

    signer_ca_pem = str(signer_ca.get("certificate_pem", "")).encode()
    signer_ca_cross_pem = str(signer_ca_cross.get("certificate_pem", "")).encode()
    openssl_verify(state.work, signer_ca_pem, signer_ca_cross_pem, "signer-backed-authority-cross-certificate")
    openssl_verify_chain(state.work, signer_ca_pem, signer_ca_cross_pem, state.material["target_leaf_pem"], "target-leaf-through-signer-backed-cross")

    offline_rotation = offline_rekey.get("rotation")
    if not isinstance(offline_rotation, dict):
        raise ValueError("offline-root re-key response has no rotation")
    offline_old = str(offline_rotation.get("predecessor", {}).get("certificate_pem", "")).encode()
    offline_new = str(offline_rotation.get("successor", {}).get("certificate_pem", "")).encode()
    offline_new_by_old = str(offline_rekey.get("new_signed_by_previous_pem", "")).encode()
    offline_old_by_new = str(offline_rekey.get("previous_signed_by_new_pem", "")).encode()
    openssl_verify(state.work, offline_old, offline_new_by_old, "offline-new-by-previous")
    openssl_verify(state.work, offline_new, offline_old_by_new, "offline-previous-by-new")
    openssl_verify_chain(state.work, offline_old, offline_new_by_old, state.material["offline_successor_leaf_pem"], "offline-successor-leaf-through-previous")
    openssl_verify_chain(state.work, offline_new, offline_old_by_new, state.material["offline_previous_leaf_pem"], "offline-previous-leaf-through-successor")
    offline_import_pem = str(offline_cross.get("certificate_pem", "")).encode()
    if offline_cross.get("imported") is not True:
        raise ValueError("offline cross-sign workflow was not recorded as imported")
    openssl_verify(state.work, offline_new, offline_import_pem, "offline-root-imported-target-cross-certificate")
    openssl_verify_chain(state.work, offline_new, offline_import_pem, state.material["target_leaf_pem"], "target-leaf-through-offline-imported-cross")

    transcript = b"".join((
        bootstrap_raw, issue_request_raw, subquorum_raw, mismatch_raw, consumed_raw,
        unauthorized_raw, cross_tenant_raw, initial_issue_raw, rotation_raw,
        restarted_issue_raw, target_ca, cross_sign_raw, signer_ca_raw,
        signer_ca_cross_raw, offline_rekey_raw, offline_cross_raw,
    ))
    return compact({
        "protocol": "trstctl-breakglass-rotation-v1",
        "checks": 26,
        "openssl": subprocess.run(["openssl", "version"], check=True, stdout=subprocess.PIPE, timeout=5).stdout.decode().strip(),
        "target_sha256": hashlib.sha256(target_der).hexdigest(),
        "transcript_sha256": hashlib.sha256(transcript).hexdigest(),
    })


class Handler(BaseHTTPRequestHandler):
    server_version = "trstctl-dod-breakglass-openssl/1"

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
        if self.path == "/v1/target":
            self.send_bytes(200, self.state.target_pem, "application/x-pem-file")
            return
        if self.path == "/v1/offline-package":
            body = compact({key: value.decode() for key, value in self.state.material.items()})
            self.send_bytes(200, body)
            return
        if self.path == "/dod/readback":
            with self.state.lock:
                body = self.state.readback
            self.send_bytes(200 if body else 404, body or compact({"error": "no verified transcript"}))
            return
        self.send_bytes(404, compact({"error": "not found"}))

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
            readback = verify_transcript(self.state, payload)
        except Exception as exc:
            self.state.fail()
            self.send_bytes(422, compact({"error": str(exc)}))
            return
        self.state.accept(readback)
        self.send_bytes(200, readback)


def generate_root(work: Path, name: str, common_name: str, path_len: int) -> tuple[Path, Path, Path]:
    key = work / f"{name}.key"
    cert = work / f"{name}.pem"
    csr = work / f"{name}.csr"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2",
        "-subj", f"/CN={common_name}",
        "-addext", f"basicConstraints=critical,CA:TRUE,pathlen:{path_len}",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    subprocess.run([
        "openssl", "req", "-new", "-key", str(key), "-out", str(csr),
        "-subj", f"/CN={common_name}",
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return key, cert, csr


def cross_sign(work: Path, name: str, csr: Path, issuer_cert: Path, issuer_key: Path, serial: int, path_len: int) -> Path:
    extensions = work / "ca-extensions.cnf"
    extensions.write_text(
        f"basicConstraints=critical,CA:TRUE,pathlen:{path_len}\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid\n"
    )
    output = work / f"{name}.pem"
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(csr), "-CA", str(issuer_cert),
        "-CAkey", str(issuer_key), "-set_serial", str(serial), "-days", "1",
        "-extfile", str(extensions), "-out", str(output),
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return output


def generate_leaf(work: Path, name: str, common_name: str, issuer_cert: Path, issuer_key: Path, serial: int) -> Path:
    key = work / f"{name}.key"
    csr = work / f"{name}.csr"
    cert = work / f"{name}.pem"
    extensions = work / f"{name}-extensions.cnf"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{common_name}\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid\n"
    )
    subprocess.run([
        "openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={common_name}",
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(csr), "-CA", str(issuer_cert),
        "-CAkey", str(issuer_key), "-set_serial", str(serial), "-days", "1",
        "-extfile", str(extensions), "-out", str(cert),
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    return cert


def generate_material(work: Path) -> dict[str, bytes]:
    target_key, target_cert, target_csr = generate_root(work, "target", "Independent DoD Cross Sign Target", 0)
    old_key, old_cert, old_csr = generate_root(work, "offline-old", "Independent Offline Root", 1)
    new_key, new_cert, new_csr = generate_root(work, "offline-new", "Independent Offline Root", 1)
    new_by_old = cross_sign(work, "offline-new-by-old", new_csr, old_cert, old_key, 2001, 1)
    old_by_new = cross_sign(work, "offline-old-by-new", old_csr, new_cert, new_key, 2002, 1)
    target_by_new = cross_sign(work, "target-by-offline-new", target_csr, new_cert, new_key, 2003, 0)
    target_leaf = generate_leaf(work, "target-leaf", "target-leaf.dod-breakglass.test", target_cert, target_key, 3001)
    old_leaf = generate_leaf(work, "offline-old-leaf", "old-leaf.dod.test", old_cert, old_key, 3002)
    new_leaf = generate_leaf(work, "offline-new-leaf", "new-leaf.dod.test", new_cert, new_key, 3003)
    _ = target_key  # private keys remain only inside this substrate work directory
    return {
        "target_certificate_pem": target_cert.read_bytes(),
        "offline_previous_certificate_pem": old_cert.read_bytes(),
        "offline_successor_certificate_pem": new_cert.read_bytes(),
        "new_signed_by_previous_pem": new_by_old.read_bytes(),
        "previous_signed_by_new_pem": old_by_new.read_bytes(),
        "target_signed_by_new_pem": target_by_new.read_bytes(),
        "target_leaf_pem": target_leaf.read_bytes(),
        "offline_previous_leaf_pem": old_leaf.read_bytes(),
        "offline_successor_leaf_pem": new_leaf.read_bytes(),
    }


def serve() -> int:
    challenge = required("TRSTCTL_DOD_CHALLENGE")
    entry_id = required("TRSTCTL_DOD_ENTRY_ID")
    identity = required("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = required("TRSTCTL_DOD_CONTRACT_DIGEST")
    if entry_id != "breakglass_rotation.cross_sign_rekey":
        raise SystemExit("wrong entry id")
    work = Path(tempfile.mkdtemp(prefix="trstctl-breakglass-openssl-"))
    try:
        state = State(generate_material(work), work)
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
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(serve())
