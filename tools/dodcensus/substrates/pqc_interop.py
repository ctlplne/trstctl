#!/usr/bin/env python3
"""Independent OpenSSL 3.5+ verifier and Envoy TLS-posture emulator for PQC DoD."""

from __future__ import annotations

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
from urllib.parse import unquote, urlparse


MAX_BODY = 8 << 20
PQC_103 = "pqc_end_to_end.automated_rollout_tls_findings"


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing {name}")
    return value


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def emit(value: dict) -> None:
    print(compact(value).decode(), flush=True)


def run(args: list[str]) -> bytes:
    openssl_conf = os.environ.get("OPENSSL_CONF", "")
    if openssl_conf != "/dev/null":
        raise ValueError("independent OpenSSL client configuration is not the pinned empty profile")
    result = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
        check=False,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "OPENSSL_CONF": openssl_conf,
        },
    )
    if result.returncode != 0:
        raise ValueError(f"independent command failed ({' '.join(args[:4])}): {result.stdout[:1000]!r}")
    return result.stdout


def decode(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} is not base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{label} is not canonical base64") from exc
    if not raw:
        raise ValueError(f"{label} is empty")
    return raw


def write(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    path.chmod(0o600)


def pem_certificates(raw: bytes) -> list[bytes]:
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    out: list[bytes] = []
    cursor = 0
    while True:
        start = raw.find(begin, cursor)
        if start < 0:
            break
        stop = raw.find(end, start)
        if stop < 0:
            raise ValueError("truncated PEM certificate set")
        stop += len(end)
        out.append(raw[start:stop] + b"\n")
        cursor = stop
    return out


def verify_pure(payload: dict, root: Path) -> dict:
    ca = payload.get("ca_pem", "")
    if not isinstance(ca, str) or "BEGIN CERTIFICATE" not in ca:
        raise ValueError("pure ML-DSA transcript omitted CA PEM")
    ca_file = root / "ca.pem"
    csr_file = root / "pure.csr"
    p7_file = root / "pure.p7"
    certs_file = root / "pure-certs.pem"
    write(ca_file, ca.encode())
    write(csr_file, decode(payload.get("csr_der_b64"), "pure CSR"))
    write(p7_file, decode(payload.get("est_pkcs7_der_b64"), "EST PKCS7"))
    run(["openssl", "req", "-inform", "DER", "-in", str(csr_file), "-verify", "-noout"])
    certs = run(["openssl", "pkcs7", "-inform", "DER", "-in", str(p7_file), "-print_certs"])
    write(certs_file, certs)
    leaf_file = root / "pure-leaf.pem"
    leaf_text = b""
    for index, candidate in enumerate(pem_certificates(certs)):
        path = root / f"candidate-{index}.pem"
        write(path, candidate)
        text = run(["openssl", "x509", "-in", str(path), "-noout", "-text"])
        if b"ML-DSA-65" in text and b"pure-mldsa.dod.test" in text:
            write(leaf_file, candidate)
            leaf_text = text
            break
    if not leaf_text:
        raise ValueError("EST response contained no pure ML-DSA-65 subject leaf")
    run(["openssl", "verify", "-CAfile", str(ca_file), str(leaf_file)])
    csr_pub = run(["openssl", "req", "-inform", "DER", "-in", str(csr_file), "-pubkey", "-noout"])
    leaf_pub = run(["openssl", "x509", "-in", str(leaf_file), "-pubkey", "-noout"])
    if csr_pub != leaf_pub:
        raise ValueError("served pure leaf public key differs from stock-client CSR")
    return {
        "mode": "pure_mldsa_leaf",
        "leaf_sha256": hashlib.sha256(leaf_file.read_bytes()).hexdigest(),
        "stock_client": run(["openssl", "version"]).decode().strip(),
    }


def verify_spiffe(payload: dict, root: Path) -> dict:
    ca = payload.get("ca_pem", "")
    items = payload.get("svids")
    if not isinstance(ca, str) or not isinstance(items, list) or len(items) != 2:
        raise ValueError("hybrid SPIFFE transcript must contain CA plus exactly two SVIDs")
    ca_file = root / "ca.pem"
    write(ca_file, ca.encode())
    identities: list[str] = []
    hints: list[str] = []
    algorithms: list[str] = []
    digests: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError("SPIFFE SVID entry is not an object")
        identity = item.get("spiffe_id")
        hint = item.get("hint")
        if not isinstance(identity, str) or not isinstance(hint, str) or not hint:
            raise ValueError("SPIFFE SVID omitted identity/hint")
        identities.append(identity)
        hints.append(hint)
        cert_der = decode(item.get("certificate_der_b64"), f"SVID {index} certificate")
        key_der = decode(item.get("private_key_der_b64"), f"SVID {index} private key")
        bundle_der = decode(item.get("bundle_der_b64"), f"SVID {index} bundle")
        cert_der_file = root / f"svid-{index}.der"
        cert_file = root / f"svid-{index}.pem"
        key_file = root / f"svid-{index}.key.der"
        bundle_file = root / f"svid-{index}-bundle.der"
        write(cert_der_file, cert_der)
        write(key_file, key_der)
        write(bundle_file, bundle_der)
        cert_pem = run(["openssl", "x509", "-inform", "DER", "-in", str(cert_der_file), "-outform", "PEM"])
        write(cert_file, cert_pem)
        text = run(["openssl", "x509", "-in", str(cert_file), "-noout", "-text"])
        if identity.encode() not in text:
            raise ValueError("SPIFFE certificate omitted its URI SAN")
        run(["openssl", "verify", "-CAfile", str(ca_file), str(cert_file)])
        run(["openssl", "pkey", "-inform", "DER", "-in", str(key_file), "-check", "-noout"])
        cert_pub = run(["openssl", "x509", "-in", str(cert_file), "-pubkey", "-noout"])
        key_pub = run(["openssl", "pkey", "-inform", "DER", "-in", str(key_file), "-pubout"])
        if cert_pub != key_pub:
            raise ValueError("SPIFFE private key does not match its certificate")
        algorithms.append("ML-DSA-65" if b"ML-DSA-65" in text else "classical")
        digests.append(hashlib.sha256(cert_der).hexdigest())
    if len(set(identities)) != 1 or len(set(hints)) != 2 or sorted(algorithms) != ["ML-DSA-65", "classical"]:
        raise ValueError("SPIFFE response is not one identity with distinct classical + ML-DSA keys")
    return {"mode": "multikey_spiffe", "identity": identities[0], "hints": hints, "algorithms": algorithms, "certificate_digests": digests}


def verify_rollout(payload: dict, state: "State") -> dict:
    selected = payload.get("selected_findings")
    applied = payload.get("applied_progress")
    rolled_back = payload.get("rollback_progress")
    desired = payload.get("desired")
    legacy = payload.get("legacy")
    if not isinstance(selected, list) or sorted(item.get("finding_kind") for item in selected if isinstance(item, dict)) != ["cipher", "protocol"]:
        raise ValueError("rollout did not bind exactly the selected protocol and cipher findings")
    if not isinstance(applied, dict) or applied.get("total") != 2 or applied.get("applied") != 2 or applied.get("queued") != 0 or applied.get("failed") != 0:
        raise ValueError("rollout progress did not converge with zero unresolved findings")
    if not isinstance(rolled_back, dict) or rolled_back.get("rolled_back") != 2 or rolled_back.get("queued") != 0:
        raise ValueError("rollback progress did not converge for both findings")
    if not isinstance(desired, dict) or desired.get("minimum_version") != "TLSv1.3" or "X25519MLKEM768" not in desired.get("key_exchange_groups", []):
        raise ValueError("desired rollout omitted TLS 1.3 hybrid ML-KEM posture")
    if not isinstance(legacy, dict) or legacy.get("minimum_version") not in ("TLSv1.0", "TLSv1.1"):
        raise ValueError("rollback transcript omitted the exact legacy protocol posture")
    with state.lock:
        if state.current != legacy or state.put_count != 2 or state.get_count < 5:
            raise ValueError("Envoy emulator did not observe apply/readback plus exact rollback")
        history = list(state.history)
    if history != [desired, legacy]:
        raise ValueError("Envoy mutation history differs from desired then exact prior posture")
    return {"mode": "automated_tls_rollout", "selected": 2, "put_count": 2, "get_count": state.get_count, "history_digest": hashlib.sha256(compact(history)).hexdigest()}


class LoopbackHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


class State:
    def __init__(self, entry_id: str):
        self.entry_id = entry_id
        self.root = tempfile.TemporaryDirectory(prefix="trstctl-pqc-dod-")
        self.directory = Path(self.root.name)
        self.key = self.directory / "pure.key.pem"
        self.csr = self.directory / "pure.csr.der"
        run(["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-out", str(self.key)])
        run(["openssl", "req", "-new", "-key", str(self.key), "-subj", "/CN=pure-mldsa.dod.test", "-addext", "subjectAltName=DNS:pure-mldsa.dod.test", "-outform", "DER", "-out", str(self.csr)])
        self.current = {
            "minimum_version": "TLSv1.0",
            "cipher_suites": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
            "key_exchange_groups": ["secp256r1"],
        }
        self.history: list[dict] = []
        self.put_count = 0
        self.get_count = 0
        self.verified = False
        self.readback = b""
        self.failures = 0
        self.lock = threading.Lock()

    def close(self) -> None:
        self.root.cleanup()

    def passed(self) -> bool:
        with self.lock:
            rollout_ok = self.entry_id != PQC_103 or (self.put_count == 2 and self.get_count >= 5)
            return self.verified and self.failures == 0 and bool(self.readback) and rollout_ok


class Handler(BaseHTTPRequestHandler):
    server_version = "trstctl-dod-pqc-interop/1"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_args: object) -> None:
        return

    def send_body(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, value: object) -> None:
        self.send_body(status, compact(value))

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/dod/csr":
            self.send_json(200, {"csr_der_b64": base64.b64encode(self.state.csr.read_bytes()).decode()})
            return
        if path == "/dod/readback":
            with self.state.lock:
                body = self.state.readback
            self.send_body(200 if body else 404, body or compact({"error": "no verification"}))
            return
        if path == "/dod/state":
            with self.state.lock:
                value = {"current": self.state.current, "history": self.state.history, "put_count": self.state.put_count, "get_count": self.state.get_count}
            self.send_json(200, value)
            return
        prefix = "/v1/tls-posture/"
        if path.startswith(prefix) and unquote(path[len(prefix):]) == "edge-listener":
            with self.state.lock:
                self.state.get_count += 1
                current = dict(self.state.current)
            self.send_json(200, current)
            return
        self.send_json(404, {"error": "not found"})

    def do_PUT(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        prefix = "/v1/tls-posture/"
        if not path.startswith(prefix) or unquote(path[len(prefix):]) != "edge-listener":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 64 << 10:
                raise ValueError("invalid length")
            posture = json.loads(self.rfile.read(length))
            if not isinstance(posture, dict) or not isinstance(posture.get("cipher_suites"), list) or not isinstance(posture.get("key_exchange_groups"), list):
                raise ValueError("invalid posture")
        except Exception:
            self.send_json(400, {"error": "invalid posture"})
            return
        with self.state.lock:
            self.state.current = posture
            self.state.history.append(posture)
            self.state.put_count += 1
        self.send_body(204, b"")

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/dod/verify":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("invalid transcript length")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("transcript is not an object")
            mode = payload.get("mode")
            with tempfile.TemporaryDirectory(prefix="trstctl-pqc-verify-") as raw:
                if mode == "pure_mldsa_leaf":
                    report = verify_pure(payload, Path(raw))
                elif mode == "multikey_spiffe":
                    report = verify_spiffe(payload, Path(raw))
                elif mode == "automated_tls_rollout":
                    report = verify_rollout(payload, self.state)
                else:
                    raise ValueError("unknown PQC verification mode")
            body = compact(report)
            with self.state.lock:
                self.state.verified = True
                self.state.readback = body
            self.send_body(200, body)
        except Exception as exc:
            with self.state.lock:
                self.state.failures += 1
            self.send_json(422, {"error": str(exc)[:800]})


def serve() -> int:
    challenge = required("TRSTCTL_DOD_CHALLENGE")
    entry_id = required("TRSTCTL_DOD_ENTRY_ID")
    identity = required("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = required("TRSTCTL_DOD_CONTRACT_DIGEST")
    signatures = run(["openssl", "list", "-signature-algorithms"])
    if b"ML-DSA-65" not in signatures:
        raise SystemExit("stock OpenSSL lacks ML-DSA-65")
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
    state.close()
    emit({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "passed": passed,
    })
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(serve())
