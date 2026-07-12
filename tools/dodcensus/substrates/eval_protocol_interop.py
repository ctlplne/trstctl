#!/usr/bin/env python3
"""Independent verifier for the tenant-bound eval protocol profile.

The control-plane runtime test drives the real protocol servers.  This separate
process accepts the resulting wire transcript only after OpenSSL/OpenSSH validate
the protocol artifacts independently of trstctl's Go parsers.
"""

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


MAX_BODY = 8 << 20
PROTOCOLS = ["acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"]


class LoopbackHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def decode(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} is not base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"{name} is not canonical base64") from exc
    if not raw:
        raise ValueError(f"{name} is empty")
    return raw


def run(args: list[str], timeout: float = 15) -> bytes:
    result = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    if result.returncode != 0:
        raise ValueError(f"independent command failed ({' '.join(args[:3])}): {result.stdout[:800]!r}")
    return result.stdout


def write(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    path.chmod(0o600)


def der_to_pem(der: bytes) -> bytes:
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


def verify_certificate(root: Path, name: str, der: bytes, ca_file: Path, required_text: bytes = b"") -> str:
    cert = root / f"{name}.pem"
    write(cert, der_to_pem(der))
    run(["openssl", "verify", "-CAfile", str(ca_file), str(cert)])
    text = run(["openssl", "x509", "-in", str(cert), "-noout", "-text"])
    if required_text and required_text not in text:
        raise ValueError(f"{name} certificate omitted {required_text!r}")
    return hashlib.sha256(der).hexdigest()


def verify(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("transcript is not an object")
    if payload.get("profile") != "eval" or not isinstance(payload.get("tenant_id"), str):
        raise ValueError("transcript is not bound to one eval tenant")
    expected = PROTOCOLS
    activation = payload.get("activation")
    if not isinstance(activation, dict) or activation.get("active") is not True or activation.get("protocols") != expected:
        raise ValueError("activation response did not open the exact seven-protocol profile")
    pre = payload.get("pre_activation")
    if not isinstance(pre, dict) or any(pre.get(name) != 503 for name in expected[:-1]) or pre.get("spiffe") != "socket-absent":
        raise ValueError("one or more protocol surfaces did not fail closed before activation")
    if payload.get("cross_tenant_status") != 403:
        raise ValueError("cross-tenant activation was not forbidden")
    restart = payload.get("restart")
    if not isinstance(restart, dict) or restart.get("active") is not True or restart.get("protocols") != expected:
        raise ValueError("restart did not replay the exact activated profile")
    readbacks = restart.get("readbacks")
    if not isinstance(readbacks, dict) or sorted(readbacks) != sorted(expected):
        raise ValueError("restart omitted a protocol readback")
    if any(not isinstance(value, str) or len(value) != 64 for value in readbacks.values()):
        raise ValueError("restart readback is not digest-bound")
    events = payload.get("tenant_events")
    if not isinstance(events, dict) or events.get("protocol.eval_profile.activated") != 1:
        raise ValueError("activation was not a single tenant event")
    for name in ("ssh.cert.issued", "tsa.timestamp.issued", "spiffe.svid.issued"):
        if not isinstance(events.get(name), int) or events[name] < 1:
            raise ValueError(f"missing tenant event {name}")
    if not isinstance(events.get("certificate.recorded"), int) or events["certificate.recorded"] < 4:
        raise ValueError("the four X.509 enrollment protocols did not record certificates")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, dict) or sorted(artifacts) != sorted(expected):
        raise ValueError("wire transcript omitted a protocol artifact")
    ca_pem = payload.get("ca_pem")
    if not isinstance(ca_pem, str) or "BEGIN CERTIFICATE" not in ca_pem:
        raise ValueError("served CA PEM is missing")

    with tempfile.TemporaryDirectory(prefix="trstctl-eval-protocol-interop-") as raw:
        root = Path(raw)
        ca_file = root / "ca.pem"
        write(ca_file, ca_pem.encode())
        run(["openssl", "x509", "-in", str(ca_file), "-noout", "-text"])

        cert_digests: dict[str, str] = {}
        acme = artifacts["acme"]
        if not isinstance(acme, dict) or not isinstance(acme.get("wire"), list) or len(acme["wire"]) < 8:
            raise ValueError("ACME transcript does not contain an account/order/challenge/finalize exchange")
        cert_digests["acme"] = verify_certificate(
            root, "acme", decode(acme.get("certificate_der"), "acme certificate"), ca_file, b"DNS:eval-profile-dod.local"
        )

        est = artifacts["est"]
        if not isinstance(est, dict):
            raise ValueError("EST artifact is invalid")
        est_p7 = root / "est.p7"
        write(est_p7, decode(est.get("response_pkcs7_der"), "EST PKCS7 response"))
        run(["openssl", "pkcs7", "-inform", "DER", "-in", str(est_p7), "-print_certs", "-noout"])
        cert_digests["est"] = verify_certificate(root, "est", decode(est.get("certificate_der"), "EST certificate"), ca_file)

        for name in ("scep", "cmp"):
            item = artifacts[name]
            if not isinstance(item, dict):
                raise ValueError(f"{name} artifact is invalid")
            request = root / f"{name}-request.der"
            response = root / f"{name}-response.der"
            write(request, decode(item.get("request_der"), f"{name} request"))
            write(response, decode(item.get("response_der"), f"{name} response"))
            run(["openssl", "asn1parse", "-inform", "DER", "-in", str(request)])
            run(["openssl", "asn1parse", "-inform", "DER", "-in", str(response)])
            cert_digests[name] = verify_certificate(root, name, decode(item.get("certificate_der"), f"{name} certificate"), ca_file)

        ssh = artifacts["ssh"]
        if not isinstance(ssh, dict) or not isinstance(ssh.get("certificate"), str) or not isinstance(ssh.get("ca"), str):
            raise ValueError("SSH artifact is invalid")
        ssh_cert = root / "id-cert.pub"
        ssh_ca = root / "ssh-ca.pub"
        write(ssh_cert, ssh["certificate"].encode())
        write(ssh_ca, ssh["ca"].encode())
        ssh_text = run(["ssh-keygen", "-L", "-f", str(ssh_cert)])
        run(["ssh-keygen", "-l", "-f", str(ssh_ca)])
        if b"eval-user" not in ssh_text or b"user certificate" not in ssh_text.lower():
            raise ValueError("OpenSSH did not recognize the issued eval-user certificate")

        tsa = artifacts["tsa"]
        if not isinstance(tsa, dict):
            raise ValueError("TSA artifact is invalid")
        tsq = root / "request.tsq"
        tsr = root / "response.tsr"
        write(tsq, decode(tsa.get("request_der"), "TSA request"))
        write(tsr, decode(tsa.get("response_der"), "TSA response"))
        tsa_text = run(["openssl", "ts", "-reply", "-in", str(tsr), "-text"])
        run(["openssl", "ts", "-verify", "-queryfile", str(tsq), "-in", str(tsr), "-CAfile", str(ca_file)])
        if b"Granted" not in tsa_text:
            raise ValueError("RFC 3161 response was not granted")

        spiffe = artifacts["spiffe"]
        if not isinstance(spiffe, dict) or spiffe.get("id") != "spiffe://eval.trstctl.local/workload":
            raise ValueError("SPIFFE artifact has the wrong workload identity")
        cert_digests["spiffe"] = verify_certificate(
            root, "spiffe", decode(spiffe.get("certificate_der"), "SPIFFE certificate"), ca_file,
            b"URI:spiffe://eval.trstctl.local/workload",
        )
        bundle = root / "spiffe-bundle.der"
        if spiffe.get("private_key_present") is not True:
            raise ValueError("SPIFFE Workload API response omitted its ephemeral private key")
        write(bundle, decode(spiffe.get("bundle_der"), "SPIFFE bundle"))
        run(["openssl", "x509", "-inform", "DER", "-in", str(bundle), "-noout", "-text"])

    canonical = compact(payload)
    return {
        "schema_version": 1,
        "profile": "eval",
        "tenant_id": payload["tenant_id"],
        "protocols": expected,
        "certificate_digests": cert_digests,
        "ssh_certificate_digest": hashlib.sha256(ssh["certificate"].encode()).hexdigest(),
        "tsa_response_digest": hashlib.sha256(decode(tsa["response_der"], "TSA response")).hexdigest(),
        "transcript_digest": hashlib.sha256(canonical).hexdigest(),
        "restart_replayed": True,
    }


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.readback = b""
        self.failures = 0
        self.read = False

    def accepted(self, body: bytes) -> None:
        with self.lock:
            self.readback = body

    def failed(self) -> None:
        with self.lock:
            self.failures += 1

    def passed(self) -> bool:
        with self.lock:
            return self.failures == 0 and len(self.readback) >= 16 and self.read


def handler_for(state: State):
    class Handler(BaseHTTPRequestHandler):
        server_version = "trstctl-dod-eval-protocol-interop/1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def send_body(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/dod/verify":
                self.send_body(404, compact({"error": "not found"}))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                state.failed()
                self.send_body(400, compact({"error": "invalid transcript length"}))
                return
            try:
                payload = json.loads(self.rfile.read(length))
                report = compact(verify(payload))
            except (ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
                state.failed()
                self.send_body(422, compact({"error": str(exc)}))
                return
            state.accepted(report)
            self.send_body(200, report)

        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/dod/readback":
                self.send_body(404, compact({"error": "not found"}))
                return
            with state.lock:
                body = state.readback
                if body:
                    state.read = True
            if not body:
                self.send_body(404, compact({"error": "no verified transcript"}))
                return
            self.send_body(200, body)

    return Handler


def main() -> int:
    challenge = os.environ.get("TRSTCTL_DOD_CHALLENGE", "")
    entry_id = os.environ.get("TRSTCTL_DOD_ENTRY_ID", "")
    identity = os.environ.get("TRSTCTL_DOD_SUBSTRATE_IDENTITY", "")
    contract_digest = os.environ.get("TRSTCTL_DOD_CONTRACT_DIGEST", "")
    if not all((challenge, entry_id, identity, contract_digest)):
        raise SystemExit("missing TRSTCTL_DOD_* environment")

    state = State()
    server = LoopbackHTTPServer(("127.0.0.1", 0), handler_for(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    print(compact({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract_digest, "pid": os.getpid(),
        "ready": True, "endpoint": endpoint,
    }).decode(), flush=True)

    stopped = threading.Event()
    signal.signal(signal.SIGINT, lambda *_args: stopped.set())
    signal.signal(signal.SIGTERM, lambda *_args: stopped.set())
    stopped.wait()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    print(compact({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract_digest, "pid": os.getpid(),
        "passed": state.passed(),
    }).decode(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
