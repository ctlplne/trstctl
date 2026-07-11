#!/usr/bin/env python3
"""Out-of-process native-connector target used only by the sealed DoD census."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socketserver
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlparse
from urllib.request import Request, urlopen


CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*", re.S)


class LoopbackHTTPServer(ThreadingHTTPServer):
    """Bind without HTTPServer's reverse-DNS lookup on loopback."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def _exact(logical: str, *arguments: str):
    return lambda payload: payload.get("logical") == logical and payload.get("args") == list(arguments)


def _haproxy_validate(payload: dict) -> bool:
    args = payload.get("args")
    return (
        payload.get("logical") == "haproxy" and isinstance(args, list) and len(args) == 3
        and args[:2] == ["-c", "-f"] and isinstance(args[2], str)
        and args[2].endswith("haproxy.cfg")
    )


def _iis_import(payload: dict) -> bool:
    args = payload.get("args")
    if payload.get("logical") != "powershell" or not isinstance(args, list) or len(args) != 4:
        return False
    command = args[3] if isinstance(args[3], str) else ""
    return (
        args[:3] == ["-NoProfile", "-NonInteractive", "-Command"]
        and "Import-PfxCertificate" in command
        and "Remove-Item" in command
        and ".pfx" in command and ".pw" in command
        and "Cert:\\LocalMachine\\MY" in command
    )


def _iis_netsh_delete(payload: dict) -> bool:
    args = payload.get("args")
    return payload.get("logical") == "netsh" and args == ["http", "delete", "sslcert", "ipport=0.0.0.0:443"]


def _iis_netsh_add(payload: dict) -> bool:
    args = payload.get("args")
    if payload.get("logical") != "netsh" or not isinstance(args, list) or len(args) != 7:
        return False
    return (
        args[:3] == ["http", "add", "sslcert"]
        and args[3] == "ipport=0.0.0.0:443"
        and isinstance(args[4], str) and re.fullmatch(r"certhash=[0-9A-F]{40}", args[4]) is not None
        and args[5] == "appid={4dc3e181-e14b-4a21-b022-59fc669b0914}"
        and args[6] == "certstorename=MY"
    )


# Exact activation contract for every local connector which claims a daemon
# validation/reload effect. A generic "some command ran" signal is not enough:
# the emulator accepts only the same argv sequence a real target requires.
SIGNAL_CONTRACTS = {
    "connector.nginx": [_exact("nginx", "-t"), _exact("nginx", "-s", "reload")],
    "connector.apache": [_exact("apachectl", "configtest"), _exact("apachectl", "graceful")],
    "connector.caddy": [_exact("caddy", "reload")],
    "connector.iis": [_iis_import, _iis_netsh_delete, _iis_netsh_add],
    "connector.haproxy": [_haproxy_validate, _exact("systemctl", "reload", "haproxy")],
    "connector.postfix": [
        _exact("postfix", "check"), _exact("doveconf", "-n"),
        _exact("postfix", "reload"), _exact("doveadm", "reload"),
    ],
    "connector.postgresql": [_exact("pg_ctl", "reload")],
    "connector.mysql": [_exact("mysqladmin", "reload")],
    "connector.rabbitmq": [_exact("rabbitmqctl", "rotate_certs")],
    "connector.tomcat": [_exact("catalina.sh", "reload")],
}


READBACK_FILES = {
    "connector.nginx": "server.crt",
    "connector.apache": "server.crt",
    "connector.caddy": "server.crt",
    "connector.haproxy": "bundle.pem",
    "connector.postfix": "postfix.crt",
    "connector.traefik": "server.crt",
    "connector.javakeystore": "keystore.p12",
    "connector.postgresql": "server.crt",
    "connector.mysql": "server.crt",
    "connector.rabbitmq": "server.crt",
    "connector.elasticsearch": "server.crt",
    "connector.tomcat": "server.crt",
}


def signal_contract_matches(entry_id: str, index: int, payload: object) -> bool:
    contract = SIGNAL_CONTRACTS.get(entry_id)
    if contract is None or type(payload) is not dict or payload.get("entry_id") != entry_id:
        return False
    if index < 0 or index >= len(contract):
        return False
    return bool(contract[index](payload))


def signal_contract_length(entry_id: str) -> int:
    return len(SIGNAL_CONTRACTS.get(entry_id, ()))


def env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing {name}")
    return value


def json_line(value: dict) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def verify_sigv4(method: str, raw_path: str, headers, body: bytes, *, access_key: str, secret_key: bytes, region: str, service: str) -> bool:
    """Verify the complete canonical AWS SigV4 request, not just its prefix."""
    try:
        algorithm = "AWS4-HMAC-SHA256"
        authorization = headers.get("Authorization", "")
        if not authorization.startswith(algorithm + " "):
            return False
        fields = {}
        for item in authorization[len(algorithm) + 1:].split(","):
            name, value = item.strip().split("=", 1)
            fields[name] = value
        credential = fields["Credential"].split("/")
        if len(credential) != 5 or credential[0] != access_key or credential[2] != region or credential[3] != service or credential[4] != "aws4_request":
            return False
        signed_names = fields["SignedHeaders"].split(";")
        if signed_names != sorted(signed_names) or "host" not in signed_names:
            return False
        amz_date = headers.get("X-Amz-Date", "")
        if len(amz_date) != 16 or credential[1] != amz_date[:8]:
            return False
        parsed = urlparse(raw_path)
        canonical_uri = quote(unquote(parsed.path or "/"), safe="/-_.~")
        query_items = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~")) for k, v in parse_qsl(parsed.query, keep_blank_values=True))
        canonical_query = "&".join(f"{key}={value}" for key, value in query_items)
        canonical_headers = ""
        for name in signed_names:
            value = headers.get(name, "")
            if value == "":
                return False
            canonical_headers += f"{name}:{' '.join(value.strip().split())}\n"
        canonical_request = "\n".join((
            method, canonical_uri, canonical_query, canonical_headers,
            fields["SignedHeaders"], hashlib.sha256(body).hexdigest(),
        ))
        scope = "/".join(credential[1:])
        string_to_sign = "\n".join((algorithm, amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()))
        date_key = hmac.new(b"AWS4" + secret_key, credential[1].encode(), hashlib.sha256).digest()
        region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
        service_key = hmac.new(region_key, service.encode(), hashlib.sha256).digest()
        signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
        expected = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, fields["Signature"])
    except (KeyError, ValueError, TypeError):
        return False


class State:
    def __init__(self, entry_id: str, root: Path):
        self.entry_id = entry_id
        self.root = root
        self.requests: list[tuple[str, str, dict[str, str], bytes]] = []
        self.signals: list[dict] = []
        self.signal_error = False
        self.cert = b""
        self.readback = b""
        self.lock = threading.Lock()

    def record(self, method: str, path: str, headers, body: bytes) -> None:
        with self.lock:
            self.requests.append((method, path, {k.lower(): v for k, v in headers.items()}, body))
            if not self.cert:
                self.cert = extract_certificate(body)

    def paths(self) -> list[tuple[str, str]]:
        with self.lock:
            return [(method, urlparse(path).path) for method, path, _, _ in self.requests]

    def readback_path_ok(self, candidate: Path) -> bool:
        relative = READBACK_FILES.get(self.entry_id)
        if relative is None:
            return False
        return candidate == (self.root / relative).resolve()

    def signal_paths_ok(self, payload: dict) -> bool:
        if self.entry_id != "connector.iis" or payload.get("logical") != "powershell":
            return True
        command = payload.get("args", [None, None, None, ""])[3]
        if not isinstance(command, str):
            return False
        pfx_paths = re.findall(r"[/A-Za-z0-9_.:-]+\.pfx", command)
        password_paths = re.findall(r"[/A-Za-z0-9_.:-]+\.pw", command)
        if len(pfx_paths) != 1 or len(password_paths) != 1:
            return False
        pfx = Path(pfx_paths[0]).resolve()
        password = Path(password_paths[0]).resolve()
        expected_dir = (self.root / "import").resolve()
        return (
            pfx.parent == expected_dir and password.parent == expected_dir
            and pfx.stem == password.stem
        )

    def passed(self) -> bool:
        paths = self.paths()
        entry = self.entry_id
        if entry in {"connector.registry", "connector.a10"}:
            return all(item in paths for item in [
                ("POST", "/axapi/v3/auth"),
                ("POST", "/axapi/v3/file/ssl-cert"),
                ("POST", "/axapi/v3/file/ssl-key"),
            ]) and any(method == "PUT" and path.startswith("/axapi/v3/slb/template/client-ssl/") for method, path in paths) and bool(self.readback)
        expected = {
            "connector.envoy": [("GET", "/v1/sds/secrets/dod-secret"), ("PUT", "/v1/sds/secrets/dod-secret")],
            "connector.f5": [
                ("POST", "/mgmt/tm/sys/crypto/cert"),
                ("POST", "/mgmt/tm/sys/crypto/key"),
                ("PATCH", "/mgmt/tm/ltm/profile/client-ssl/dod-profile"),
            ],
            "connector.netscaler": [
                ("POST", "/nitro/v1/config/login"),
                ("PUT", "/nitro/v1/config/sslcertkey"),
                ("POST", "/nitro/v1/config/logout"),
            ],
            "connector.kemp": [("PUT", "/access/certificates/dod-target-trstctl"), ("PATCH", "/access/virtual-services/dod-target/certificate")],
            "connector.cisco": [("POST", "/api/certificate/import")],
            "connector.fortigate": [("PUT", "/api/v2/cmdb/vpn.certificate/local/dod-target")],
            "connector.paloalto": [("POST", "/api/")],
            "connector.acm": [("POST", "/")],
            "connector.azurekv": [("PUT", "/certificates/dod-target/import")],
            "connector.gcpcm": [("PATCH", "/v1/projects/dod-project/locations/global/certificates/dod-target")],
        }
        if entry in expected:
            required = expected[entry]
            if not all(item in paths for item in required) or not self.readback:
                return False
            if entry == "connector.f5":
                uploads = [path for method, path in paths if method == "POST" and path.startswith("/mgmt/shared/file-transfer/uploads/")]
                return len(uploads) == 2
            if entry == "connector.netscaler":
                return paths.count(("POST", "/nitro/v1/config/systemfile")) == 2
            if entry == "connector.paloalto":
                with self.lock:
                    raw_paths = [path for method, path, _, _ in self.requests if method == "POST"]
                categories = {parse_qs(urlparse(path).query).get("category", [""])[0] for path in raw_paths}
                return {"certificate", "private-key"}.issubset(categories)
            return True
        # Local/shared-volume connectors must cross the filesystem boundary and
        # be read back by this process. Connectors with activation also produce
        # at least one independently executed signal command.
        no_exec = {"connector.traefik", "connector.javakeystore", "connector.elasticsearch"}
        if entry in no_exec:
            return bool(self.readback)
        with self.lock:
            complete = (
                not self.signal_error and len(self.signals) == signal_contract_length(entry)
            )
        return bool(self.readback) and complete

    def record_signal(self, payload: dict) -> bool:
        with self.lock:
            if (
                not signal_contract_matches(self.entry_id, len(self.signals), payload)
                or not self.signal_paths_ok(payload)
            ):
                self.signal_error = True
                return False
            self.signals.append(payload)
        values = payload.get("args", [])
        if not isinstance(values, list):
            return True
        joined = " ".join(value for value in values if isinstance(value, str))
        pfx_paths = re.findall(r"[/A-Za-z0-9_.:-]+\.pfx", joined)
        password_paths = re.findall(r"[/A-Za-z0-9_.:-]+\.pw", joined)
        if not pfx_paths or not password_paths:
            return True
        certificate = pkcs12_certificate(Path(pfx_paths[0]), password_file=Path(password_paths[0]))
        if certificate:
            with self.lock:
                self.readback = certificate
                self.cert = certificate
        return True


def extract_certificate(body: bytes) -> bytes:
    try:
        value = json.loads(body)
    except Exception:
        match = CERT_RE.search(body)
        return match.group(0) if match else b""
    candidates: list[bytes] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
        elif isinstance(node, str):
            candidates.append(node.encode())
            try:
                candidates.append(base64.b64decode(node, validate=True))
            except Exception:
                pass

    walk(value)
    for candidate in candidates:
        match = CERT_RE.search(candidate)
        if match:
            return match.group(0)
    # A JSON wire string contains escaped newlines, so matching the raw request
    # before decoding would mistake "\\n" for certificate bytes. Raw PEM upload
    # endpoints reach this fallback because their bodies are not JSON.
    match = CERT_RE.search(body)
    return match.group(0) if match else b""


def pkcs12_certificate(path: Path, password_file: Path | None = None, password: str = "") -> bytes:
    if not path.is_file():
        return b""
    command = ["openssl", "pkcs12", "-in", str(path), "-clcerts", "-nokeys"]
    if password_file is not None:
        command.extend(["-passin", f"file:{password_file}"])
    else:
        command.extend(["-passin", f"pass:{password}"])
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.SubprocessError):
        return b""
    if completed.returncode != 0:
        return b""
    return extract_certificate(completed.stdout)


def auth_ok(state: State, method: str, headers, path: str, body: bytes) -> bool:
    entry = state.entry_id
    authorization = headers.get("Authorization", "")
    if entry in {"connector.registry", "connector.a10"}:
        if path == "/axapi/v3/auth":
            try:
                auth = json.loads(body)["credentials"]
                return auth["username"] == "dod-user" and auth["password"] == "dod-password-connector"
            except (KeyError, TypeError, ValueError):
                return False
        return authorization == "A10 dod-session-token"
    if entry in {"connector.f5", "connector.cisco"}:
        expected = "Basic " + base64.b64encode(b"dod-user:dod-password-connector").decode()
        return authorization == expected
    if entry in {"connector.kemp", "connector.fortigate"}:
        return authorization == "Bearer dod-token-connector"
    if entry in {"connector.azurekv", "connector.gcpcm"}:
        return authorization == "Bearer dod-bearer-token"
    if entry == "connector.netscaler":
        if urlparse(path).path == "/nitro/v1/config/login":
            try:
                login = json.loads(body)["login"]
                return login["username"] == "dod-user" and login["password"] == "dod-password-connector"
            except (KeyError, TypeError, ValueError):
                return False
        return "NITRO_AUTH_TOKEN=dod-nitro-session" in headers.get("Cookie", "")
    if entry == "connector.acm":
        return verify_sigv4(
            method, path, headers, body,
            access_key="AKIADODTEST", secret_key=b"dod-aws-secret-key-material", region="us-east-1", service="acm",
        )
    if entry == "connector.paloalto":
        return headers.get("X-PAN-KEY", "") == "dod-api-key"
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "trstctl-dod-connector/1"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_args) -> None:
        return

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(min(length, 8 << 20))

    def _send(self, status: int, body: bytes = b"{}", content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/dod/config":
            body = json.dumps({"root": str(self.state.root)}).encode()
            self._send(200, body)
            return
        if parsed.path == "/dod/readback":
            query = parse_qs(parsed.query)
            if query.get("path"):
                candidate = Path(query["path"][0]).resolve()
                try:
                    if not self.state.readback_path_ok(candidate):
                        raise ValueError("path is not the connector's installed credential")
                    data = candidate.read_bytes()
                except Exception:
                    self._send(404, b"readback missing")
                    return
                certificate = extract_certificate(data)
                if not certificate and candidate.suffix.lower() in {".p12", ".pfx"}:
                    certificate = pkcs12_certificate(candidate, password="dod-password-connector")
                self.state.readback = certificate if query.get("certificate") and certificate else data
                if not self.state.cert:
                    self.state.cert = certificate
                self._send(200, self.state.readback, "application/octet-stream")
                return
            data = self.state.cert or self.state.readback
            self.state.readback = data
            self._send(200 if data else 404, data or b"readback missing", "application/octet-stream")
            return
        body = b""
        if not auth_ok(self.state, "GET", self.headers, self.path, body):
            self._send(401, b'{"error":"authentication required"}')
            return
        self.state.record("GET", self.path, self.headers, body)
        if self.path.startswith("/v1/sds/secrets/"):
            self._send(404)
            return
        if "/v1/operations/" in self.path:
            self._send(200, b'{"name":"operations/dod-op","done":true}')
            return
        self._send(200)

    def do_POST(self) -> None:
        self._mutate("POST")

    def do_PUT(self) -> None:
        self._mutate("PUT")

    def do_PATCH(self) -> None:
        self._mutate("PATCH")

    def _mutate(self, method: str) -> None:
        body = self._body()
        if self.path.startswith("/dod/signal"):
            try:
                payload = json.loads(body)
            except Exception:
                payload = {"raw": body.decode(errors="replace")}
            if not self.state.record_signal(payload):
                self._send(422, b'{"error":"signal does not match connector activation contract"}')
                return
            self._send(200, b'{"accepted":true}')
            return
        if not auth_ok(self.state, method, self.headers, self.path, body):
            self._send(401, b'{"error":"authentication required"}')
            return
        self.state.record(method, self.path, self.headers, body)
        parsed = urlparse(self.path)
        if parsed.path == "/axapi/v3/auth":
            self._send(200, b'{"authresponse":{"signature":"dod-session-token"}}')
            return
        if parsed.path == "/nitro/v1/config/login":
            self._send(200, b'{"sessionid":"dod-nitro-session"}')
            return
        if self.state.entry_id == "connector.gcpcm" and method == "PATCH":
            self._send(200, b'{"name":"operations/dod-op","done":false}')
            return
        if self.state.entry_id == "connector.paloalto":
            self._send(200, b'<response status="success"><result>ok</result></response>', "application/xml")
            return
        self._send(200)


def signal_action(args) -> int:
    payload = json.dumps({"entry_id": args.entry, "logical": args.logical, "args": args.args}).encode()
    request = Request(args.endpoint.rstrip("/") + "/dod/signal", data=payload, method="POST", headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        return 0 if response.status // 100 == 2 else 1


def serve() -> int:
    challenge = env("TRSTCTL_DOD_CHALLENGE")
    entry_id = env("TRSTCTL_DOD_ENTRY_ID")
    identity = env("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = env("TRSTCTL_DOD_CONTRACT_DIGEST")
    root = Path(tempfile.mkdtemp(prefix="trstctl-dod-connector-"))
    state = State(entry_id, root)
    server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
    server.state = state  # type: ignore[attr-defined]
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    json_line({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "ready": True, "endpoint": endpoint,
    })
    while not stop.wait(0.1):
        pass
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
    passed = state.passed()
    json_line({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "passed": passed,
    })
    shutil.rmtree(root, ignore_errors=True)
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    action = sub.add_parser("signal")
    action.add_argument("--endpoint", required=True)
    action.add_argument("--entry", required=True)
    action.add_argument("--logical", required=True)
    action.add_argument("args", nargs="*")
    args = parser.parse_args()
    if args.command == "signal":
        return signal_action(args)
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
