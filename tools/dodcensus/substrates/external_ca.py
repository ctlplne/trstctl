#!/usr/bin/env python3
"""Out-of-process, OpenSSL-backed universal external-CA DoD substrate."""

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
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlparse
from urllib.request import Request, urlopen


PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*", re.S)
AZURE_KEY_NAME_RE = re.compile(r"^trstctl-(?:generate|rotate)-[0-9a-f]{48}$")
AZURE_KEY_VERSION = "dod-version"
LOOPBACK_HOST_RE = re.compile(r"^127\.0\.0\.1:([1-9][0-9]{0,4})$")


class LoopbackHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server that never performs reverse DNS during bind."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing {name}")
    return value


def json_line(value: dict) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def verify_sigv4(method: str, raw_path: str, headers, body: bytes, *, access_key: str, secret_key: bytes, region: str, service: str) -> bool:
    """Recompute the server side of AWS Signature Version 4 exactly."""
    try:
        authorization = headers.get("Authorization", "")
        algorithm = "AWS4-HMAC-SHA256"
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
        required_signed_names = ["content-type", "host", "x-amz-date", "x-amz-target"]
        if signed_names != required_signed_names:
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
        payload_hash = hashlib.sha256(body).hexdigest()
        canonical_request = "\n".join((method, canonical_uri, canonical_query, canonical_headers, fields["SignedHeaders"], payload_hash))
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


def verify_hs256_jwt(token: str, key: bytes, *, issuer: str, audience: str) -> bool:
    try:
        protected, payload, encoded_signature = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        signature = base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
        expected = hmac.new(key, f"{protected}.{payload}".encode(), hashlib.sha256).digest()
        now = int(time.time())
        return (
            header.get("alg") == "HS256"
            and claims.get("iss") == issuer
            and claims.get("aud") == audience
            and isinstance(claims.get("jti"), str) and bool(claims["jti"])
            and int(claims.get("nbf", now + 1)) <= now <= int(claims.get("exp", now - 1))
            and hmac.compare_digest(signature, expected)
        )
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_integer(raw: bytes) -> bytes:
    raw = raw.lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_length(len(raw)) + raw


def _ecdsa_raw_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError("ES256 signature must contain r||s")
    body = _der_integer(signature[:32]) + _der_integer(signature[32:])
    return b"\x30" + _der_length(len(body)) + body


def _p256_jwk_public_pem(jwk: dict) -> bytes:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("ACME account JWK must be P-256")
    x = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    y = base64.urlsafe_b64decode(jwk["y"] + "=" * (-len(jwk["y"]) % 4))
    if len(x) != 32 or len(y) != 32:
        raise ValueError("invalid P-256 point")
    # SubjectPublicKeyInfo(id-ecPublicKey, prime256v1, uncompressed point).
    der = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + x + y
    encoded = base64.b64encode(der)
    return b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + b"\n-----END PUBLIC KEY-----\n"


def verify_acme_jws(state, body: bytes, path: str, origin: str, *, new_account: bool) -> tuple[bool, dict]:
    """Verify RFC 8555 protected fields, nonce replay, and ES256 signature."""
    try:
        if not origin:
            return False, {}
        envelope = json.loads(body)
        protected_raw = envelope["protected"]
        payload_raw = envelope["payload"]
        signature_raw = envelope["signature"]
        protected = json.loads(base64.urlsafe_b64decode(protected_raw + "=" * (-len(protected_raw) % 4)))
        payload_bytes = base64.urlsafe_b64decode(payload_raw + "=" * (-len(payload_raw) % 4))
        payload = json.loads(payload_bytes) if payload_bytes else {}
        if protected.get("alg") != "ES256" or protected.get("url") != origin + path:
            return False, {}
        nonce = protected.get("nonce", "")
        with state.lock:
            if nonce not in state.issued_nonces or nonce in state.used_nonces:
                return False, {}
            public_pem = state.account_public_pem
        if new_account:
            if "kid" in protected:
                return False, {}
            public_pem = _p256_jwk_public_pem(protected["jwk"])
        elif protected.get("kid") != origin + "/account/1" or not public_pem:
            return False, {}
        signature = _ecdsa_raw_to_der(base64.urlsafe_b64decode(signature_raw + "=" * (-len(signature_raw) % 4)))
        with tempfile.TemporaryDirectory(prefix="acme-jws-", dir=state.root) as directory:
            public_path = Path(directory) / "account-public.pem"
            signature_path = Path(directory) / "signature.der"
            public_path.write_bytes(public_pem)
            signature_path.write_bytes(signature)
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(public_path), "-signature", str(signature_path)],
                input=f"{protected_raw}.{payload_raw}".encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=10, check=False,
            )
        if result.returncode != 0:
            return False, {}
        with state.lock:
            state.used_nonces.add(nonce)
            if new_account:
                state.account_public_pem = public_pem
        return True, payload
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, OSError, subprocess.SubprocessError):
        return False, {}


def choose_private_host() -> str:
    # Plain HTTP is a development/emulator exception only. Binding the proof to
    # loopback exercises that explicit policy without teaching production config
    # that credentials may traverse a private LAN in cleartext.
    return "127.0.0.1"


def run_checked(args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {completed.stderr.decode(errors='replace')[:512]}")
    return completed.stdout


class State:
    def __init__(self, entry_id: str, root: Path):
        self.entry_id = entry_id
        self.root = root
        self.root_key = root / "root.key.pem"
        self.root_cert = root / "root.cert.pem"
        self.leaf = b""
        self.chain = b""
        self.requests: list[tuple[str, str]] = []
        self.authenticated = True
        self.serial = 1000
        self.nonce = 0
        self.base_url = ""
        self.issued_nonces: set[str] = set()
        self.used_nonces: set[str] = set()
        self.account_public_pem = b""
        self.public_origin = ""
        self.aws_transcript: list[tuple[str, str, str]] = []
        self.azure_keys: set[str] = set()
        self.azure_create_count: dict[str, int] = {}
        self.azure_transcript: list[tuple[str, str, str]] = []
        self.lock = threading.Lock()
        self._make_root()

    def _make_root(self) -> None:
        command = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(self.root_key), "-out", str(self.root_cert),
            "-days", "2", "-sha256", "-subj", "/CN=trstctl DoD External CA Root",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ]
        try:
            run_checked(command)
        except RuntimeError:
            run_checked(command[:-4])
        os.chmod(self.root_key, 0o600)

    def root_pem(self) -> bytes:
        return self.root_cert.read_bytes()

    def rsa_jwk(self) -> tuple[str, str]:
        output = run_checked(["openssl", "rsa", "-in", str(self.root_key), "-noout", "-modulus"])
        modulus_hex = output.decode().strip().split("=", 1)[-1]
        modulus = bytes.fromhex(modulus_hex)
        n = base64.urlsafe_b64encode(modulus).rstrip(b"=").decode()
        e = base64.urlsafe_b64encode(b"\x01\x00\x01").rstrip(b"=").decode()
        return n, e

    def sign_digest(self, digest: bytes) -> bytes:
        with self.lock:
            self.serial += 1
            digest_path = self.root / f"digest-{self.serial}.bin"
            digest_path.write_bytes(digest)
            signature = run_checked([
                "openssl", "pkeyutl", "-sign", "-inkey", str(self.root_key),
                "-in", str(digest_path), "-pkeyopt", "digest:sha256",
            ])
            # The product, not the emulator, constructs the leaf certificate.
            # A non-empty marker lets final-receipt validation require that the
            # remote private-key operation actually occurred.
            self.chain = self.root_pem()
            return signature

    def next_nonce(self) -> str:
        with self.lock:
            self.nonce += 1
            value = f"dod-nonce-{self.nonce}"
            self.issued_nonces.add(value)
            return value

    def record(self, method: str, path: str, headers, authenticated: bool = True) -> None:
        with self.lock:
            self.requests.append((method, urlparse(path).path))
            self.authenticated = self.authenticated and authenticated

    def bind_public_origin(self, headers) -> str:
        """Bind redirect/JWS URLs to one exact child-visible loopback origin."""
        hosts = headers.get_all("Host", [])
        if len(hosts) != 1:
            return ""
        match = LOOPBACK_HOST_RE.fullmatch(hosts[0])
        if match is None or int(match.group(1)) > 65535:
            return ""
        origin = "http://" + hosts[0]
        with self.lock:
            if not self.public_origin:
                self.public_origin = origin
            if self.public_origin != origin:
                return ""
        return origin

    def azure_create(self, name: str) -> bool:
        with self.lock:
            self.azure_create_count[name] = self.azure_create_count.get(name, 0) + 1
            if name in self.azure_keys:
                return False
            self.azure_keys.add(name)
            return True

    def azure_exists(self, name: str) -> bool:
        with self.lock:
            return name in self.azure_keys

    def azure_event(self, action: str, name: str, version: str = "") -> None:
        with self.lock:
            self.azure_transcript.append((action, name, version))

    def aws_event(self, method: str, path: str, target: str) -> None:
        with self.lock:
            self.aws_transcript.append((method, path, target))

    def sign(self, csr: bytes) -> bytes:
        with self.lock:
            self.serial += 1
            serial = self.serial
            csr_path = self.root / f"request-{serial}.csr.pem"
            leaf_path = self.root / f"leaf-{serial}.cert.pem"
            if b"-----BEGIN CERTIFICATE REQUEST-----" in csr or b"-----BEGIN NEW CERTIFICATE REQUEST-----" in csr:
                csr_pem = csr
            else:
                csr_pem = b"-----BEGIN CERTIFICATE REQUEST-----\n" + base64.encodebytes(csr) + b"-----END CERTIFICATE REQUEST-----\n"
            csr_path.write_bytes(csr_pem)
            command = [
                "openssl", "x509", "-req", "-in", str(csr_path),
                "-CA", str(self.root_cert), "-CAkey", str(self.root_key),
                "-set_serial", str(serial), "-days", "1", "-sha256",
                "-copy_extensions", "copy", "-out", str(leaf_path),
            ]
            try:
                run_checked(command)
            except RuntimeError:
                run_checked(command[:-4] + ["-out", str(leaf_path)])
            run_checked(["openssl", "verify", "-CAfile", str(self.root_cert), str(leaf_path)])
            self.leaf = leaf_path.read_bytes()
            self.chain = self.leaf + self.root_pem()
            return self.chain

    def passed(self) -> bool:
        if not self.chain or not self.authenticated:
            return False
        with self.lock:
            requests = list(self.requests)
        entry = self.entry_id
        if entry == "external_ca.awspca":
            with self.lock:
                transcript = list(self.aws_transcript)
            return transcript == [
                ("POST", "/", "ACMPrivateCA.IssueCertificate"),
                ("POST", "/", "ACMPrivateCA.GetCertificate"),
            ]
        if entry == "external_ca.azurekv":
            with self.lock:
                keys = set(self.azure_keys)
                create_count = dict(self.azure_create_count)
                transcript = list(self.azure_transcript)
            if len(keys) != 1:
                return False
            name = next(iter(keys))
            expected = [
                ("miss", name, ""),
                ("create", name, AZURE_KEY_VERSION),
                ("sign", name, AZURE_KEY_VERSION),
            ]
            return (
                AZURE_KEY_NAME_RE.fullmatch(name) is not None
                and create_count.get(name) == 1
                and ordered_transcript_contains(transcript, expected)
                and all(event_name == name and (not version or version == AZURE_KEY_VERSION) for _, event_name, version in transcript)
            )
        required: dict[str, list[tuple[str, str]]] = {
            "external_ca.registry": [("POST", "/services/v2/order/certificate/ssl_plus"), ("GET", "/services/v2/order/certificate/1"), ("GET", "/services/v2/certificate/2/download/format/pem_all")],
            "external_ca.adcs": [("POST", "/certsrv/certfnsh.asp"), ("GET", "/certsrv/certnew.cer")],
            "external_ca.digicert": [("POST", "/services/v2/order/certificate/ssl_plus"), ("GET", "/services/v2/order/certificate/1"), ("GET", "/services/v2/certificate/2/download/format/pem_all")],
            "external_ca.ejbca": [("POST", "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll")],
            "external_ca.entrust": [("POST", "/v1/certificate-authorities/dod-ca/enrollments")],
            "external_ca.gcpcas": [("POST", "/v1/projects/dod/locations/us/caPools/dod/certificates")],
            "external_ca.globalsign": [("POST", "/v2/certificates")],
            "external_ca.letsencrypt": [("POST", "/new-account"), ("POST", "/new-order"), ("POST", "/order/1/finalize"), ("POST", "/cert/1")],
            "external_ca.sectigo": [("POST", "/api/ssl/v1/enroll"), ("GET", "/api/ssl/v1/collect/7/pem")],
            "external_ca.shellca": [("POST", "/dod/shell-sign")],
            "external_ca.smallstep": [("POST", "/1.0/sign")],
            "external_ca.vaultpki": [("POST", "/v1/pki/sign/dod-role")],
            "external_ca.venafi": [("POST", "/vedsdk/Certificates/Request"), ("POST", "/vedsdk/Certificates/Retrieve")],
        }
        expected = required.get(entry)
        return expected is not None and ordered_transcript_contains(requests, expected)


def ordered_transcript_contains(actual: list[tuple], expected: list[tuple]) -> bool:
    """Return true only when every expected operation appears in wire order."""
    index = 0
    for item in actual:
        if index < len(expected) and item == expected[index]:
            index += 1
    return index == len(expected)


def pem_parts(chain: bytes) -> tuple[bytes, bytes]:
    parts = PEM_CERT_RE.findall(chain)
    return parts[0], b"".join(parts[1:])


def pem_der(pem_value: bytes) -> bytes:
    lines = [line for line in pem_value.splitlines() if not line.startswith(b"-----")]
    return base64.b64decode(b"".join(lines))


def decode_jws_payload(body: bytes) -> dict:
    envelope = json.loads(body or b"{}")
    encoded = envelope.get("payload", "")
    if encoded == "":
        return {}
    encoded += "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded))


class Handler(BaseHTTPRequestHandler):
    server_version = "trstctl-dod-external-ca/1"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_args) -> None:
        return

    def _read(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(min(length, 8 << 20))

    def _send(self, status: int, body: bytes = b"{}", content_type: str = "application/json", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.path != "/directory" and self.path != "/dod/root":
            self.send_header("Replay-Nonce", self.state.next_nonce())
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: dict, headers: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(value, separators=(",", ":")).encode(), headers=headers)

    def do_HEAD(self) -> None:
        if self.path == "/new-nonce":
            self.state.record("HEAD", self.path, self.headers)
            self._send(200, b"")
            return
        self._send(404, b"")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/dod/root":
            self._send(200, self.state.root_pem(), "application/x-pem-file")
            return
        if parsed.path == "/directory":
            base = self.state.bind_public_origin(self.headers)
            self.state.record("GET", parsed.path, self.headers, bool(base))
            if not base:
                self._json(400, {"type": "urn:ietf:params:acme:error:malformed", "detail": "invalid public origin"})
                return
            self._json(200, {"newNonce": base + "/new-nonce", "newAccount": base + "/new-account", "newOrder": base + "/new-order", "meta": {"termsOfService": base + "/terms"}})
            return
        self._provider_request("GET")

    def do_POST(self) -> None:
        self._provider_request("POST")

    def do_PUT(self) -> None:
        self._provider_request("PUT")

    def _provider_request(self, method: str) -> None:
        body = self._read()
        parsed = urlparse(self.path)
        path = parsed.path
        entry = self.state.entry_id
        effective = "external_ca.digicert" if entry == "external_ca.registry" else entry

        if effective == "external_ca.adcs":
            expected = "Basic " + base64.b64encode(b"dod-user:dod-token").decode()
            authenticated = self.headers.get("Authorization", "") == expected
            self.state.record(method, path, self.headers, authenticated)
            if method == "POST" and path.endswith("/certfnsh.asp"):
                form = parse_qs(body.decode())
                self.state.sign(form.get("CertRequest", [""])[0].encode())
                self._send(200, b'<a href="certnew.cer?ReqID=42&Enc=b64">issued</a>', "text/html")
                return
            if method == "GET" and path.endswith("/certnew.cer"):
                self._send(200, self.state.chain, "application/pem-certificate-chain")
                return

        if effective == "external_ca.awspca":
            authenticated = verify_sigv4(
                method, self.path, self.headers, body,
                access_key="AKIADOD", secret_key=b"dod-token", region="us-east-1", service="acm-pca",
            )
            self.state.record(method, path, self.headers, authenticated)
            payload = json.loads(body or b"{}")
            target = self.headers.get("X-Amz-Target", "")
            if not authenticated:
                self._json(403, {"__type": "UnrecognizedClientException", "message": "invalid SigV4 authentication"})
                return
            if method == "POST" and path == "/" and target == "ACMPrivateCA.IssueCertificate":
                self.state.aws_event(method, path, target)
                self.state.sign(base64.b64decode(payload["Csr"]))
                self._json(200, {"CertificateArn": "arn:aws:acm-pca:us-east-1:123:certificate-authority/dod/certificate/dod"})
                return
            if method == "POST" and path == "/" and target == "ACMPrivateCA.GetCertificate":
                self.state.aws_event(method, path, target)
                leaf, issuer = pem_parts(self.state.chain)
                self._json(200, {"Certificate": leaf.decode(), "CertificateChain": issuer.decode()})
                return

        if effective == "external_ca.azurekv":
            authenticated = self.headers.get("Authorization", "") == "Bearer dod-token"
            payload = json.loads(body or b"{}")
            create_match = re.fullmatch(r"/keys/([^/]+)/create", path)
            get_match = re.fullmatch(r"/keys/([^/]+)(?:/([^/]+))?", path)
            sign_match = re.fullmatch(r"/keys/([^/]+)/([^/]+)/sign", path)
            if method == "POST" and create_match is not None:
                name = create_match.group(1)
                valid = AZURE_KEY_NAME_RE.fullmatch(name) is not None and payload.get("kty") in {"RSA", "RSA-HSM"} and payload.get("key_size") == 2048
                self.state.record(method, path, self.headers, authenticated and valid)
                if not authenticated:
                    self._json(401, {"error": {"code": "Unauthorized", "message": "bearer token required"}})
                    return
                if not valid:
                    self._json(400, {"error": {"code": "BadParameter", "message": "RSA-HSM signing key required"}})
                    return
                if not self.state.azure_create(name):
                    self._json(409, {"error": {"code": "Conflict", "message": "key already exists"}})
                    return
                self.state.azure_event("create", name, AZURE_KEY_VERSION)
                n, e = self.state.rsa_jwk()
                self._json(200, {"key": {"kid": f"https://dod.managedhsm.azure.net/keys/{name}/{AZURE_KEY_VERSION}", "kty": "RSA-HSM", "n": n, "e": e, "key_ops": ["sign", "verify"]}})
                return
            if method == "GET" and get_match is not None:
                name, version = get_match.groups()
                valid = AZURE_KEY_NAME_RE.fullmatch(name) is not None and (version is None or version == AZURE_KEY_VERSION)
                self.state.record(method, path, self.headers, authenticated and valid)
                if not authenticated:
                    self._json(401, {"error": {"code": "Unauthorized", "message": "bearer token required"}})
                    return
                if not valid or not self.state.azure_exists(name):
                    if authenticated and valid:
                        self.state.azure_event("miss", name)
                    self._json(404, {"error": {"code": "KeyNotFound", "message": "key not found"}})
                    return
                n, e = self.state.rsa_jwk()
                self._json(200, {"key": {"kid": f"https://dod.managedhsm.azure.net/keys/{name}/{AZURE_KEY_VERSION}", "kty": "RSA-HSM", "n": n, "e": e, "key_ops": ["sign", "verify"]}})
                return
            if method == "POST" and sign_match is not None:
                name, version = sign_match.groups()
                valid = AZURE_KEY_NAME_RE.fullmatch(name) is not None and version == AZURE_KEY_VERSION and payload.get("alg") == "RS256" and isinstance(payload.get("value"), str)
                self.state.record(method, path, self.headers, authenticated and valid)
                if not authenticated:
                    self._json(401, {"error": {"code": "Unauthorized", "message": "bearer token required"}})
                    return
                if not valid:
                    self._json(400, {"error": {"code": "BadParameter", "message": "RS256 required"}})
                    return
                if not self.state.azure_exists(name):
                    self._json(404, {"error": {"code": "KeyNotFound", "message": "key not found"}})
                    return
                encoded = payload["value"] + "=" * (-len(payload["value"]) % 4)
                signature = self.state.sign_digest(base64.urlsafe_b64decode(encoded))
                self.state.azure_event("sign", name, version)
                self._json(200, {"value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()})
                return
            self.state.record(method, path, self.headers, False)

        if effective == "external_ca.digicert":
            authenticated = self.headers.get("X-DC-DEVKEY", "") == "dod-token"
            self.state.record(method, path, self.headers, authenticated)
            if method == "POST" and "/order/certificate/" in path:
                payload = json.loads(body)
                self.state.sign(payload["certificate"]["csr"].encode())
                self._json(201, {"id": 1, "certificate_id": 2})
                return
            if method == "GET" and path.endswith("/order/certificate/1"):
                self._json(200, {"status": "issued", "certificate": {"id": 2}})
                return
            if method == "GET" and "/download/format/pem_all" in path:
                self._send(200, self.state.chain, "application/pem-certificate-chain")
                return

        if effective == "external_ca.ejbca":
            authenticated = self.headers.get("Authorization", "") == "Bearer dod-token"
            self.state.record(method, path, self.headers, authenticated)
            payload = json.loads(body)
            chain = self.state.sign(payload["certificate_request"].encode())
            leaf, issuer = pem_parts(chain)
            self._json(200, {"certificate": base64.b64encode(pem_der(leaf)).decode(), "certificate_chain": [base64.b64encode(pem_der(issuer)).decode()], "response_format": "DER"})
            return

        if effective == "external_ca.entrust":
            self.state.record(method, path, self.headers)
            payload = json.loads(body)
            chain = self.state.sign(payload["csr"].encode())
            leaf, issuer = pem_parts(chain)
            self._json(200, {"trackingId": "dod-track", "status": "ISSUED", "certificate": leaf.decode(), "chain": issuer.decode()})
            return

        if effective == "external_ca.gcpcas":
            authenticated = self.headers.get("Authorization", "") == "Bearer dod-token"
            self.state.record(method, path, self.headers, authenticated)
            payload = json.loads(body)
            chain = self.state.sign(payload["pemCsr"].encode())
            leaf, issuer = pem_parts(chain)
            self._json(200, {"name": "dod-certificate", "pemCertificate": leaf.decode(), "pemCertificateChain": [issuer.decode()]})
            return

        if effective == "external_ca.globalsign":
            authenticated = self.headers.get("ApiKey", "") == "dod-token" and self.headers.get("ApiSecret", "") == "dod-token"
            self.state.record(method, path, self.headers, authenticated)
            payload = json.loads(body)
            chain = self.state.sign(payload["csr"].encode())
            leaf, issuer = pem_parts(chain)
            self._json(200, {"status": "issued", "serial_number": "1001", "certificate": leaf.decode(), "chain": issuer.decode()})
            return

        if effective == "external_ca.letsencrypt":
            base = self.state.bind_public_origin(self.headers)
            authenticated, jws_payload = verify_acme_jws(
                self.state, body, path, base, new_account=path == "/new-account",
            )
            self.state.record(method, path, self.headers, bool(base) and authenticated)
            if not base or not authenticated:
                self._json(400, {"type": "urn:ietf:params:acme:error:malformed", "detail": "invalid JWS"})
                return
            if path == "/new-nonce":
                self._send(200, b"")
                return
            if path == "/new-account":
                self._json(201, {"status": "valid", "orders": base + "/account/1/orders"}, {"Location": base + "/account/1"})
                return
            if path == "/new-order":
                self._json(201, {"status": "ready", "authorizations": [base + "/authz/1"], "finalize": base + "/order/1/finalize"}, {"Location": base + "/order/1"})
                return
            if path == "/authz/1":
                self._json(200, {"status": "valid", "identifier": {"type": "dns", "value": "dod.example"}})
                return
            if path == "/order/1/finalize":
                csr = jws_payload["csr"] + "=" * (-len(jws_payload["csr"]) % 4)
                self.state.sign(base64.urlsafe_b64decode(csr))
                self._json(200, {"status": "valid", "finalize": base + path, "certificate": base + "/cert/1"}, {"Location": base + "/order/1"})
                return
            if path == "/cert/1":
                self._send(200, self.state.chain, "application/pem-certificate-chain")
                return

        if effective == "external_ca.sectigo":
            authenticated = self.headers.get("login", "") == "dod-login" and self.headers.get("password", "") == "dod-token" and self.headers.get("customerUri", "") == "dod-customer"
            self.state.record(method, path, self.headers, authenticated)
            if method == "POST" and path.endswith("/enroll"):
                payload = json.loads(body)
                self.state.sign(payload["csr"].encode())
                self._json(200, {"sslId": 7, "renewId": "dod"})
                return
            if method == "GET" and "/collect/" in path:
                self._send(200, self.state.chain, "application/pem-certificate-chain")
                return

        if effective == "external_ca.shellca" and path == "/dod/shell-sign":
            self.state.record(method, path, self.headers)
            payload = json.loads(body)
            chain = self.state.sign(payload["csr"].encode())
            self._json(200, {"chain": chain.decode()})
            return

        if effective == "external_ca.smallstep":
            payload = json.loads(body)
            base = self.state.bind_public_origin(self.headers)
            authenticated = verify_hs256_jwt(
                payload.get("ott", ""), b"0123456789abcdef0123456789abcdef",
                issuer="dod-provisioner", audience=base + "/1.0/sign",
            )
            self.state.record(method, path, self.headers, bool(base) and authenticated)
            if not base or not authenticated:
                self._json(401, {"error": "invalid provisioner token or public origin"})
                return
            chain = self.state.sign(payload["csr"].encode())
            leaf, issuer = pem_parts(chain)
            self._json(200, {"crt": leaf.decode(), "ca": issuer.decode(), "certChain": [leaf.decode(), issuer.decode()]})
            return

        if effective == "external_ca.vaultpki":
            authenticated = self.headers.get("X-Vault-Token", "") == "dod-token"
            self.state.record(method, path, self.headers, authenticated)
            payload = json.loads(body)
            chain = self.state.sign(payload["csr"].encode())
            leaf, issuer = pem_parts(chain)
            self._json(200, {"data": {"certificate": leaf.decode(), "issuing_ca": issuer.decode(), "ca_chain": [issuer.decode()], "serial_number": "10:01"}})
            return

        if effective == "external_ca.venafi":
            authenticated = self.headers.get("Authorization", "") == "Bearer dod-token"
            self.state.record(method, path, self.headers, authenticated)
            if path.endswith("/Request"):
                payload = json.loads(body)
                self.state.sign(payload["PKCS10"].encode())
                self._json(200, {"CertificateDN": "\\VED\\Policy\\dod", "Guid": "dod-guid"})
                return
            if path.endswith("/Retrieve"):
                self._json(200, {"CertificateData": self.state.chain.decode(), "Status": "ISSUED"})
                return

        self.state.record(method, path, self.headers, False)
        self._json(404, {"error": f"unhandled {method} {path} for {entry}"})


def serve() -> int:
    challenge = required_env("TRSTCTL_DOD_CHALLENGE")
    entry_id = required_env("TRSTCTL_DOD_ENTRY_ID")
    identity = required_env("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = required_env("TRSTCTL_DOD_CONTRACT_DIGEST")
    root = Path(tempfile.mkdtemp(prefix="trstctl-dod-external-ca-"))
    state = State(entry_id, root)
    host = choose_private_host()
    server = LoopbackHTTPServer((host, 0), Handler)
    server.state = state  # type: ignore[attr-defined]
    scheme = "http"
    if entry_id in ("external_ca.adcs", "external_ca.entrust"):
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        if entry_id == "external_ca.adcs":
            tls_context.load_cert_chain(
                certfile=required_env("TRSTCTL_ADCS_TLS_SERVER_CERT_FILE"),
                keyfile=required_env("TRSTCTL_ADCS_TLS_SERVER_KEY_FILE"),
            )
        else:
            tls_context.verify_mode = ssl.CERT_REQUIRED
            tls_context.load_cert_chain(
                certfile=required_env("TRSTCTL_ENTRUST_MTLS_SERVER_CERT_FILE"),
                keyfile=required_env("TRSTCTL_ENTRUST_MTLS_SERVER_KEY_FILE"),
            )
            tls_context.load_verify_locations(
                cafile=required_env("TRSTCTL_ENTRUST_MTLS_CLIENT_CA_FILE"),
            )
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    state.base_url = f"{scheme}://{host}:{server.server_port}"
    stopped = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    json_line({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "ready": True, "endpoint": state.base_url,
    })
    while not stopped.wait(0.1):
        pass
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
    passed = state.passed()
    if not passed:
        with state.lock:
            diagnostic = {
                "entry_id": state.entry_id,
                "requests": list(state.requests),
                "authenticated": state.authenticated,
                "has_chain": bool(state.chain),
                "aws_transcript": list(state.aws_transcript),
                "azure_transcript": list(state.azure_transcript),
            }
        print("external-CA proof failed: " + json.dumps(diagnostic, sort_keys=True, separators=(",", ":")), file=sys.stderr, flush=True)
    json_line({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "passed": passed,
    })
    shutil.rmtree(root, ignore_errors=True)
    return 0 if passed else 1


def sign_command(endpoint: str, csr_path: str, output_path: str) -> int:
    csr = Path(csr_path).read_text()
    request = Request(endpoint.rstrip("/") + "/dod/shell-sign", data=json.dumps({"csr": csr}).encode(), method="POST", headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=10) as response:
        value = json.load(response)
    Path(output_path).write_text(value["chain"])
    os.chmod(output_path, 0o600)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    signer = sub.add_parser("sign")
    signer.add_argument("--endpoint", required=True)
    signer.add_argument("csr")
    signer.add_argument("output")
    args = parser.parse_args()
    if args.command == "sign":
        return sign_command(args.endpoint, args.csr, args.output)
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
