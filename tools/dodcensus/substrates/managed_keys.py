#!/usr/bin/env python3
"""Nonce-bound KMS/HSM custody substrate for the production DoD census.

Cloud modes implement the vendor data-plane protocols and cryptographically
authenticate every request. Hardware modes accept only an independently read
device transcript and verify its signature with OpenSSL before passing.
"""

from __future__ import annotations

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
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlparse


MAX_BODY = 1 << 20
AWS_ACCESS_KEY = "AKIADODMANAGEDKEY"
AWS_SECRET_KEY = b"dod-aws-managed-key-secret-material"
AWS_REGION = "us-east-1"
AZURE_TOKEN = "dod-azure-managed-key-bearer"
GCP_TOKEN = "dod-gcp-managed-key-bearer"
GCP_PARENT = "projects/dod/locations/us/keyRings/runtime"
PROBE = b"trstctl managed-key custody proof v1"
INNER_ENV = "TRSTCTL_HSM_PROOF_INNER"
NETWORK_ENV = "TRSTCTL_HSM_PROOF_NETWORK"
IMAGE_ENV = "TRSTCTL_HSM_PROOF_IMAGE"
CONTAINER_ENDPOINT_ENV = "TRSTCTL_HSM_CONTAINER_ENDPOINT"
DOCKER_HOST_ENDPOINT_ENV = "TRSTCTL_RUNTIME_DOCKER_HOST"
INNER_PORT = 8080


class LoopbackHTTPServer(ThreadingHTTPServer):
    """Bind without HTTPServer's reverse-DNS lookup on the loopback address."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing {name}")
    return value


def required_image_id() -> str:
    value = required_env(IMAGE_ENV)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise SystemExit(f"{IMAGE_ENV} must be a content-addressed Docker image id")
    return value


def inner_envelope_matches(
    value: object, *, challenge: str, entry_id: str, identity: str,
    contract: str, flag: str, outer_pid: int, expected_pid: int | None = None,
) -> bool:
    if type(value) is not dict or value.get(flag) is not True:
        return False
    pid = value.get("pid")
    if type(value.get("schema_version")) is not int or value.get("schema_version") != 1:
        return False
    if type(pid) is not int or pid <= 0 or pid == outer_pid:
        return False
    if expected_pid is not None and pid != expected_pid:
        return False
    expected = {
        "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract,
    }
    return all(
        isinstance(value.get(name), str) and hmac.compare_digest(value[name], wanted)
        for name, wanted in expected.items()
    )


def json_line(value: object) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def run_openssl(args: list[str], *, data: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["openssl", *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace")[:240])
    return result.stdout


def verify_sigv4(method: str, raw_path: str, headers, body: bytes) -> bool:
    """Verify the complete AWS KMS SigV4 MAC and canonical request."""
    try:
        algorithm = "AWS4-HMAC-SHA256"
        authorization = headers.get("Authorization", "")
        if not authorization.startswith(algorithm + " "):
            return False
        fields: dict[str, str] = {}
        for item in authorization[len(algorithm) + 1 :].split(","):
            name, value = item.strip().split("=", 1)
            fields[name] = value
        credential = fields["Credential"].split("/")
        if credential != [AWS_ACCESS_KEY, credential[1], AWS_REGION, "kms", "aws4_request"]:
            return False
        signed = fields["SignedHeaders"].split(";")
        if signed != sorted(signed) or "host" not in signed:
            return False
        amz_date = headers.get("X-Amz-Date", "")
        if len(amz_date) != 16 or credential[1] != amz_date[:8]:
            return False
        parsed = urlparse(raw_path)
        canonical_uri = quote(unquote(parsed.path or "/"), safe="/-_.~")
        query_items = sorted(
            (quote(k, safe="-_.~"), quote(v, safe="-_.~"))
            for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        )
        canonical_query = "&".join(f"{k}={v}" for k, v in query_items)
        canonical_headers = ""
        for name in signed:
            header_value = headers.get(name, "")
            if header_value == "":
                return False
            canonical_headers += f"{name}:{' '.join(header_value.strip().split())}\n"
        canonical_request = "\n".join(
            (method, canonical_uri, canonical_query, canonical_headers,
             fields["SignedHeaders"], hashlib.sha256(body).hexdigest())
        )
        scope = "/".join(credential[1:])
        to_sign = "\n".join(
            (algorithm, amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest())
        )
        date_key = hmac.new(b"AWS4" + AWS_SECRET_KEY, credential[1].encode(), hashlib.sha256).digest()
        region_key = hmac.new(date_key, AWS_REGION.encode(), hashlib.sha256).digest()
        service_key = hmac.new(region_key, b"kms", hashlib.sha256).digest()
        signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
        expected = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, fields["Signature"])
    except (KeyError, ValueError, TypeError, IndexError):
        return False


class Key:
    def __init__(self, root: Path, key_id: str, tags: dict[str, str] | None = None) -> None:
        self.key_id = key_id
        self.private = root / f"{key_id}.pem"
        self.public_pem = root / f"{key_id}.pub.pem"
        run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.private)])
        run_openssl(["pkey", "-in", str(self.private), "-pubout", "-out", str(self.public_pem)])
        self.public_der = run_openssl(["pkey", "-in", str(self.private), "-pubout", "-outform", "DER"])
        self.state = "active"
        self.signature = b""
        self.digest = b""
        self.tags = dict(tags or {})

    def sign_digest(self, digest: bytes) -> bytes:
        if self.state != "active" or len(digest) != 32:
            raise RuntimeError("key is not active or digest is invalid")
        signature = run_openssl(
            ["pkeyutl", "-sign", "-inkey", str(self.private), "-pkeyopt", "digest:sha256"],
            data=digest,
        )
        # OpenSSL cannot frame the signature and digest through one stdin, so
        # keep the verification inputs in separate private temporary files.
        with tempfile.TemporaryDirectory(prefix="trstctl-managed-verify-") as raw:
            directory = Path(raw)
            (directory / "sig").write_bytes(signature)
            (directory / "digest").write_bytes(digest)
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(self.public_pem),
                 "-in", str(directory / "digest"), "-sigfile", str(directory / "sig"),
                 "-pkeyopt", "digest:sha256"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
            )
        if result.returncode != 0:
            raise RuntimeError("OpenSSL rejected provider signature")
        self.signature = signature
        self.digest = digest
        return signature


def verify_message(public_der: bytes, signature: bytes, message: bytes) -> bool:
    """Independently verify an RSA/SHA-256 signature; malformed input is false."""
    try:
        if len(public_der) < 128 or len(signature) < 64 or len(message) < 16:
            return False
        with tempfile.TemporaryDirectory(prefix="trstctl-hsm-witness-") as raw:
            root = Path(raw)
            (root / "public.der").write_bytes(public_der)
            (root / "signature").write_bytes(signature)
            (root / "message").write_bytes(message)
            public_pem = run_openssl(
                ["pkey", "-pubin", "-inform", "DER", "-in", str(root / "public.der"), "-outform", "PEM"]
            )
            (root / "public.pem").write_bytes(public_pem)
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(root / "public.pem"),
                 "-signature", str(root / "signature"), str(root / "message")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
            )
            return result.returncode == 0
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return False


class State:
    def __init__(self, entry_id: str, root: Path) -> None:
        self.entry_id = entry_id
        self.root = root
        self.mode = self._mode(entry_id)
        self.lock = threading.Lock()
        self.keys: dict[str, Key] = {}
        self.next_key = 0
        self.auth_failures = 0
        self.create_count = 0
        self.sign_count = 0
        self.revoke_count = 0
        self.zeroize_count = 0
        self.readbacks: set[str] = set()
        self.hardware_verified = False
        self.provider_requests = 0
        self.last_provider_request: dict[str, str] = {}

    @staticmethod
    def _mode(entry_id: str) -> str:
        if entry_id in {"hsm_kms.runtime", "hsm_kms.aws_kms"}:
            return "aws"
        if entry_id == "hsm_kms.azure_key_vault":
            return "azure"
        if entry_id == "hsm_kms.gcp_kms":
            return "gcp"
        return "hardware"

    def create(self, prefix: str, tags: dict[str, str] | None = None) -> Key:
        with self.lock:
            self.next_key += 1
            key_id = f"{prefix}-{self.next_key}"
        return self.create_named(key_id, tags)

    def create_named(self, key_id: str, tags: dict[str, str] | None = None) -> Key:
        with self.lock:
            if key_id in self.keys:
                raise ValueError("provider key already exists")
        key = Key(self.root, key_id, tags)
        with self.lock:
            self.keys[key_id] = key
            self.create_count += 1
        return key

    def key(self, key_id: str) -> Key | None:
        if "/keys/" in key_id:
            key_id = key_id.split("/keys/", 1)[1].split("/", 1)[0]
        elif "/cryptoKeys/" in key_id:
            key_id = key_id.split("/cryptoKeys/", 1)[1].split("/", 1)[0]
        with self.lock:
            return self.keys.get(key_id)

    def observe_provider_request(self, method: str, path: str, target: str = "") -> None:
        with self.lock:
            self.provider_requests += 1
            self.last_provider_request = {
                "method": method,
                "path": path[:240],
                "target": target[:120],
            }

    def diagnostics(self) -> dict[str, object]:
        with self.lock:
            return {
                "mode": self.mode,
                "provider_requests": self.provider_requests,
                "last_provider_request": dict(self.last_provider_request),
                "auth_failures": self.auth_failures,
                "create_count": self.create_count,
                "sign_count": self.sign_count,
                "revoke_count": self.revoke_count,
                "zeroize_count": self.zeroize_count,
                "key_count": len(self.keys),
            }

    def passed(self) -> bool:
        with self.lock:
            if self.auth_failures != 0:
                return False
            if self.mode == "hardware":
                return self.hardware_verified
            return (
                self.create_count >= 2 and self.sign_count >= 2
                and self.revoke_count >= 1 and self.zeroize_count >= 1
                and {"active", "revoked", "zeroized"}.issubset(self.readbacks)
            )


def verify_hardware_witness(value: object) -> bool:
    try:
        if not isinstance(value, dict):
            return False
        generated = value["generated_key"]
        rotated = value["rotated_key"]
        public_der = base64.b64decode(value["public_der"], validate=True)
        signature = base64.b64decode(value["signature"], validate=True)
        message = base64.b64decode(value["message"], validate=True)
        if generated == rotated or len(public_der) < 128 or len(signature) < 64 or len(message) < 16:
            return False
        if not (value.get("generated_present") and value.get("rotated_present") and value.get("revoked_denied") and value.get("zeroized_absent")):
            return False
        return verify_message(public_der, signature, message)
    except (KeyError, ValueError, TypeError, RuntimeError):
        return False


def handler_for(state: State):
    class Handler(BaseHTTPRequestHandler):
        server_version = "trstctl-dod-managed-keys/1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def body(self) -> bytes:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return b""
            if length < 0 or length > MAX_BODY:
                return b""
            return self.rfile.read(length)

        def send_json(self, status: int, value: object) -> None:
            body = compact(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authenticated(self, body: bytes) -> bool:
            if state.mode == "aws":
                valid = verify_sigv4(self.command, self.path, self.headers, body)
            elif state.mode == "azure":
                valid = hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + AZURE_TOKEN)
            elif state.mode == "gcp":
                valid = hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + GCP_TOKEN)
            else:
                valid = False
            if not valid:
                with state.lock:
                    state.auth_failures += 1
            return valid

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/dod/config":
                self.send_json(200, {
                    "provider": state.mode, "endpoint": f"http://{self.headers.get('Host')}",
                    "container_endpoint": os.environ.get(CONTAINER_ENDPOINT_ENV, ""),
                    "aws_access_key_id": AWS_ACCESS_KEY, "aws_secret_access_key": AWS_SECRET_KEY.decode(),
                    "aws_region": AWS_REGION, "azure_token": AZURE_TOKEN, "gcp_token": GCP_TOKEN,
                    "gcp_parent": GCP_PARENT,
                })
                return
            if parsed.path == "/dod/diagnostics":
                self.send_json(200, state.diagnostics())
                return
            if parsed.path == "/dod/readback":
                query = parse_qs(parsed.query)
                key = state.key(query.get("key_id", [""])[0])
                expected = query.get("expect", [""])[0]
                if key is None or key.state != expected or not key.signature:
                    self.send_json(409, {"error": "provider state/signature readback mismatch"})
                    return
                with state.lock:
                    state.readbacks.add(expected)
                self.send_json(200, {
                    "key_id": key.key_id, "state": key.state,
                    "public_der": base64.b64encode(key.public_der).decode(),
                    "signature": base64.b64encode(key.signature).decode(),
                    "digest": base64.b64encode(key.digest).decode(),
                    "private_export": "denied: provider custody is non-exportable",
                })
                return
            state.observe_provider_request(self.command, self.path, self.headers.get("X-Amz-Target", ""))
            if state.mode == "azure" and parsed.path.startswith("/keys/"):
                if not self.authenticated(b""):
                    self.send_json(401, {"error": {"code": "Unauthorized"}})
                    return
                parts = parsed.path.strip("/").split("/")
                key = state.key(parts[1] if len(parts) > 1 else "")
                if key is None or key.state == "zeroized":
                    self.send_json(404, {"error": {"code": "KeyNotFound"}})
                    return
                self.send_json(200, {
                    "key": {"kid": f"https://dod.managedhsm.azure.net/keys/{key.key_id}/v1"},
                    "der": base64.b64encode(key.public_der).decode(),
                    "attributes": {"enabled": key.state == "active"},
                })
                return
            if state.mode == "gcp" and "/cryptoKeys/" in parsed.path:
                if not self.authenticated(b""):
                    self.send_json(401, {"error": {"status": "UNAUTHENTICATED"}})
                    return
                key_id = parsed.path.split("/cryptoKeys/", 1)[1].split("/", 1)[0]
                key = state.key(key_id)
                if key is None:
                    self.send_json(404, {"error": {"status": "NOT_FOUND"}})
                    return
                resource = f"{GCP_PARENT}/cryptoKeys/{key.key_id}"
                if parsed.path.endswith("/publicKey"):
                    if key.state == "zeroized":
                        self.send_json(404, {"error": {"status": "NOT_FOUND"}})
                        return
                    self.send_json(200, {"pem": key.public_pem.read_text()})
                elif "/cryptoKeyVersions/" in parsed.path:
                    version_state = {
                        "active": "ENABLED", "revoked": "DISABLED", "zeroized": "DESTROY_SCHEDULED",
                    }[key.state]
                    self.send_json(200, {"name": resource + "/cryptoKeyVersions/1", "state": version_state})
                else:
                    self.send_json(200, {"name": resource, "purpose": "ASYMMETRIC_SIGN"})
                return
            self.send_json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            body = self.body()
            if self.path == "/dod/witness":
                try:
                    value = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    value = None
                valid = state.mode == "hardware" and verify_hardware_witness(value)
                with state.lock:
                    state.hardware_verified = valid
                self.send_json(200 if valid else 400, {"accepted": valid})
                return
            state.observe_provider_request(self.command, self.path, self.headers.get("X-Amz-Target", ""))
            if not self.authenticated(body):
                self.send_json(401, {"error": "cryptographic authentication required"})
                return
            try:
                value = json.loads(body or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_json(400, {"error": "invalid json"})
                return
            try:
                if state.mode == "aws":
                    self.aws(value)
                elif state.mode == "azure":
                    self.azure(value)
                else:
                    self.gcp(value)
            except (KeyError, ValueError, RuntimeError, IndexError) as error:
                self.send_json(400, {"error": str(error)[:160]})

        def do_PATCH(self) -> None:  # noqa: N802
            body = self.body()
            state.observe_provider_request(self.command, self.path, self.headers.get("X-Amz-Target", ""))
            if not self.authenticated(body):
                self.send_json(401, {"error": {"code": "Unauthorized"}})
                return
            path = urlparse(self.path).path
            if state.mode == "azure":
                key_id = path.strip("/").split("/")[1]
            elif state.mode == "gcp" and "/cryptoKeys/" in path:
                key_id = path.split("/cryptoKeys/", 1)[1].split("/", 1)[0]
            else:
                self.send_json(404, {"error": "unknown patch operation"})
                return
            key = state.key(key_id)
            if key is None:
                self.send_json(404, {"error": {"code": "KeyNotFound"}})
                return
            key.state = "revoked"
            with state.lock:
                state.revoke_count += 1
            if state.mode == "azure":
                self.send_json(200, {"attributes": {"enabled": False}})
            else:
                self.send_json(200, {"state": "DISABLED"})

        def do_DELETE(self) -> None:  # noqa: N802
            body = self.body()
            state.observe_provider_request(self.command, self.path, self.headers.get("X-Amz-Target", ""))
            if state.mode != "azure" or not self.authenticated(body):
                self.send_json(401, {"error": {"code": "Unauthorized"}})
                return
            key_id = urlparse(self.path).path.strip("/").split("/")[1]
            key = state.key(key_id)
            if key is None:
                self.send_json(404, {"error": {"code": "KeyNotFound"}})
                return
            key.state = "zeroized"
            with state.lock:
                state.zeroize_count += 1
            self.send_json(200, {"recoveryId": "deleted/" + key_id})

        def aws(self, value: dict) -> None:
            target = self.headers.get("X-Amz-Target", "")
            if target == "TrentService.ListKeys":
                with state.lock:
                    key_ids = sorted(state.keys)
                self.send_json(200, {
                    "Keys": [
                        {"KeyId": key_id, "KeyArn": f"arn:aws:kms:{AWS_REGION}:123456789012:key/{key_id}"}
                        for key_id in key_ids
                    ],
                    "Truncated": False,
                })
                return
            if target == "TrentService.ListResourceTags":
                key = state.key(value.get("KeyId", ""))
                if key is None:
                    self.send_json(400, {"__type": "NotFoundException"})
                    return
                self.send_json(200, {
                    "Tags": [
                        {"TagKey": name, "TagValue": tag_value}
                        for name, tag_value in sorted(key.tags.items())
                    ],
                    "Truncated": False,
                })
                return
            if target == "TrentService.CreateKey":
                if value.get("KeyUsage") != "SIGN_VERIFY" or value.get("KeySpec") != "RSA_2048":
                    raise ValueError("invalid AWS asymmetric key request")
                tags = value.get("Tags", [])
                if not isinstance(tags, list) or any(
                    not isinstance(tag, dict) or not isinstance(tag.get("TagKey"), str)
                    or not isinstance(tag.get("TagValue"), str)
                    for tag in tags
                ):
                    raise ValueError("invalid AWS key tags")
                key = state.create("aws-key", {tag["TagKey"]: tag["TagValue"] for tag in tags})
                self.send_json(200, {"KeyMetadata": {
                    "KeyId": key.key_id, "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY",
                    "KeyState": "Enabled", "Enabled": True,
                }})
                return
            key = state.key(value.get("KeyId", ""))
            if key is None:
                self.send_json(400, {"__type": "NotFoundException"})
                return
            if target == "TrentService.DescribeKey":
                provider_state = {
                    "active": "Enabled", "revoked": "Disabled", "zeroized": "PendingDeletion",
                }[key.state]
                self.send_json(200, {"KeyMetadata": {
                    "KeyId": key.key_id, "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY",
                    "KeyState": provider_state, "Enabled": provider_state == "Enabled",
                }})
            elif target == "TrentService.GetPublicKey":
                self.send_json(200, {"PublicKey": base64.b64encode(key.public_der).decode()})
            elif target == "TrentService.Sign":
                digest = base64.b64decode(value["Message"], validate=True)
                signature = key.sign_digest(digest)
                with state.lock:
                    state.sign_count += 1
                self.send_json(200, {"Signature": base64.b64encode(signature).decode()})
            elif target == "TrentService.DisableKey":
                key.state = "revoked"
                with state.lock:
                    state.revoke_count += 1
                self.send_json(200, {})
            elif target == "TrentService.ScheduleKeyDeletion":
                key.state = "zeroized"
                with state.lock:
                    state.zeroize_count += 1
                self.send_json(200, {"KeyId": key.key_id})
            else:
                raise ValueError("unknown AWS KMS target")

        def azure(self, value: dict) -> None:
            path = urlparse(self.path).path
            if path.endswith("/create"):
                if value.get("kty") != "RSA" or value.get("key_size") != 2048:
                    raise ValueError("invalid Azure RSA-HSM create request")
                key_name = path.strip("/").split("/")[1]
                key = state.create_named(key_name)
                self.send_json(200, {
                    "key": {"kid": f"https://dod.managedhsm.azure.net/keys/{key.key_id}/v1"},
                    "der": base64.b64encode(key.public_der).decode(),
                    "attributes": {"enabled": True},
                })
                return
            if path.endswith("/sign"):
                key_id = path.strip("/").split("/")[1]
                key = state.key(key_id)
                if key is None or value.get("alg") != "RS256":
                    raise ValueError("invalid Azure sign request")
                signature = key.sign_digest(decode_b64url(value["value"]))
                with state.lock:
                    state.sign_count += 1
                self.send_json(200, {"value": b64url(signature)})
                return
            raise ValueError("unknown Azure Key Vault operation")

        def gcp(self, value: dict) -> None:
            path = urlparse(self.path).path.removeprefix("/v1/").lstrip("/")
            if path.endswith("/cryptoKeys"):
                query = parse_qs(urlparse(self.path).query)
                requested = query.get("cryptoKeyId", [""])[0]
                template = value.get("versionTemplate", {})
                if not requested or value.get("purpose") != "ASYMMETRIC_SIGN" or not isinstance(template, dict) or template.get("algorithm") != "RSA_SIGN_PKCS1_2048_SHA256":
                    raise ValueError("invalid GCP asymmetric key request")
                key = state.create_named(requested)
                self.send_json(200, {"name": f"{GCP_PARENT}/cryptoKeys/{key.key_id}"})
                return
            if path.endswith(":asymmetricSign"):
                key_id = path.split("/cryptoKeys/", 1)[1].split("/", 1)[0]
                key = state.key(key_id)
                if key is None:
                    raise ValueError("unknown GCP key")
                digest = base64.b64decode(value["digest"]["sha256"], validate=True)
                signature = key.sign_digest(digest)
                with state.lock:
                    state.sign_count += 1
                self.send_json(200, {"signature": base64.b64encode(signature).decode()})
                return
            if path.endswith(":disable"):
                key_id = path.split("/cryptoKeys/", 1)[1].split("/", 1)[0]
                key = state.key(key_id)
                if key is None:
                    raise ValueError("unknown GCP key")
                key.state = "revoked"
                with state.lock:
                    state.revoke_count += 1
                self.send_json(200, {"state": "DISABLED"})
                return
            if path.endswith(":destroy"):
                key_id = path.split("/cryptoKeys/", 1)[1].split("/", 1)[0]
                key = state.key(key_id)
                if key is None:
                    raise ValueError("unknown GCP key")
                key.state = "zeroized"
                with state.lock:
                    state.zeroize_count += 1
                self.send_json(200, {"state": "DESTROY_SCHEDULED"})
                return
            raise ValueError("unknown GCP KMS operation")

    return Handler


def serve_main() -> int:
    challenge = required_env("TRSTCTL_DOD_CHALLENGE")
    entry_id = required_env("TRSTCTL_DOD_ENTRY_ID")
    identity = required_env("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = required_env("TRSTCTL_DOD_CONTRACT_DIGEST")
    root = Path(tempfile.mkdtemp(prefix="trstctl-dod-managed-keys-"))
    state = State(entry_id, root)
    inner = os.environ.get(INNER_ENV) == "1"
    server = LoopbackHTTPServer(("0.0.0.0" if inner else "127.0.0.1", INNER_PORT if inner else 0), handler_for(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    json_line({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "ready": True, "endpoint": endpoint,
    })
    stopped = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    stopped.wait()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    passed = state.passed()
    json_line({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "passed": passed,
    })
    shutil.rmtree(root, ignore_errors=True)
    return 0 if passed else 1


def container_main() -> int:
    """Run the emulator on an isolated bridge and proxy nonce-bound receipts."""
    network = required_env(NETWORK_ENV)
    image = required_image_id()
    challenge = required_env("TRSTCTL_DOD_CHALLENGE")
    entry_id = required_env("TRSTCTL_DOD_ENTRY_ID")
    identity = required_env("TRSTCTL_DOD_SUBSTRATE_IDENTITY")
    contract = required_env("TRSTCTL_DOD_CONTRACT_DIGEST")
    outer_pid = os.getpid()
    name = f"trstctl-dod-hsm-emulator-{os.getpid()}"
    command = [
        "docker", "run", "--rm", "--platform", "linux/amd64", "--name", name,
        "--network", network, "--network-alias", "managed-key-emulator",
        "-p", f"127.0.0.1::{INNER_PORT}",
    ]
    for env_name in (
        "TRSTCTL_DOD_CHALLENGE", "TRSTCTL_DOD_ENTRY_ID",
        "TRSTCTL_DOD_SUBSTRATE_IDENTITY", "TRSTCTL_DOD_CONTRACT_DIGEST",
    ):
        command.extend(("-e", f"{env_name}={required_env(env_name)}"))
    command.extend((
        "-e", f"{INNER_ENV}=1",
        "-e", f"{CONTAINER_ENDPOINT_ENV}=http://managed-key-emulator:{INNER_PORT}",
        "--entrypoint", "python3", image, "/usr/local/libexec/trstctl-managed-keys.py",
    ))
    child = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    stopped = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    assert child.stdout is not None
    assert child.stderr is not None
    ready_line = child.stdout.readline()
    try:
        inner_ready = json.loads(ready_line)
    except json.JSONDecodeError:
        inner_ready = {}
    if not inner_envelope_matches(
        inner_ready, challenge=challenge, entry_id=entry_id, identity=identity,
        contract=contract, flag="ready", outer_pid=outer_pid,
    ):
        child.kill()
        _, stderr = child.communicate(timeout=10)
        raise SystemExit(f"inner managed-key emulator failed READY: {stderr[:240]}")
    inner_pid = int(inner_ready["pid"])
    host_port = ""
    for _ in range(50):
        mapped = subprocess.run(
            ["docker", "port", name, f"{INNER_PORT}/tcp"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False,
        ).stdout.strip()
        if mapped:
            host_port = mapped.rsplit(":", 1)[-1]
            break
        time.sleep(0.1)
    if not host_port:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        raise SystemExit("inner managed-key emulator has no loopback port mapping")
    host_endpoint = os.environ.get(DOCKER_HOST_ENDPOINT_ENV, "127.0.0.1")
    if host_endpoint not in {"127.0.0.1", "host.docker.internal"}:
        raise SystemExit(f"{DOCKER_HOST_ENDPOINT_ENV} has an untrusted host name")
    json_line({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "ready": True, "endpoint": f"http://{host_endpoint}:{host_port}",
        "runtime_identity": image,
    })
    while not stopped.wait(0.1) and child.poll() is None:
        pass
    subprocess.run(
        ["docker", "stop", "-t", "5", name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    remaining_stdout, stderr = child.communicate(timeout=10)
    final_receipts = []
    for line in remaining_stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "passed" in value:
            final_receipts.append(value)
    passed = child.returncode == 0 and len(final_receipts) == 1 and inner_envelope_matches(
        final_receipts[0], challenge=challenge, entry_id=entry_id, identity=identity,
        contract=contract, flag="passed", outer_pid=outer_pid, expected_pid=inner_pid,
    )
    if not passed:
        print(stderr[:240], file=os.sys.stderr)
    json_line({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id,
        "identity": identity, "contract_digest": contract, "pid": os.getpid(),
        "passed": passed, "runtime_identity": image,
    })
    return 0 if passed else 1


def main() -> int:
    if os.environ.get(NETWORK_ENV) and os.environ.get(INNER_ENV) != "1":
        return container_main()
    return serve_main()


if __name__ == "__main__":
    raise SystemExit(main())
