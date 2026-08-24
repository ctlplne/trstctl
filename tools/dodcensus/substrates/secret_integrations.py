#!/usr/bin/env python3
"""Out-of-process dynamic-secret and secret-sync DoD substrate.

HTTP integrations are vendor-wire-faithful emulators, including HCP Terraform's
workspace Variables JSON:API and Vault/OpenBao KV v2 read/CAS/write semantics.
Database entries launch the official PostgreSQL/MySQL/MongoDB/Redis containers and
expose only a control/readback endpoint; trstctl talks to the actual database port,
never to a fixture adapter.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlparse


IMAGES = {
    "postgresql": "postgres:16.15-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685",
    "mysql": "mysql:8.4@sha256:d36d39a64cd12a5c1cc9e6aa2bfb5f8d4c81a2f6586e0a04a9ae13939db02209",
    # MongoDB 8.x refuses to start on Docker Desktop's Linux 6.19 kernel
    # (SERVER-121912). The still-supported 7.0 line exercises the same native
    # user/session lifecycle without weakening the database proof.
    "mongodb": "mongo:7.0.39-jammy@sha256:04582c3a144d088f841c446abfc19f79adcefa8bd00ad4a7fb18e27b9585c5d6",
    "redis": "redis:8.2-bookworm@sha256:14678cf7a021c8fef198403f2cf5f6d30492218156f41f03cdb79a4caafb8bd4",
}

# The pinned linux/amd64 runner may execute through architecture emulation on
# an arm64 developer host. Keep receiver compilation bounded, but give the Go
# linker enough time to finish from a cold cache. The parent broker applies a
# slightly larger independent READY deadline.
GITHUB_RECEIVER_BUILD_TIMEOUT_SECONDS = 40


class LoopbackHTTPServer(ThreadingHTTPServer):
    """Bind without HTTPServer's reverse-DNS lookup on loopback."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


class DatabaseBridgeHandler(socketserver.BaseRequestHandler):
    """Copy opaque database protocol bytes to the real pinned container."""

    def handle(self) -> None:
        server = self.server
        upstream_addresses = getattr(server, "upstream_addresses")
        state = getattr(server, "state")
        with state.lock:
            state.bridge_accepts += 1
        upstream_socket = None
        for route, upstream_address in upstream_addresses:
            try:
                upstream_socket = socket.create_connection(upstream_address, timeout=5)
                with state.lock:
                    state.bridge_upstream_route = route
                break
            except OSError as exc:
                with state.lock:
                    state.bridge_last_errno = int(exc.errno or -1)
        if upstream_socket is None:
            return
        with upstream_socket as upstream:
            with state.lock:
                state.bridge_upstream_connects += 1
            upstream.settimeout(None)

            def pump(source: socket.socket, destination: socket.socket) -> None:
                try:
                    while True:
                        chunk = source.recv(64 * 1024)
                        if not chunk:
                            break
                        destination.sendall(chunk)
                except (ConnectionError, OSError):
                    pass
                finally:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            request_to_upstream = threading.Thread(
                target=pump, args=(self.request, upstream), daemon=True,
            )
            request_to_upstream.start()
            pump(upstream, self.request)
            request_to_upstream.join(timeout=2)


class LoopbackDatabaseBridge(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, upstream_port: int, state) -> None:
        self.upstream_addresses = (
            ("loopback", ("127.0.0.1", upstream_port)),
            ("docker-host", ("host.docker.internal", upstream_port)),
        )
        self.state = state
        super().__init__(("127.0.0.1", 0), DatabaseBridgeHandler)


# This receiver is compiled into a temporary, independent process by the
# GitHub substrate. Its X25519/XSalsa20-Poly1305 sealed-box implementation is
# interoperable with libsodium and retains the private key only in that process.
# Keeping the source in this digest-pinned Python command means the DoD gate
# cryptographically binds both halves of the external receiver.
GITHUB_SEALED_BOX_RECEIVER = r'''package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"

	"golang.org/x/crypto/nacl/box"
)

type request struct {
	Ciphertext string `json:"ciphertext"`
}

type response struct {
	PublicKey string `json:"public_key,omitempty"`
	Plaintext string `json:"plaintext,omitempty"`
	Error     string `json:"error,omitempty"`
}

func main() {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	encoder := json.NewEncoder(os.Stdout)
	if err != nil {
		_ = encoder.Encode(response{Error: err.Error()})
		return
	}
	_ = encoder.Encode(response{PublicKey: base64.StdEncoding.EncodeToString(publicKey[:])})
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var request request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			_ = encoder.Encode(response{Error: "invalid request"})
			continue
		}
		ciphertext, err := base64.StdEncoding.DecodeString(request.Ciphertext)
		if err != nil {
			_ = encoder.Encode(response{Error: "invalid ciphertext"})
			continue
		}
		plaintext, ok := box.OpenAnonymous(nil, ciphertext, publicKey, privateKey)
		if !ok {
			_ = encoder.Encode(response{Error: "sealed-box authentication failed"})
			continue
		}
		_ = encoder.Encode(response{Plaintext: base64.StdEncoding.EncodeToString(plaintext)})
	}
}
'''


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"missing {name}")
    return value


def json_line(value: dict) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def run(args: list[str], timeout: float = 30, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=check, text=True)


class State:
    def __init__(self, entry_id: str):
        self.entry_id = entry_id
        self.kind = self._kind(entry_id)
        self.container = f"trstctl-dod-secret-{os.getpid()}-{secrets.token_hex(4)}"
        self.container_port = {"postgresql": 5432, "mysql": 3306, "mongodb": 27017, "redis": 6379}.get(self.kind, 0)
        self.host_port = 0
        self.database_bridge = None
        self.database_bridge_thread = None
        self.bridge_accepts = 0
        self.bridge_upstream_connects = 0
        self.bridge_last_errno = 0
        self.bridge_upstream_route = "none"
        self.start_error = ""
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.requests: list[tuple[str, str]] = []
        self.principals: dict[str, dict] = {}
        self.values: dict[str, bytes] = {}
        self.sync_operations: dict[str, tuple[str, bytes]] = {}
        self.sync_versions: dict[str, int] = {}
        self.containers: set[str] = set()
        self.issued = False
        self.used = False
        self.revoked = False
        self.synced = False
        self.readback = False
        self.reconciled = False
        self.native_wire = False
        self.sensitive = False
        self.category = ""
        self.cas_conflicts = 0
        self.cas_preserved = False
        self.protocol_errors = 0
        self.terraform_variables: dict[str, dict] = {}
        self.vault_records: dict[str, dict] = {}
        self.vault_race_injected: set[str] = set()
        self.counter = 0
        self.github_box_directory = None
        self.github_box_process = None
        self.github_public_key = b""
        self.github_key_id = ""
        if entry_id == "secret_sync.github_actions":
            self._start_github_sealed_box_receiver()
        if self.kind in IMAGES:
            threading.Thread(target=self._start_database, daemon=True).start()
        else:
            self.ready.set()

    @staticmethod
    def _kind(entry: str) -> str:
        if entry == "dynamic_secret.registry":
            return "postgresql"
        mapping = {
            "dynamic_secret.postgresql": "postgresql",
            "dynamic_secret.mysql": "mysql",
            "dynamic_secret.mongodb": "mongodb",
            "dynamic_secret.redis": "redis",
        }
        return mapping.get(entry, "http")

    def _start_database(self) -> None:
        try:
            # Keep an exited fixture until cleanup so timeout diagnostics can
            # inspect its exact state and bounded logs. cleanup() always removes
            # this nonce-scoped name, whether startup succeeds or fails.
            args = ["docker", "run", "-d", "--name", self.container, "-p", f"127.0.0.1::{self.container_port}"]
            if self.kind == "postgresql":
                args += ["-e", "POSTGRES_PASSWORD=dod-admin", "-e", "POSTGRES_DB=app", IMAGES[self.kind]]
            elif self.kind == "mysql":
                args += ["-e", "MYSQL_ROOT_PASSWORD=dod-admin", "-e", "MYSQL_DATABASE=app", IMAGES[self.kind]]
            elif self.kind == "mongodb":
                args += ["-e", "MONGO_INITDB_ROOT_USERNAME=root", "-e", "MONGO_INITDB_ROOT_PASSWORD=dod-admin", IMAGES[self.kind]]
            else:
                args += [IMAGES[self.kind], "redis-server", "--requirepass", "dod-admin"]
            run(args, timeout=180)
            deadline = time.time() + 120
            last_database_error = ""
            while time.time() < deadline and not self.stop.is_set():
                try:
                    mapped = run(["docker", "port", self.container, f"{self.container_port}/tcp"], timeout=5).stdout.strip().splitlines()[0]
                    self.host_port = int(mapped.rsplit(":", 1)[1])
                    if self._database_healthy():
                        self._start_database_bridge()
                        self.ready.set()
                        return
                except Exception as exc:
                    last_database_error = str(exc)
                time.sleep(0.25)
            diagnostics = self._database_failure_diagnostics(last_database_error)
            raise RuntimeError(f"database did not become healthy: {diagnostics}")
        except Exception as exc:
            self.start_error = str(exc)
            self.ready.set()

    def _database_failure_diagnostics(self, last_database_error: str) -> str:
        details = [f"kind={self.kind}"]
        if last_database_error:
            details.append(f"last_error={' '.join(last_database_error.split())[:2000]}")
        commands = (
            ("state", ["docker", "inspect", "--format", "{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{json .State.Error}}", self.container]),
            ("logs", ["docker", "logs", "--tail", "80", self.container]),
        )
        for label, args in commands:
            try:
                output = run(args, timeout=10, check=False).stdout
                # The fixtures use this password only for their private test
                # containers, but keep even that value out of retained evidence.
                output = " ".join(output.replace("dod-admin", "[redacted]").split())[:4000]
                details.append(f"{label}={output or '[empty]'}")
            except Exception as exc:
                details.append(f"{label}_error={' '.join(str(exc).split())[:1000]}")
        return "; ".join(details)

    def _start_database_bridge(self) -> None:
        upstream_port = self.host_port
        bridge = LoopbackDatabaseBridge(upstream_port, self)
        thread = threading.Thread(target=bridge.serve_forever, daemon=True)
        thread.start()
        self.database_bridge = bridge
        self.database_bridge_thread = thread
        self.host_port = int(bridge.server_address[1])

    def _database_healthy(self) -> bool:
        if self.kind == "postgresql":
            cmd = ["docker", "exec", self.container, "pg_isready", "-U", "postgres", "-d", "app"]
        elif self.kind == "mysql":
            cmd = ["docker", "exec", self.container, "mysqladmin", "-uroot", "-pdod-admin", "ping", "--silent"]
        elif self.kind == "mongodb":
            cmd = ["docker", "exec", self.container, "mongosh", "--quiet", "--username", "root", "--password", "dod-admin", "--authenticationDatabase", "admin", "--eval", "db.adminCommand({ping:1}).ok"]
        else:
            cmd = ["docker", "exec", self.container, "redis-cli", "-a", "dod-admin", "PING"]
        return run(cmd, timeout=5).returncode == 0

    def config(self) -> dict:
        if not self.ready.wait(130):
            raise RuntimeError("database readiness timeout")
        if self.start_error:
            raise RuntimeError(self.start_error)
        host = f"127.0.0.1:{self.host_port}"
        if self.kind == "postgresql":
            return {"kind": self.kind, "admin_dsn": f"postgres://postgres:dod-admin@{host}/app?sslmode=disable", "database": "app"}
        if self.kind == "mysql":
            return {"kind": self.kind, "admin_dsn": f"root:dod-admin@tcp({host})/app?parseTime=true", "addr": host, "database": "app"}
        if self.kind == "mongodb":
            return {"kind": self.kind, "admin_dsn": f"mongodb://root:dod-admin@{host}/app?authSource=admin", "database": "app"}
        if self.kind == "redis":
            return {"kind": self.kind, "addr": host, "password": "dod-admin"}
        return {"kind": "http"}

    def bridge_status(self) -> dict:
        with self.lock:
            return {
                "accepts": self.bridge_accepts,
                "upstream_connects": self.bridge_upstream_connects,
                "last_errno": self.bridge_last_errno,
                "upstream_route": self.bridge_upstream_route,
            }

    def database_readback(self, principal: str, phase: str) -> bool:
        principal = re.sub(r"[^a-zA-Z0-9_.-]", "", principal)
        if not principal or phase not in {"active", "absent"}:
            return False
        if self.kind == "postgresql":
            query = (f"SELECT count(*) FROM pg_stat_activity WHERE usename='{principal}'" if phase == "active"
                     else f"SELECT count(*) FROM pg_roles WHERE rolname='{principal}'")
            cmd = ["docker", "exec", self.container, "psql", "-U", "postgres", "-d", "app", "-Atc", query]
        elif self.kind == "mysql":
            table = "information_schema.processlist" if phase == "active" else "mysql.user"
            query = f"SELECT count(*) FROM {table} WHERE USER='{principal}'"
            cmd = ["docker", "exec", self.container, "mysql", "-uroot", "-pdod-admin", "-Nse", query]
        elif self.kind == "mongodb":
            if phase == "active":
                expression = f"db.getSiblingDB('admin').aggregate([{{$currentOp:{{allUsers:true,idleConnections:true}}}},{{$match:{{'effectiveUsers.user':'{principal}'}}}},{{$count:'n'}}]).toArray()[0]?.n || 0"
            else:
                expression = f"db.getSiblingDB('app').runCommand({{usersInfo:'{principal}'}}).users.length"
            # mongosh does not accept mysql-style joined short options (`-uroot`,
            # `-pdod-admin`). Use its documented argument form so a CLI usage
            # error can never be misread as a successful numeric readback.
            cmd = ["docker", "exec", self.container, "mongosh", "--quiet",
                   "--username", "root", "--password", "dod-admin",
                   "--authenticationDatabase", "admin", "--eval", expression]
        else:
            if phase == "active":
                cmd = ["docker", "exec", self.container, "sh", "-c", f"redis-cli -a dod-admin CLIENT LIST 2>/dev/null | grep -c 'user={principal}'"]
            else:
                cmd = ["docker", "exec", self.container, "sh", "-c", f"test \"$(redis-cli -a dod-admin --raw ACL GETUSER {principal} 2>/dev/null)\" = \"\""]
        try:
            result = run(cmd, timeout=10, check=False)
            if result.returncode != 0:
                ok = False
            elif self.kind == "redis" and phase == "absent":
                ok = result.returncode == 0
            else:
                # Read only the command's final numeric result. Parsing every
                # digit from an error/help page can turn a failed verifier into
                # a false positive (for example a version or example port).
                match = re.search(r"(?:^|\n)\s*(\d+)\s*$", result.stdout)
                if match is None:
                    ok = False
                else:
                    count = int(match.group(1))
                    ok = count > 0 if phase == "active" else count == 0
        except Exception:
            ok = False
        if ok and phase == "active":
            self.issued = True
            self.used = True
        if ok and phase == "absent":
            self.revoked = True
        return ok

    def passed(self) -> bool:
        if self.entry_id.startswith("dynamic_secret."):
            return self.issued and self.used and self.revoked
        if self.entry_id in {
            "secret_sync.aws_secrets_manager",
            "secret_sync.gcp_secret_manager",
            "secret_sync.azure_key_vault",
        }:
            return self.synced and self.readback and self.reconciled and sum(self.sync_versions.values()) == 1
        if self.entry_id == "secrets_residuals.terraform_opentofu_native_sync":
            return (self.synced and self.readback and self.reconciled and self.native_wire and
                    self.sensitive and self.category == "env" and self.protocol_errors == 0 and
                    sum(self.sync_versions.values()) == 1)
        if self.entry_id == "secrets_residuals.vault_kv_outbound_sync":
            return (self.synced and self.readback and self.reconciled and self.native_wire and
                    self.cas_conflicts == 1 and self.cas_preserved and self.protocol_errors == 0 and
                    sum(self.sync_versions.values()) == 1)
        return self.synced and self.readback

    def next_id(self, prefix: str) -> str:
        with self.lock:
            self.counter += 1
            return f"{prefix}{self.counter}"

    def _start_github_sealed_box_receiver(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="trstctl-dod-github-box-")
        source = os.path.join(directory.name, "main.go")
        binary = os.path.join(directory.name, "receiver")
        with open(source, "w", encoding="utf-8") as handle:
            handle.write(GITHUB_SEALED_BOX_RECEIVER)
        run(
            ["go", "build", "-trimpath", "-o", binary, source],
            timeout=GITHUB_RECEIVER_BUILD_TIMEOUT_SECONDS,
        )
        process = subprocess.Popen(
            [binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        if process.stdout is None:
            raise RuntimeError("GitHub sealed-box receiver stdout is unavailable")
        ready = json.loads(process.stdout.readline())
        public_key = base64.b64decode(ready.get("public_key", ""), validate=True)
        if len(public_key) != 32 or ready.get("error"):
            raise RuntimeError("GitHub sealed-box receiver did not generate an X25519 key")
        self.github_box_directory = directory
        self.github_box_process = process
        self.github_public_key = public_key
        self.github_key_id = "dod-" + hashlib.sha256(public_key).hexdigest()[:24]

    def open_github_sealed_box(self, ciphertext: bytes) -> bytes:
        process = self.github_box_process
        if process is None or process.stdin is None or process.stdout is None or process.poll() is not None:
            raise RuntimeError("GitHub sealed-box receiver is not running")
        request = json.dumps({"ciphertext": base64.b64encode(ciphertext).decode()}, separators=(",", ":"))
        process.stdin.write(request + "\n")
        process.stdin.flush()
        response = json.loads(process.stdout.readline())
        if response.get("error"):
            raise ValueError(response["error"])
        return base64.b64decode(response.get("plaintext", ""), validate=True)

    def cleanup(self) -> None:
        self.stop.set()
        if self.database_bridge is not None:
            self.database_bridge.shutdown()
            self.database_bridge.server_close()
        if self.database_bridge_thread is not None:
            self.database_bridge_thread.join(timeout=2)
        if self.github_box_process is not None:
            if self.github_box_process.stdin is not None:
                self.github_box_process.stdin.close()
            try:
                self.github_box_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.github_box_process.kill()
                self.github_box_process.wait(timeout=2)
        if self.github_box_directory is not None:
            self.github_box_directory.cleanup()
        if self.kind in IMAGES:
            run(["docker", "rm", "-f", self.container], timeout=20, check=False)


class Handler(BaseHTTPRequestHandler):
    server_version = "trstctl-dod-secret-integrations/1"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, *_args) -> None:
        return

    def body(self) -> bytes:
        length = min(int(self.headers.get("Content-Length", "0") or 0), 8 << 20)
        return self.rfile.read(length)

    def send_body(self, status: int, body: bytes = b"{}", content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/dod/config":
            try:
                self.send_body(200, json.dumps(self.state.config()).encode())
            except Exception as exc:
                self.send_body(503, json.dumps({"error": str(exc)}).encode())
            return
        if parsed.path == "/dod/bridge-status":
            self.send_body(200, json.dumps(self.state.bridge_status()).encode())
            return
        if parsed.path == "/dod/auth":
            self._auth(parsed)
            return
        if parsed.path == "/dod/readback":
            self._readback(parsed)
            return
        if parsed.path == "/dod/sync-state":
            self._sync_state(parsed)
            return
        if (self.state.entry_id == "secrets_residuals.terraform_opentofu_native_sync" and
                parsed.path == "/api/v2/workspaces/ws-dod-opentofu/vars"):
            self._terraform_sync_get(parsed)
            return
        if (self.state.entry_id == "secrets_residuals.vault_kv_outbound_sync" and
                parsed.path.startswith("/v1/team-secrets/data/apps/")):
            self._vault_sync_get(parsed.path)
            return
        if self.state.entry_id == "secret_sync.github_actions" and parsed.path.endswith("/actions/secrets/public-key"):
            if self.headers.get("Authorization") != "Bearer dod-github-token":
                self.send_body(401); return
            self.state.requests.append(("GET", parsed.path))
            self.send_body(200, json.dumps({
                "key_id": self.state.github_key_id,
                "key": base64.b64encode(self.state.github_public_key).decode(),
            }).encode())
            return
        if self.state.entry_id == "dynamic_secret.gcp_iam" and "/keys" in parsed.path:
            self._gcp_iam_get(parsed.path)
            return
        if self.state.entry_id == "dynamic_secret.azure_entra" and "/applications/" in parsed.path:
            if self.headers.get("Authorization") != "Bearer dod-azure-admin-token":
                self.send_body(401); return
            credentials = [
                {"keyId": key, "displayName": record.get("display_name", "")}
                for key, record in self.state.principals.items()
                if record.get("display_name")
            ]
            self.send_body(200, json.dumps({"passwordCredentials": credentials}).encode())
            return
        if self.state.entry_id == "secret_sync.kubernetes_secrets" and "/secrets/" in parsed.path:
            if self.headers.get("Authorization") != "Bearer dod-k8s-sync-token":
                self.send_body(401); return
            self.send_body(404)
            return
        if self.state.entry_id == "secret_sync.gcp_secret_manager" and parsed.path.endswith("/versions/latest:access"):
            if self.headers.get("Authorization") != "Bearer dod-gcp-sync-token" or not self.headers.get("Idempotency-Key"):
                self.send_body(401); return
            key = unquote(parsed.path.split("/secrets/", 1)[1].split("/versions/", 1)[0])
            if key not in self.state.values:
                self.send_body(404); return
            self.state.reconciled = True
            self.send_body(200, json.dumps({"payload": {"data": base64.b64encode(self.state.values[key]).decode()}}).encode())
            return
        if self.state.entry_id == "secret_sync.azure_key_vault" and "/secrets/" in parsed.path:
            if self.headers.get("Authorization") != "Bearer dod-azure-sync-token" or not self.headers.get("Idempotency-Key"):
                self.send_body(401); return
            key = unquote(parsed.path.split("/secrets/", 1)[1])
            if key not in self.state.values:
                self.send_body(404); return
            self.state.reconciled = True
            self.send_body(200, json.dumps({"value": base64.b64encode(self.state.values[key]).decode()}).encode())
            return
        self.send_body(404)

    def do_POST(self) -> None:
        self._mutate("POST")

    def do_PUT(self) -> None:
        self._mutate("PUT")

    def do_PATCH(self) -> None:
        self._mutate("PATCH")

    def do_DELETE(self) -> None:
        self._mutate("DELETE")

    def _auth(self, parsed) -> None:
        query = parse_qs(parsed.query)
        supplied = query.get("secret", [""])[0]
        key = query.get("id", [""])[0]
        authorization = self.headers.get("Authorization", "")
        valid = False
        with self.state.lock:
            aws_access_key = self._sigv4_access_key()
            if self.state.entry_id == "dynamic_secret.aws_iam":
                record = self.state.principals.get(aws_access_key)
                valid = bool(aws_access_key and record and self._verify_sigv4(
                    parsed, b"", aws_access_key, record.get("secret", ""), "us-east-1", "sts",
                ))
            elif key in self.state.principals:
                record = self.state.principals[key]
                if record.get("certificate") and query.get("signature", [""])[0]:
                    valid = self._verify_gcp_signature(record["certificate"], query["signature"][0])
                else:
                    valid = supplied == record.get("secret") or authorization == "Bearer " + record.get("secret", "")
            elif not key:
                # Azure returns the secret value to the workload but keeps the
                # password-object id as the revocation handle. Kubernetes does
                # the same split between its ServiceAccount name and token. A
                # workload therefore authenticates with only the generated
                # authority-bearing value; it must not need the control-plane
                # revocation handle to prove that value works.
                valid = any(
                    supplied == record.get("secret")
                    or authorization == "Bearer " + record.get("secret", "")
                    for record in self.state.principals.values()
                    if record.get("secret")
                )
            if valid:
                self.state.used = True
        self.send_body(200 if valid else 401, b'{"authenticated":true}' if valid else b'{"authenticated":false}')

    def _sigv4_access_key(self) -> str:
        match = re.match(
            r"^AWS4-HMAC-SHA256 Credential=([^/]+)/", self.headers.get("Authorization", ""),
        )
        return match.group(1) if match else ""

    def _verify_sigv4(self, parsed, body: bytes, access_key: str, secret_key: str,
                      region: str, service: str, required_signed: tuple[str, ...] = ()) -> bool:
        authorization = self.headers.get("Authorization", "")
        match = re.fullmatch(
            r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request, "
            r"SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})",
            authorization,
        )
        if not match:
            return False
        actual_access, date_stamp, actual_region, actual_service, signed_raw, supplied = match.groups()
        amz_date = self.headers.get("X-Amz-Date", "")
        signed_headers = signed_raw.split(";")
        if (actual_access != access_key or actual_region != region or actual_service != service
                or not re.fullmatch(r"\d{8}T\d{6}Z", amz_date)
                or not amz_date.startswith(date_stamp)
                or signed_headers != sorted(set(signed_headers))
                or "host" not in signed_headers or "x-amz-date" not in signed_headers
                or not set(required_signed).issubset(signed_headers)):
            return False
        canonical_headers = []
        for name in signed_headers:
            value = self.headers.get("Host" if name == "host" else name)
            if value is None:
                return False
            canonical_headers.append(name + ":" + re.sub(r"\s+", " ", value.strip()) + "\n")
        query_pairs = [
            (quote(key, safe="-_.~"), quote(value, safe="-_.~"))
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        canonical_query = "&".join(key + "=" + value for key, value in sorted(query_pairs))
        canonical_path = quote(unquote(parsed.path or "/"), safe="/-_.~")
        canonical_request = "\n".join([
            self.command, canonical_path, canonical_query, "".join(canonical_headers),
            signed_raw, hashlib.sha256(body).hexdigest(),
        ])
        scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ])
        key = ("AWS4" + secret_key).encode()
        for component in (date_stamp, region, service, "aws4_request"):
            key = hmac.new(key, component.encode(), hashlib.sha256).digest()
        expected = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, supplied)

    @staticmethod
    def _verify_gcp_signature(certificate: bytes, encoded_signature: str) -> bool:
        try:
            signature = base64.b64decode(encoded_signature, validate=True)
            with tempfile.TemporaryDirectory(prefix="trstctl-dod-gcp-auth-") as directory:
                cert_path = os.path.join(directory, "cert.pem")
                pub_path = os.path.join(directory, "public.pem")
                sig_path = os.path.join(directory, "signature.bin")
                with open(cert_path, "wb") as handle:
                    handle.write(certificate)
                with open(sig_path, "wb") as handle:
                    handle.write(signature)
                public = run(["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"], timeout=10).stdout.encode()
                with open(pub_path, "wb") as handle:
                    handle.write(public)
                result = subprocess.run(
                    ["openssl", "dgst", "-sha256", "-verify", pub_path, "-signature", sig_path],
                    input=b"trstctl-dod-gcp-auth", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
                )
                return result.returncode == 0
        except Exception:
            return False

    def _readback(self, parsed) -> None:
        query = parse_qs(parsed.query)
        if self.state.kind in IMAGES:
            ok = self.state.database_readback(query.get("principal", [""])[0], query.get("phase", [""])[0])
            self.send_body(200 if ok else 404, json.dumps({"verified": ok}).encode())
            return
        key = query.get("key", [""])[0]
        with self.state.lock:
            value = self.state.values.get(key)
            if value is not None:
                self.state.readback = True
        self.send_body(200 if value is not None else 404, value or b"missing", "application/octet-stream")

    def _sync_state(self, parsed) -> None:
        key = parse_qs(parsed.query).get("key", [""])[0]
        with self.state.lock:
            versions = self.state.sync_versions.get(key, 0)
            reconciled = self.state.reconciled
            native_wire = self.state.native_wire
            sensitive = self.state.sensitive
            category = self.state.category
            cas_conflicts = self.state.cas_conflicts
            cas_preserved = self.state.cas_preserved
        self.send_body(200, json.dumps({
            "versions": versions,
            "reconciled": reconciled,
            "native_wire": native_wire,
            "sensitive": sensitive,
            "category": category,
            "cas_conflicts": cas_conflicts,
            "cas_preserved": cas_preserved,
        }).encode())

    def _terraform_sync_get(self, parsed) -> None:
        operation = self.headers.get("Idempotency-Key", "")
        query = parse_qs(parsed.query)
        valid = (
            self.headers.get("Authorization") == "Bearer dod-terraform-token" and
            self.headers.get("Accept") == "application/vnd.api+json" and
            self.headers.get("Content-Type") == "application/vnd.api+json" and
            bool(operation) and query.get("page[number]") == ["1"] and
            query.get("page[size]") == ["100"]
        )
        if not valid:
            with self.state.lock:
                self.state.protocol_errors += 1
            self.send_body(401)
            return
        with self.state.lock:
            self.state.requests.append(("GET", parsed.path))
            data = []
            for variable in self.state.terraform_variables.values():
                expected = "DOD managed variable; operation-sha256=" + hashlib.sha256(operation.encode()).hexdigest()
                if variable["operation"] == operation and variable["description"] == expected:
                    self.state.reconciled = True
                data.append({
                    "id": variable["id"],
                    "type": "vars",
                    "attributes": {
                        "key": variable["key"],
                        "description": variable["description"],
                        "category": variable["category"],
                        "hcl": variable["hcl"],
                        "sensitive": variable["sensitive"],
                    },
                })
        self.send_body(200, json.dumps({
            "data": data,
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }).encode(), "application/vnd.api+json")

    def _vault_sync_get(self, path: str) -> None:
        operation = self.headers.get("Idempotency-Key", "")
        if (self.headers.get("X-Vault-Token") != "dod-vault-token" or
                self.headers.get("X-Vault-Namespace") != "platform/team-a" or not operation):
            with self.state.lock:
                self.state.protocol_errors += 1
            self.send_body(403)
            return
        key = unquote(path.removeprefix("/v1/team-secrets/data/apps/"))
        if not key:
            with self.state.lock:
                self.state.protocol_errors += 1
            self.send_body(404)
            return
        with self.state.lock:
            self.state.requests.append(("GET", path))
            record = self.state.vault_records.setdefault(key, {
                "version": 1,
                "data": {"owner": b"platform", "value": b"preexisting-value"},
            })
            if key in self.state.values and record["data"].get("value") == self.state.values[key]:
                self.state.reconciled = True
            encoded = {name: value.decode("utf-8") for name, value in record["data"].items()}
            version = record["version"]
        self.send_body(200, json.dumps({
            "data": {"data": encoded, "metadata": {"version": version}},
        }).encode())

    def _mutate(self, method: str) -> None:
        body = self.body()
        parsed = urlparse(self.path)
        entry = self.state.entry_id
        self.state.requests.append((method, parsed.path))
        if entry in {"dynamic_secret.aws_iam"}:
            self._aws_iam(parsed, body)
        elif entry == "dynamic_secret.gcp_iam":
            self._gcp_iam(method, parsed.path, body)
        elif entry == "dynamic_secret.azure_entra":
            self._azure_entra(parsed.path, body)
        elif entry == "dynamic_secret.kubernetes":
            self._kubernetes(method, parsed.path, body)
        elif entry in {"secret_sync.registry", "secret_sync.generic_ci_json"}:
            self._generic_sync(body)
        elif entry == "secret_sync.aws_secrets_manager":
            self._aws_sync(parsed, body)
        elif entry == "secret_sync.gcp_secret_manager":
            self._gcp_sync(parsed, body)
        elif entry == "secret_sync.azure_key_vault":
            self._azure_sync(parsed.path, body)
        elif entry == "secret_sync.github_actions":
            self._github_sync(parsed.path, body)
        elif entry == "secret_sync.gitlab_ci":
            self._gitlab_sync(method, parsed.path, body)
        elif entry == "secret_sync.vercel":
            self._vercel_sync(parsed.path, body)
        elif entry == "secret_sync.kubernetes_secrets":
            self._kubernetes_sync(method, parsed.path, body)
        elif entry == "secrets_residuals.terraform_opentofu_native_sync":
            self._terraform_sync(method, parsed, body)
        elif entry == "secrets_residuals.vault_kv_outbound_sync":
            self._vault_sync(method, parsed.path, body)
        else:
            self.send_body(404)

    def _aws_iam(self, parsed, body: bytes) -> None:
        if not self._verify_sigv4(
                parsed, body, "AKIADODADMIN", "dod-aws-admin-secret", "us-east-1", "iam",
                ("content-type",)) or self.headers.get("Content-Type") != "application/x-www-form-urlencoded; charset=utf-8":
            self.send_body(401); return
        form = parse_qs(body.decode())
        action = form.get("Action", [""])[0]
        user = form.get("UserName", [""])[0]
        if action == "CreateUser":
            self.state.principals.setdefault(user, {})
            self.send_body(200, b"<CreateUserResponse/>", "application/xml")
        elif action in {"AttachUserPolicy", "DetachUserPolicy"}:
            self.send_body(200, b"<ok/>", "application/xml")
        elif action == "CreateAccessKey":
            suffix = self.state.next_id("")
            key, secret_value = "AKIADODDYNAMIC" + suffix, "dod-aws-dynamic-secret-" + suffix
            self.state.principals[key] = {"secret": secret_value, "user": user}
            self.state.issued = True
            xml = f"<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>{key}</AccessKeyId><SecretAccessKey>{secret_value}</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>".encode()
            self.send_body(200, xml, "application/xml")
        elif action == "DeleteAccessKey":
            self.state.principals.pop(form.get("AccessKeyId", [""])[0], None); self.send_body(200, b"<ok/>", "application/xml")
        elif action == "DeleteUser":
            self.state.principals.pop(user, None)
            self.state.revoked = not any(v.get("user") == user for v in self.state.principals.values()); self.send_body(200, b"<ok/>", "application/xml")
        elif action == "ListAccessKeys":
            if user not in self.state.principals and not any(v.get("user") == user for v in self.state.principals.values()):
                self.send_body(404, b"<Error><Code>NoSuchEntity</Code></Error>", "application/xml"); return
            members = "".join(
                f"<member><AccessKeyId>{key}</AccessKeyId></member>"
                for key, value in self.state.principals.items() if value.get("user") == user
            )
            self.send_body(200, f"<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>{members}</AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>".encode(), "application/xml")
        else:
            self.send_body(400, b"<Error>unsupported action</Error>", "application/xml")

    def _gcp_iam(self, method: str, path: str, body: bytes) -> None:
        if self.headers.get("Authorization") != "Bearer dod-gcp-admin-token":
            self.send_body(401); return
        if method == "POST" and path.endswith("keys:upload"):
            certificate = base64.b64decode(json.loads(body)["publicKeyData"])
            key = hashlib.sha1(certificate).hexdigest()
            name = f"projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys/{key}"
            self.state.principals[key] = {"certificate": certificate, "name": name}
            self.state.issued = True
            self.send_body(200, json.dumps({"name": name, "keyOrigin": "USER_PROVIDED", "keyType": "USER_MANAGED"}).encode())
        elif method == "POST":
            key = self.state.next_id("gcp-key-")
            secret_value = "dod-gcp-dynamic-secret-" + key
            self.state.principals[key] = {"secret": secret_value}
            self.state.issued = True
            credential = json.dumps({"type": "service_account", "private_key_id": key, "private_key": secret_value, "client_email": "dyn@p.iam.gserviceaccount.com"}).encode()
            response = {"name": "projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys/" + key, "privateKeyData": base64.b64encode(credential).decode()}
            self.send_body(200, json.dumps(response).encode())
        else:
            key = unquote(path.rsplit("/", 1)[-1]); self.state.principals.pop(key, None); self.state.revoked = True; self.send_body(200)

    def _gcp_iam_get(self, path: str) -> None:
        if self.headers.get("Authorization") != "Bearer dod-gcp-admin-token":
            self.send_body(401); return
        if path.endswith("/keys"):
            keys = [{"name": value["name"]} for value in self.state.principals.values() if value.get("certificate")]
            self.send_body(200, json.dumps({"keys": keys}).encode()); return
        key = unquote(path.rsplit("/", 1)[-1])
        record = self.state.principals.get(key)
        if not record or not record.get("certificate"):
            self.send_body(404); return
        self.send_body(200, json.dumps({"publicKeyData": base64.b64encode(record["certificate"]).decode()}).encode())

    def _azure_entra(self, path: str, body: bytes) -> None:
        if self.headers.get("Authorization") != "Bearer dod-azure-admin-token":
            self.send_body(401); return
        if path.endswith("/addPassword"):
            payload = json.loads(body)
            key = self.state.next_id("azure-key-")
            secret_value = "dod-azure-dynamic-secret-" + key
            display_name = payload.get("passwordCredential", {}).get("displayName", "")
            self.state.principals[key] = {"secret": secret_value, "display_name": display_name}; self.state.issued = True
            self.send_body(200, json.dumps({"keyId": key, "secretText": secret_value, "displayName": display_name}).encode())
        else:
            key = json.loads(body).get("keyId", ""); self.state.principals.pop(key, None); self.state.revoked = True; self.send_body(200)

    def _kubernetes(self, method: str, path: str, body: bytes) -> None:
        if self.headers.get("Authorization") != "Bearer dod-k8s-admin-token":
            self.send_body(401); return
        if method == "POST" and path.endswith("/serviceaccounts"):
            name = json.loads(body)["metadata"]["name"]; self.state.principals[name] = {}; self.send_body(201, json.dumps({"metadata": {"name": name}}).encode())
        elif method == "POST" and path.endswith("/rolebindings"):
            self.send_body(201)
        elif method == "POST" and path.endswith("/token"):
            name = path.split("/")[-2]; token = "dod-k8s-token-" + name; self.state.principals[token] = {"secret": token, "user": name}; self.state.issued = True
            self.send_body(201, json.dumps({"status": {"token": token}}).encode())
        elif method == "DELETE":
            name = path.rsplit("/", 1)[-1]
            if "/serviceaccounts/" in path:
                self.state.principals.pop(name, None)
                for key in [k for k, v in self.state.principals.items() if v.get("user") == name]: self.state.principals.pop(key, None)
                self.state.revoked = True
            self.send_body(200)
        else:
            self.send_body(404)

    def _generic_sync(self, body: bytes) -> None:
        expected = {
            "secret_sync.registry": "Bearer dod-registry-token",
            "secret_sync.generic_ci_json": "Bearer dod-generic-token",
        }[self.state.entry_id]
        if self.headers.get("Authorization") != expected:
            self.send_body(401); return
        payload = json.loads(body); self.state.values[payload["key"]] = base64.b64decode(payload["encoded_value"]); self.state.synced = True; self.send_body(200)

    def _terraform_sync(self, method: str, parsed, body: bytes) -> None:
        operation = self.headers.get("Idempotency-Key", "")
        collection = "/api/v2/workspaces/ws-dod-opentofu/vars"
        valid_headers = (
            self.headers.get("Authorization") == "Bearer dod-terraform-token" and
            self.headers.get("Accept") == "application/vnd.api+json" and
            self.headers.get("Content-Type") == "application/vnd.api+json" and
            bool(operation)
        )
        try:
            payload = json.loads(body)
            data = payload["data"]
            attributes = data["attributes"]
            key = attributes["key"]
            value = attributes["value"]
            description = attributes["description"]
            expected_description = (
                "DOD managed variable; operation-sha256=" +
                hashlib.sha256(operation.encode()).hexdigest()
            )
            native_shape = (
                set(payload) == {"data"} and data.get("type") == "vars" and
                isinstance(key, str) and bool(key) and isinstance(value, str) and
                attributes.get("category") == "env" and attributes.get("hcl") is False and
                attributes.get("sensitive") is True and description == expected_description and
                operation not in description and "provider" not in attributes and
                "encoded_value" not in attributes
            )
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            native_shape = False
            key = value = description = ""
            data = {}
        valid_path = (
            (method == "POST" and parsed.path == collection and not data.get("id")) or
            (method == "PATCH" and parsed.path.startswith(collection + "/") and
             data.get("id") == unquote(parsed.path.removeprefix(collection + "/")))
        )
        if not valid_headers or not native_shape or not valid_path:
            with self.state.lock:
                self.state.protocol_errors += 1
            self.send_body(400)
            return
        with self.state.lock:
            existing = self.state.terraform_variables.get(key)
            if method == "POST" and existing is not None:
                self.send_body(422)
                return
            if method == "PATCH" and (existing is None or existing["id"] != data["id"]):
                self.send_body(404)
                return
            variable_id = data.get("id") or "var-dod-1"
            self.state.terraform_variables[key] = {
                "id": variable_id,
                "key": key,
                "description": description,
                "category": "env",
                "hcl": False,
                "sensitive": True,
                "operation": operation,
            }
            self.state.values[key] = value.encode()
            self.state.sync_operations[operation] = (key, value.encode())
            self.state.sync_versions[key] = self.state.sync_versions.get(key, 0) + 1
            self.state.native_wire = True
            self.state.sensitive = True
            self.state.category = "env"
            self.state.synced = True
        response = {
            "data": {
                "id": variable_id,
                "type": "vars",
                "attributes": {
                    "key": key,
                    "description": description,
                    "category": "env",
                    "hcl": False,
                    "sensitive": True,
                },
            },
        }
        self.send_body(201 if method == "POST" else 200,
                       json.dumps(response).encode(), "application/vnd.api+json")

    def _vault_sync(self, method: str, path: str, body: bytes) -> None:
        operation = self.headers.get("Idempotency-Key", "")
        prefix = "/v1/team-secrets/data/apps/"
        valid_headers = (
            method == "POST" and path.startswith(prefix) and
            self.headers.get("X-Vault-Token") == "dod-vault-token" and
            self.headers.get("X-Vault-Namespace") == "platform/team-a" and
            self.headers.get("Content-Type") == "application/json" and bool(operation)
        )
        try:
            payload = json.loads(body)
            options = payload["options"]
            data = payload["data"]
            cas = options["cas"]
            key = unquote(path.removeprefix(prefix))
            native_shape = (
                set(payload) == {"options", "data"} and set(options) == {"cas"} and
                isinstance(cas, int) and cas >= 0 and isinstance(data, dict) and bool(key) and
                isinstance(data.get("value"), str) and
                all(isinstance(name, str) and isinstance(value, str) for name, value in data.items()) and
                "provider" not in data and "encoded_value" not in data
            )
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            native_shape = False
            cas = -1
            key = ""
            data = {}
        if not valid_headers or not native_shape:
            with self.state.lock:
                self.state.protocol_errors += 1
            self.send_body(400)
            return
        with self.state.lock:
            record = self.state.vault_records.get(key)
            if record is None or cas != record["version"]:
                self.state.protocol_errors += 1
                self.send_body(400, b'{"errors":["check-and-set parameter did not match current version"]}')
                return
            if key not in self.state.vault_race_injected:
                # Race the first CAS after its read. A correct pusher must re-read
                # version 2, preserve the independently changed sibling field,
                # and retry with cas=2.
                record["version"] += 1
                record["data"] = {"owner": b"concurrent-writer", "value": b"concurrent-value"}
                self.state.vault_race_injected.add(key)
                self.state.cas_conflicts += 1
                self.send_body(400, b'{"errors":["check-and-set parameter did not match current version"]}')
                return
            preserved = data.get("owner") == "concurrent-writer"
            if not preserved:
                self.state.protocol_errors += 1
                self.send_body(409)
                return
            record["version"] += 1
            record["data"] = {name: value.encode() for name, value in data.items()}
            self.state.values[key] = record["data"]["value"]
            self.state.sync_operations[operation] = (key, self.state.values[key])
            self.state.sync_versions[key] = self.state.sync_versions.get(key, 0) + 1
            self.state.cas_preserved = True
            self.state.native_wire = True
            self.state.synced = True
            version = record["version"]
        self.send_body(200, json.dumps({"data": {"version": version}}).encode())

    def _aws_sync(self, parsed, body: bytes) -> None:
        if not self._verify_sigv4(
                parsed, body, "AKIADODSYNC", "dod-aws-sync-secret", "us-east-1", "secretsmanager",
                ("content-type", "x-amz-target")) or self.headers.get("Content-Type") != "application/x-amz-json-1.1":
            self.send_body(401); return
        target = self.headers.get("X-Amz-Target", ""); payload = json.loads(body); key = payload.get("Name", "")
        operation = payload.get("ClientRequestToken", "")
        value = base64.b64decode(payload.get("SecretBinary", ""))
        if not operation or self.headers.get("Idempotency-Key") != operation:
            self.send_body(400); return
        prior = self.state.sync_operations.get(operation)
        if prior is not None:
            if prior != (key, value): self.send_body(409); return
            self.state.reconciled = True
            self.send_body(200); return
        if target.endswith("PutSecretValue") and key not in self.state.values:
            self.send_body(400, b'{"__type":"ResourceNotFoundException"}'); return
        self.state.values[key] = value
        self.state.sync_operations[operation] = (key, value)
        self.state.sync_versions[key] = self.state.sync_versions.get(key, 0) + 1
        self.state.synced = True; self.send_body(200)

    def _gcp_sync(self, parsed, body: bytes) -> None:
        if self.headers.get("Authorization") != "Bearer dod-gcp-sync-token" or not self.headers.get("Idempotency-Key"): self.send_body(401); return
        path = parsed.path
        if path.endswith(":addVersion"):
            key = unquote(path.split("/secrets/", 1)[1].split(":", 1)[0])
            if key not in self.state.containers: self.send_body(404); return
            self.state.values[key] = base64.b64decode(json.loads(body)["payload"]["data"])
            self.state.sync_versions[key] = self.state.sync_versions.get(key, 0) + 1
            self.state.synced = True; self.send_body(200)
        else:
            self.state.containers.add(parse_qs(parsed.query).get("secretId", [""])[0]); self.send_body(200)

    def _azure_sync(self, path: str, body: bytes) -> None:
        if self.headers.get("Authorization") != "Bearer dod-azure-sync-token" or not self.headers.get("Idempotency-Key"): self.send_body(401); return
        key = unquote(path.split("/secrets/", 1)[1])
        self.state.values[key] = base64.b64decode(json.loads(body)["value"])
        self.state.sync_versions[key] = self.state.sync_versions.get(key, 0) + 1
        self.state.synced = True; self.send_body(200)

    def _github_sync(self, path: str, body: bytes) -> None:
        if self.headers.get("Authorization") != "Bearer dod-github-token": self.send_body(401); return
        key = unquote(path.rsplit("/", 1)[-1]); payload = json.loads(body)
        if payload.get("key_id") != self.state.github_key_id: self.send_body(400); return
        try:
            ciphertext = base64.b64decode(payload["encrypted_value"], validate=True)
            plaintext = self.state.open_github_sealed_box(ciphertext)
        except (KeyError, TypeError, ValueError, RuntimeError):
            self.send_body(400); return
        self.state.values[key] = plaintext; self.state.synced = True; self.send_body(204, b"")

    def _gitlab_sync(self, method: str, path: str, body: bytes) -> None:
        if self.headers.get("PRIVATE-TOKEN") != "dod-gitlab-token": self.send_body(401); return
        payload = json.loads(body); key = payload["key"]
        if method == "PUT" and key not in self.state.values: self.send_body(404); return
        self.state.values[key] = payload["value"].encode(); self.state.synced = True; self.send_body(201)

    def _vercel_sync(self, path: str, body: bytes) -> None:
        if self.headers.get("Authorization") != "Bearer dod-vercel-token": self.send_body(401); return
        payload = json.loads(body); self.state.values[payload["key"]] = payload["value"].encode(); self.state.synced = True; self.send_body(200)

    def _kubernetes_sync(self, method: str, path: str, body: bytes) -> None:
        if self.headers.get("Authorization") != "Bearer dod-k8s-sync-token": self.send_body(401); return
        if method == "POST":
            payload = json.loads(body); key = payload["metadata"]["name"]; self.state.values[key] = base64.b64decode(payload["data"]["value"]); self.state.synced = True; self.send_body(201)
        else:
            self.send_body(404)


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
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    json_line({"schema_version": 1, "challenge": challenge, "entry_id": entry_id, "identity": identity,
               "contract_digest": contract, "pid": os.getpid(), "ready": True, "endpoint": endpoint})
    while not stopped.wait(0.1): pass
    server.shutdown(); server.server_close(); thread.join(timeout=2)
    passed = state.passed()
    state.cleanup()
    json_line({"schema_version": 1, "challenge": challenge, "entry_id": entry_id, "identity": identity,
               "contract_digest": contract, "pid": os.getpid(), "passed": passed})
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_subparsers(dest="command", required=True).add_parser("serve")
    parser.parse_args(); return serve()


if __name__ == "__main__":
    raise SystemExit(main())
