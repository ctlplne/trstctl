#!/usr/bin/env python3
"""Pinned real-kind substrate for Kubernetes posture route DoD evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


KIND_VERSION = "v0.31.0"
NODE_IMAGE = "kindest/node:v1.31.14@sha256:6f86cf509dbb42767b6e79debc3f2c32e4ee01386f0489b3b2be24b0a55aac2b"
NAMESPACE = "trstctl-dod"
TARGET_NAMESPACE = "apps"
CSR_NAME = "dod-kind-csr"
BUNDLE_NAME = "dod-kind-roots"
ISSUER_NAME = "dod-kind-issuer"
MAX_BODY = 4 << 20


class LoopbackHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def run(args: list[str], timeout: float = 180, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")},
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({' '.join(args[:4])}): {result.stdout[-2000:]}")
    return result


def require_kind() -> str:
    binary = shutil.which("kind")
    if not binary:
        raise RuntimeError("kind v0.31.0 is required on PATH for the real-cluster DoD substrate")
    version = run([binary, "version"], timeout=10).stdout.strip()
    if not re.search(r"\bv?0\.31\.0\b", version):
        raise RuntimeError(f"kind binary version is not pinned {KIND_VERSION}: {version}")
    if platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"}:
        digest = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
        expected = "eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa"
        if digest != expected:
            raise RuntimeError(f"kind linux/amd64 binary digest {digest} is not the official {KIND_VERSION} digest")
    return binary


def kubeconfig_value(raw: str, key: str) -> str:
    match = re.search(rf"(?m)^\s*{re.escape(key)}:\s*([^\s]+)\s*$", raw)
    if not match:
        raise RuntimeError(f"kind kubeconfig omitted {key}")
    return match.group(1)


class KubernetesAPI:
    def __init__(self, server: str, ca_pem: bytes, client_cert: bytes, client_key: bytes, root: Path) -> None:
        self.server = server.rstrip("/")
        ca_file = root / "admin-ca.pem"
        cert_file = root / "admin-client.pem"
        key_file = root / "admin-client-key.pem"
        ca_file.write_bytes(ca_pem)
        cert_file.write_bytes(client_cert)
        key_file.write_bytes(client_key)
        for path in (ca_file, cert_file, key_file):
            path.chmod(0o600)
        context = ssl.create_default_context(cafile=str(ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cert_file), str(key_file))
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))

    def request(self, method: str, path: str, value: object | None = None) -> tuple[int, bytes]:
        body = None if value is None else compact(value)
        request = urllib.request.Request(self.server + path, data=body, method=method)
        request.add_header("Accept", "application/json")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(request, timeout=30) as response:
                return response.status, response.read(MAX_BODY + 1)
        except urllib.error.HTTPError as error:
            return error.code, error.read(MAX_BODY + 1)

    def json(self, method: str, path: str, value: object | None = None, accepted: tuple[int, ...] = (200, 201)) -> dict:
        status, raw = self.request(method, path, value)
        if status not in accepted:
            raise RuntimeError(f"Kubernetes {method} {path} status={status}: {raw[:1200]!r}")
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise RuntimeError(f"Kubernetes {method} {path} returned a non-object")
        return decoded

    def create(self, path: str, value: dict) -> dict:
        return self.json("POST", path, value, (200, 201, 409))


def crd(group: str, plural: str, singular: str, kind: str, scope: str, version: str) -> dict:
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": f"{plural}.{group}"},
        "spec": {
            "group": group,
            "scope": scope,
            "names": {"plural": plural, "singular": singular, "kind": kind},
            "versions": [{
                "name": version,
                "served": True,
                "storage": True,
                "schema": {"openAPIV3Schema": {"type": "object", "x-kubernetes-preserve-unknown-fields": True}},
                "subresources": {"status": {}},
            }],
        },
    }


def wait_crd(api: KubernetesAPI, name: str) -> None:
    deadline = time.time() + 60
    path = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + name
    while time.time() < deadline:
        status, raw = api.request("GET", path)
        if status == 200:
            value = json.loads(raw)
            conditions = value.get("status", {}).get("conditions", [])
            if any(item.get("type") == "Established" and item.get("status") == "True" for item in conditions):
                return
        time.sleep(0.25)
    raise RuntimeError(f"CRD {name} did not become Established")


def create_namespace(api: KubernetesAPI, name: str) -> None:
    api.create("/api/v1/namespaces", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}})


def prepare_fixtures(api: KubernetesAPI, root: Path) -> tuple[str, str, str]:
    for definition in (
        crd("trstctl.com", "clusterissuers", "clusterissuer", "ClusterIssuer", "Cluster", "v1alpha1"),
        crd("trstctl.com", "issuers", "issuer", "Issuer", "Namespaced", "v1alpha1"),
        crd("trstctl.com", "certificates", "certificate", "Certificate", "Namespaced", "v1alpha1"),
        crd("trstctl.com", "trustbundles", "trustbundle", "TrustBundle", "Cluster", "v1alpha1"),
        crd("cert-manager.io", "certificaterequests", "certificaterequest", "CertificateRequest", "Namespaced", "v1"),
    ):
        name = definition["metadata"]["name"]
        api.create("/apis/apiextensions.k8s.io/v1/customresourcedefinitions", definition)
        wait_crd(api, name)

    create_namespace(api, NAMESPACE)
    create_namespace(api, TARGET_NAMESPACE)
    api.create(f"/api/v1/namespaces/{NAMESPACE}/serviceaccounts", {
        "apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "trstctl-dod-controller", "namespace": NAMESPACE},
    })
    role_name = "trstctl-dod-controller"
    api.create("/apis/rbac.authorization.k8s.io/v1/clusterroles", {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": role_name},
        "rules": [
            {"apiGroups": ["trstctl.com"], "resources": ["issuers", "clusterissuers", "certificates", "trustbundles"], "verbs": ["get", "list", "watch"]},
            {"apiGroups": ["trstctl.com"], "resources": ["issuers/status", "clusterissuers/status", "certificates/status", "trustbundles/status"], "verbs": ["get", "update", "patch"]},
            {"apiGroups": ["cert-manager.io"], "resources": ["certificaterequests"], "verbs": ["get", "list", "watch"]},
            {"apiGroups": ["cert-manager.io"], "resources": ["certificaterequests/status"], "verbs": ["get", "update", "patch"]},
            {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"], "verbs": ["get", "list", "watch"]},
            {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/status"], "verbs": ["get", "update", "patch"]},
            {"apiGroups": [""], "resources": ["secrets", "configmaps"], "verbs": ["get", "list", "watch", "create", "update", "patch"]},
        ],
    })
    api.create("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": role_name},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role_name},
        "subjects": [{"kind": "ServiceAccount", "name": "trstctl-dod-controller", "namespace": NAMESPACE}],
    })
    token_response = api.json("POST", f"/api/v1/namespaces/{NAMESPACE}/serviceaccounts/trstctl-dod-controller/token", {
        "apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
        "spec": {"audiences": ["https://kubernetes.default.svc"], "expirationSeconds": 1800},
    }, (200, 201))
    token = token_response.get("status", {}).get("token", "")
    if not token:
        raise RuntimeError("Kubernetes TokenRequest returned no service-account token")

    api.create("/apis/trstctl.com/v1alpha1/clusterissuers", {
        "apiVersion": "trstctl.com/v1alpha1", "kind": "ClusterIssuer",
        "metadata": {"name": ISSUER_NAME}, "spec": {},
    })

    csr_key = root / "csr-key.pem"
    csr_der = root / "request.der"
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=dod-kind-workload", "-keyout", str(csr_key), "-outform", "DER", "-out", str(csr_der)], timeout=30)
    csr_raw = csr_der.read_bytes()
    csr_key.unlink(missing_ok=True)
    csr_hash = hashlib.sha256(csr_raw).hexdigest()
    api.create("/apis/certificates.k8s.io/v1/certificatesigningrequests", {
        "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
        "metadata": {
            "name": CSR_NAME,
            "annotations": {"trstctl.com/issuer-name": ISSUER_NAME, "trstctl.com/issuer-kind": "ClusterIssuer", "trstctl.com/issuer-group": "trstctl.com"},
        },
        "spec": {
            "request": base64.b64encode(csr_raw).decode(), "signerName": f"trstctl.com/{ISSUER_NAME}",
            "expirationSeconds": 3600, "usages": ["digital signature", "key encipherment", "client auth"],
        },
    })
    csr = api.json("GET", "/apis/certificates.k8s.io/v1/certificatesigningrequests/" + CSR_NAME)
    api.json("PUT", "/apis/certificates.k8s.io/v1/certificatesigningrequests/" + CSR_NAME + "/approval", {
        "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
        "metadata": {"name": CSR_NAME, "resourceVersion": csr["metadata"]["resourceVersion"]},
        "status": {"conditions": [{
            "type": "Approved", "status": "True", "reason": "DODApproved",
            "message": "approved by the isolated real-kind DoD fixture", "lastUpdateTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]},
    })

    bundle_key = root / "bundle-key.pem"
    bundle_cert = root / "bundle.pem"
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=DoD Kind Trust Root", "-keyout", str(bundle_key), "-out", str(bundle_cert)], timeout=30)
    bundle_key.unlink(missing_ok=True)
    bundle_pem = bundle_cert.read_text().strip() + "\n"
    bundle_hash = hashlib.sha256(bundle_pem.encode()).hexdigest()
    api.create("/apis/trstctl.com/v1alpha1/trustbundles", {
        "apiVersion": "trstctl.com/v1alpha1", "kind": "TrustBundle", "metadata": {"name": BUNDLE_NAME},
        "spec": {"caBundlePEM": bundle_pem, "target": {"namespaces": [TARGET_NAMESPACE], "configMapName": BUNDLE_NAME, "key": "ca-bundle.pem"}},
    })
    return token, csr_hash, bundle_hash


class State:
    def __init__(self, entry_id: str, identity: str, contract_digest: str) -> None:
        self.entry_id = entry_id
        self.identity = identity
        self.contract_digest = contract_digest
        self.root = Path(tempfile.mkdtemp(prefix="trstctl-dod-kind-"))
        self.cluster_name = "trstctl-dod-" + hashlib.sha256((entry_id + str(os.getpid())).encode()).hexdigest()[:10]
        self.kind = require_kind()
        self.kubeconfig = self.root / "kubeconfig"
        self.lock = threading.Lock()
        self.config_read = False
        self.verified = False
        self.readback = b""
        self.api: KubernetesAPI | None = None
        self.api_port = 0
        self.ca_pem = b""
        self.token = ""
        self.csr_hash = ""
        self.bundle_hash = ""

    def start(self) -> None:
        run([self.kind, "create", "cluster", "--name", self.cluster_name, "--image", NODE_IMAGE, "--kubeconfig", str(self.kubeconfig), "--wait", "180s"], timeout=300)
        node = self.cluster_name + "-control-plane"
        image = run(["docker", "inspect", "--format", "{{.Config.Image}}", node], timeout=15).stdout.strip()
        if image != NODE_IMAGE:
            raise RuntimeError(f"kind node image {image!r} is not exact pinned {NODE_IMAGE!r}")
        raw = self.kubeconfig.read_text()
        server = kubeconfig_value(raw, "server")
        parsed = urlparse(server)
        if parsed.scheme != "https" or parsed.hostname not in {"127.0.0.1", "localhost"} or not parsed.port:
            raise RuntimeError(f"kind kubeconfig server is not loopback HTTPS: {server}")
        self.api_port = parsed.port
        self.ca_pem = base64.b64decode(kubeconfig_value(raw, "certificate-authority-data"), validate=True)
        client_cert = base64.b64decode(kubeconfig_value(raw, "client-certificate-data"), validate=True)
        client_key = base64.b64decode(kubeconfig_value(raw, "client-key-data"), validate=True)
        self.api = KubernetesAPI(server, self.ca_pem, client_cert, client_key, self.root)
        self.token, self.csr_hash, self.bundle_hash = prepare_fixtures(self.api, self.root)

    def stop(self) -> None:
        run([self.kind, "delete", "cluster", "--name", self.cluster_name], timeout=120, check=False)
        shutil.rmtree(self.root, ignore_errors=True)

    def config(self) -> bytes:
        with self.lock:
            self.config_read = True
        return compact({
            "schema_version": 1, "api_port": self.api_port,
            "ca_pem": base64.b64encode(self.ca_pem).decode(), "token": base64.b64encode(self.token.encode()).decode(),
            "namespace": NAMESPACE, "cluster_name": self.cluster_name, "node_image": NODE_IMAGE,
        })

    def cluster_state(self) -> dict:
        assert self.api is not None
        csr = self.api.json("GET", "/apis/certificates.k8s.io/v1/certificatesigningrequests/" + CSR_NAME)
        certificate = base64.b64decode(csr.get("status", {}).get("certificate", ""), validate=True)
        if b"BEGIN CERTIFICATE" not in certificate:
            raise RuntimeError("real-kind CSR has no signed certificate status")
        csr_conditions = csr.get("status", {}).get("conditions", [])
        if not any(item.get("type") == "Ready" and item.get("status") == "True" for item in csr_conditions):
            raise RuntimeError("real-kind CSR was not marked Ready")
        bundle = self.api.json("GET", "/apis/trstctl.com/v1alpha1/trustbundles/" + BUNDLE_NAME)
        bundle_status = bundle.get("status", {})
        if bundle_status.get("targets") != 1 or bundle_status.get("bundleSHA256") != self.bundle_hash:
            raise RuntimeError("real-kind TrustBundle status does not match its distributed public bundle")
        config_map = self.api.json("GET", f"/api/v1/namespaces/{TARGET_NAMESPACE}/configmaps/{BUNDLE_NAME}")
        installed = config_map.get("data", {}).get("ca-bundle.pem", "")
        if hashlib.sha256(installed.encode()).hexdigest() != self.bundle_hash:
            raise RuntimeError("real-kind ConfigMap readback does not match TrustBundle")
        issuer = self.api.json("GET", "/apis/trstctl.com/v1alpha1/clusterissuers/" + ISSUER_NAME)
        if not any(item.get("type") == "Ready" and item.get("status") == "True" for item in issuer.get("status", {}).get("conditions", [])):
            raise RuntimeError("real-kind ClusterIssuer was not reconciled Ready")
        return {
            "csr": {
                "name": CSR_NAME, "uid": csr["metadata"]["uid"], "resource_version": csr["metadata"]["resourceVersion"],
                "public_hash": self.csr_hash, "certificate_digest": hashlib.sha256(certificate).hexdigest(),
            },
            "trust_bundle": {
                "name": BUNDLE_NAME, "uid": bundle["metadata"]["uid"], "resource_version": bundle["metadata"]["resourceVersion"],
                "public_hash": self.bundle_hash, "config_map_uid": config_map["metadata"]["uid"],
            },
        }

    def verify(self, payload: object) -> bytes:
        if not isinstance(payload, dict) or payload.get("entry_id") != self.entry_id:
            raise RuntimeError("verification payload is not bound to the selected manifest entry")
        tenant_id = payload.get("tenant_id")
        report_id = payload.get("report_id")
        cluster_id = payload.get("cluster_id")
        route = payload.get("route")
        ca_pem = payload.get("ca_pem")
        if not all(isinstance(value, str) and value for value in (tenant_id, report_id, cluster_id, ca_pem)) or not isinstance(route, dict):
            raise RuntimeError("verification payload omitted tenant/report/cluster/route evidence")
        state = self.cluster_state()
        capability = "CAP-K8S-04" if self.entry_id.endswith("certificate_signing_requests") else "CAP-K8S-07"
        object_key = "csr" if capability == "CAP-K8S-04" else "trust_bundle"
        expected = state[object_key]
        if route.get("capability") != capability or route.get("served") is not True or not route.get("last_sync"):
            raise RuntimeError("served HTTP route did not report fresh controller-backed state")
        controllers = route.get("controllers")
        objects = route.get("objects")
        if not isinstance(controllers, list) or len(controllers) != 1 or controllers[0].get("report_id") != report_id or controllers[0].get("cluster_id") != cluster_id:
            raise RuntimeError("served route is not bound to the authenticated mTLS report")
        if not isinstance(objects, list) or len(objects) != 1:
            raise RuntimeError("served route did not expose exactly the reconciled kind object")
        item = objects[0]
        if item.get("name") != expected["name"] or item.get("uid") != expected["uid"] or item.get("state") != "ready" or item.get("public_hash") != expected["public_hash"]:
            raise RuntimeError("served route object does not match independent kind readback")
        ca_file = self.root / "control-plane-ca.pem"
        cert_file = self.root / "issued-csr.pem"
        ca_file.write_text(ca_pem)
        csr = self.api.json("GET", "/apis/certificates.k8s.io/v1/certificatesigningrequests/" + CSR_NAME) if self.api else {}
        cert_file.write_bytes(base64.b64decode(csr.get("status", {}).get("certificate", ""), validate=True))
        run(["openssl", "verify", "-CAfile", str(ca_file), str(cert_file)], timeout=15)
        report = compact({
            "schema_version": 1, "entry_id": self.entry_id, "tenant_id": tenant_id,
            "report_id": report_id, "cluster_id": cluster_id, "kind_node_image": NODE_IMAGE,
            "kind_state": state, "route_digest": hashlib.sha256(compact(route)).hexdigest(),
        })
        with self.lock:
            self.verified = True
            self.readback = report
        return report

    def passed(self) -> bool:
        with self.lock:
            return self.config_read and self.verified and len(self.readback) >= 16


def handler_for(state: State):
    class Handler(BaseHTTPRequestHandler):
        server_version = "trstctl-dod-kind/1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def send_body(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/dod/config":
                self.send_body(200, state.config())
                return
            if self.path == "/dod/readback":
                with state.lock:
                    body = state.readback
                self.send_body(200 if body else 404, body or compact({"error": "no verified reconcile"}))
                return
            self.send_body(404, compact({"error": "not found"}))

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/dod/verify":
                self.send_body(404, compact({"error": "not found"}))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                self.send_body(400, compact({"error": "invalid verification length"}))
                return
            try:
                body = state.verify(json.loads(self.rfile.read(length)))
            except (RuntimeError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
                self.send_body(422, compact({"error": str(error)}))
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
    state = State(entry_id, identity, contract_digest)
    state.start()
    server = LoopbackHTTPServer(("127.0.0.1", 0), handler_for(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(compact({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id, "identity": identity,
        "contract_digest": contract_digest, "pid": os.getpid(), "ready": True,
        "endpoint": f"http://127.0.0.1:{server.server_address[1]}",
    }).decode(), flush=True)
    stopped = threading.Event()
    signal.signal(signal.SIGINT, lambda *_args: stopped.set())
    signal.signal(signal.SIGTERM, lambda *_args: stopped.set())
    stopped.wait()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    passed = state.passed()
    state.stop()
    print(compact({
        "schema_version": 1, "challenge": challenge, "entry_id": entry_id, "identity": identity,
        "contract_digest": contract_digest, "pid": os.getpid(), "passed": passed,
    }).decode(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
