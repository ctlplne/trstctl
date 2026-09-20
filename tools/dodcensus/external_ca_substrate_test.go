// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestExternalCASubstrateAzureStateAndBridgeOriginProtocols(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo, "tools", "dodcensus", "substrates", "external_ca.py")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const program = `
import base64
from email.message import Message
import hashlib
import hmac
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import sys
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

spec = spec_from_file_location("external_ca_substrate", sys.argv[1])
module = module_from_spec(spec)
spec.loader.exec_module(module)

def request(base, method, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = Request(base + path, data=body, method=method, headers={
        "Authorization": "Bearer dod-token",
        "Content-Type": "application/json",
    })
    try:
        with urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.loads(error.read())

with tempfile.TemporaryDirectory(prefix="external-ca-regression-") as directory:
    state = module.State("external_ca.azurekv", Path(directory))
    server = module.LoopbackHTTPServer(("127.0.0.1", 0), module.Handler)
    server.state = state
    state.base_url = "http://127.0.0.1:%d" % server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = state.base_url
        name = "trstctl-generate-" + "a" * 48
        key = "/keys/" + name
        version = key + "/" + module.AZURE_KEY_VERSION
        status, missing = request(base, "GET", key + "?api-version=7.4")
        assert status == 404 and missing["error"]["code"] == "KeyNotFound", (status, missing)
        status, missing_sign = request(base, "POST", version + "/sign?api-version=7.4", {
            "alg": "RS256", "value": base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode(),
        })
        assert status == 404 and missing_sign["error"]["code"] == "KeyNotFound", (status, missing_sign)
        status, created = request(base, "POST", key + "/create?api-version=7.4", {"kty": "RSA-HSM", "key_size": 2048})
        assert status == 200 and created["key"]["kid"].endswith("/" + name + "/" + module.AZURE_KEY_VERSION), (status, created)
        status, fetched = request(base, "GET", version + "?api-version=7.4")
        assert status == 200 and fetched["key"]["kid"] == created["key"]["kid"], (status, fetched)
        status, signed = request(base, "POST", version + "/sign?api-version=7.4", {
            "alg": "RS256", "value": base64.urlsafe_b64encode(b"y" * 32).rstrip(b"=").decode(),
        })
        assert status == 200 and signed["value"], (status, signed)
        assert state.passed(), (state.requests, state.azure_transcript)
        assert module.ordered_transcript_contains(
            [("GET", "/first"), ("POST", "/second"), ("GET", "/third")],
            [("GET", "/first"), ("GET", "/third")],
        )
        assert not module.ordered_transcript_contains(
            [("GET", "/third"), ("GET", "/first")],
            [("GET", "/first"), ("GET", "/third")],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

def origin_state():
    value = object.__new__(module.State)
    value.lock = threading.Lock()
    value.public_origin = ""
    return value

def headers(*hosts):
    value = Message()
    for host in hosts:
        value.add_header("Host", host)
    return value

origin = origin_state()
assert origin.bind_public_origin(headers("127.0.0.1:54321")) == "http://127.0.0.1:54321"
assert origin.bind_public_origin(headers("127.0.0.1:54321")) == "http://127.0.0.1:54321"
assert origin.bind_public_origin(headers("127.0.0.1:54322")) == ""
for invalid in (
    headers(), headers("localhost:54321"), headers("host.docker.internal:54321"),
    headers("127.0.0.1"), headers("127.0.0.1:0"), headers("127.0.0.1:65536"),
    headers("127.0.0.1:054321"), headers("user@127.0.0.1:54321"),
    headers("127.0.0.1:54321", "127.0.0.1:54321"),
):
    assert origin_state().bind_public_origin(invalid) == "", invalid

def aws_state(transcript):
    value = object.__new__(module.State)
    value.entry_id = "external_ca.awspca"
    value.chain = b"issued"
    value.authenticated = True
    value.lock = threading.Lock()
    value.requests = []
    value.aws_transcript = transcript
    return value

aws_issue = ("POST", "/", "ACMPrivateCA.IssueCertificate")
aws_get = ("POST", "/", "ACMPrivateCA.GetCertificate")
assert aws_state([aws_issue, aws_get]).passed()
assert not aws_state([aws_get, aws_issue]).passed()
assert not aws_state([aws_issue]).passed()
assert not aws_state([("GET", "/", aws_issue[2]), aws_get]).passed()
assert not aws_state([("POST", "/wrong", aws_issue[2]), aws_get]).passed()

def sigv4_headers(signed_names, target="ACMPrivateCA.IssueCertificate"):
    values = Message()
    values["Content-Type"] = "application/x-amz-json-1.1"
    values["Host"] = "127.0.0.1:54321"
    values["X-Amz-Date"] = "20260712T120000Z"
    values["X-Amz-Target"] = target
    canonical_headers = "".join(name + ":" + " ".join(values[name].strip().split()) + "\n" for name in signed_names)
    body = b"{}"
    canonical_request = "\n".join((
        "POST", "/", "", canonical_headers, ";".join(signed_names), hashlib.sha256(body).hexdigest(),
    ))
    scope = "20260712/us-east-1/acm-pca/aws4_request"
    string_to_sign = "\n".join((
        "AWS4-HMAC-SHA256", values["X-Amz-Date"], scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ))
    date_key = hmac.new(b"AWS4dod-token", b"20260712", hashlib.sha256).digest()
    region_key = hmac.new(date_key, b"us-east-1", hashlib.sha256).digest()
    service_key = hmac.new(region_key, b"acm-pca", hashlib.sha256).digest()
    signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    values["Authorization"] = (
        "AWS4-HMAC-SHA256 Credential=AKIADOD/" + scope
        + ", SignedHeaders=" + ";".join(signed_names) + ", Signature=" + signature
    )
    return values

required_signed = ["content-type", "host", "x-amz-date", "x-amz-target"]
signed = sigv4_headers(required_signed)
assert module.verify_sigv4("POST", "/", signed, b"{}", access_key="AKIADOD", secret_key=b"dod-token", region="us-east-1", service="acm-pca")
unsigned_target = sigv4_headers(["host", "x-amz-date"])
assert not module.verify_sigv4("POST", "/", unsigned_target, b"{}", access_key="AKIADOD", secret_key=b"dod-token", region="us-east-1", service="acm-pca")
signed.replace_header("X-Amz-Target", "ACMPrivateCA.GetCertificate")
assert not module.verify_sigv4("POST", "/", signed, b"{}", access_key="AKIADOD", secret_key=b"dod-token", region="us-east-1", service="acm-pca")
`
	command := exec.CommandContext(ctx, "python3", "-c", program, path) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("external-CA substrate protocol regression: %v\n%s", err, output)
	}
}
