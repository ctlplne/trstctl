// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// signedWebhookReceiver is a receiver that verifies every delivery with the
// shared key, as an operator's endpoint would, and keeps what it accepted.
type signedWebhookReceiver struct {
	server   *httptest.Server
	key      []byte
	mu       sync.Mutex
	accepted [][]byte
	headers  []http.Header
	refused  int
}

func newSignedWebhookReceiver(t *testing.T, key []byte) *signedWebhookReceiver {
	t.Helper()
	r := &signedWebhookReceiver{key: key}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		if err := secretsync.VerifyWebhookSignature(r.key, req.Header.Get(secretsync.WebhookTimestampHeader), body,
			req.Header.Get(secretsync.WebhookSignatureHeader), time.Now(), 0); err != nil {
			r.refused++
			http.Error(w, "signature refused", http.StatusUnauthorized)
			return
		}
		r.accepted = append(r.accepted, body)
		r.headers = append(r.headers, req.Header.Clone())
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.server.Close)
	return r
}

// TestServedSecretSyncToASignedWebhook is A202 for the webhook target, built
// from config as the binary builds it: the outbox delivers the templated body,
// the receiver verifies the signature before accepting it, and the same
// request with one byte changed is refused.
func TestServedSecretSyncToASignedWebhook(t *testing.T) {
	ctx := context.Background()
	receiver := newSignedWebhookReceiver(t, []byte("receiver-shared-signing-key"))
	registry, minter, err := secretSyncTargetsFromConfig(ctx, []config.SecretSyncTargetConfig{{
		TenantID: servedTestTenant, ID: "deploy-hook", Type: "webhook", Endpoint: receiver.server.URL,
		AllowInsecureLoopback: true,
		SigningKeyRef:         writeServedCredentialFile(t, "webhook-signing-key", "receiver-shared-signing-key"),
		BodyTemplate:          `{"secret":{"name":"${key}","value":"${value}"},"delivery":"${delivery_id}","at":${timestamp}}`,
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(minter.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = registry
	})
	registerServedTenant(t, h, "signed webhook tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "webhook-syncer", "secrets:read", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{"name": "app/db", "value": "pa\"ss\nword"}); status != http.StatusCreated {
		t.Fatalf("create secret: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, "webhook-sync-1",
		map[string]any{"name": "app/db", "target": "deploy-hook", "remote_key": "DB_PASSWORD"})
	if status != http.StatusOK {
		t.Fatalf("queue the sync: %d %s", status, body)
	}
	job := drainSecretSyncUntil(t, h, currentSecretSyncJobIDForTest(t, h.store, h.tenant, "webhook-sync-1"), store.SecretSyncJobDelivered, 3)
	if job.Status != store.SecretSyncJobDelivered {
		t.Fatalf("the sync = %+v, want delivered", job)
	}
	receiver.mu.Lock()
	accepted, headers, refused := append([][]byte(nil), receiver.accepted...), append([]http.Header(nil), receiver.headers...), receiver.refused
	receiver.mu.Unlock()
	if len(accepted) != 1 || refused != 0 {
		t.Fatalf("the receiver accepted %d and refused %d deliveries", len(accepted), refused)
	}
	var delivered struct {
		Secret   struct{ Name, Value string }
		Delivery string
		At       int64
	}
	if err := json.Unmarshal(accepted[0], &delivered); err != nil || delivered.Secret.Name != "DB_PASSWORD" ||
		delivered.Secret.Value != "pa\"ss\nword" || delivered.Delivery == "" || delivered.Delivery != headers[0].Get(secretsync.WebhookDeliveryHeader) {
		t.Fatalf("delivered body %s (%v)", accepted[0], err)
	}

	// Replay the exact delivery with one byte of the body changed: refused.
	tampered := bytes.Replace(accepted[0], []byte("pa"), []byte("PA"), 1)
	req, _ := http.NewRequest(http.MethodPost, receiver.server.URL, bytes.NewReader(tampered))
	for _, name := range []string{secretsync.WebhookTimestampHeader, secretsync.WebhookSignatureHeader, secretsync.WebhookDeliveryHeader} {
		req.Header.Set(name, headers[0].Get(name))
	}
	resp, err := receiver.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a tampered delivery = %d, want 401", resp.StatusCode)
	}
	t.Logf("A202_WEBHOOK_OK delivery=%s", delivered.Delivery)
}

const a202LocalStackImage = "localstack/localstack@sha256:b279c01f4cfb8f985a482e4014cabc1e2697b9d7a6c8c8db2e40f4d9f93687c7"

// TestServedSecretSyncToParameterStoreOnLocalStack is A202 for Parameter
// Store against LocalStack: the delivered secret is a SecureString at the
// hierarchical name, read back with GetParameter and decryption; a later
// version overwrites it.
func TestServedSecretSyncToParameterStoreOnLocalStack(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a202LocalStackImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned LocalStack image is not present locally: %v\n%s", err, out)
	}
	ctx := context.Background()
	_, address := a201Container(t, "4566", "-e", "SERVICES=ssm,kms", a202LocalStackImage)
	endpoint := "http://" + address
	a201Await(t, "LocalStack SSM", func() bool {
		resp, err := http.Get(endpoint + "/_localstack/health")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		var health struct{ Services map[string]string }
		return json.NewDecoder(resp.Body).Decode(&health) == nil &&
			(health.Services["ssm"] == "available" || health.Services["ssm"] == "running")
	})
	registry, minter, err := secretSyncTargetsFromConfig(ctx, []config.SecretSyncTargetConfig{{
		TenantID: servedTestTenant, ID: "params", Type: "aws-parameter-store", Endpoint: endpoint, AllowInsecureLoopback: true,
		Region: "us-east-1", AccessKeyID: "test", SecretAccessRef: writeServedCredentialFile(t, "ssm-secret", "test"),
		PathPrefix: "apps/payments",
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(minter.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = registry
	})
	registerServedTenant(t, h, "parameter store tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "ssm-syncer", "secrets:read", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{"name": "app/db", "value": "ssm-v1"}); status != http.StatusCreated {
		t.Fatalf("create secret: %d %s", status, body)
	}
	sync := func(idem string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, idem,
			map[string]any{"name": "app/db", "target": "params", "remote_key": "db/password"})
		if status != http.StatusOK {
			t.Fatalf("queue the sync: %d %s", status, body)
		}
		if job := drainSecretSyncUntil(t, h, currentSecretSyncJobIDForTest(t, h.store, h.tenant, idem), store.SecretSyncJobDelivered, 3); job.Status != store.SecretSyncJobDelivered {
			t.Fatalf("the sync = %+v, want delivered", job)
		}
	}
	// The readback is LocalStack's own SSM API, called directly: GetParameter
	// with decryption over the AWS JSON protocol (LocalStack does not check the
	// signature, so none of trstctl's signing code is involved).
	read := func() (string, string, int64) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, endpoint+"/", bytes.NewReader([]byte(`{"Name":"/apps/payments/db/password","WithDecryption":true}`)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/20261027/us-east-1/ssm/aws4_request, SignedHeaders=host, Signature=00")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GetParameter: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out struct {
			Parameter struct {
				Value, Type string
				Version     int64
			}
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GetParameter = %d %v", resp.StatusCode, err)
		}
		return out.Parameter.Value, out.Parameter.Type, out.Parameter.Version
	}
	sync("ssm-sync-1")
	if value, kind, version := read(); value != "ssm-v1" || kind != "SecureString" || version != 1 {
		t.Fatalf("parameter = %q %s v%d, want ssm-v1 as a SecureString", value, kind, version)
	}
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/app/db", tok, map[string]any{"value": "ssm-v2"}); status != http.StatusOK {
		t.Fatalf("rotate the secret: %d %s", status, body)
	}
	sync("ssm-sync-2")
	if value, _, version := read(); value != "ssm-v2" || version != 2 {
		t.Fatalf("parameter after the next version = %q v%d", value, version)
	}
	t.Log("A202_PARAMETER_STORE_OK")
}

// netlifyAPIDouble answers the environment-variable calls the Netlify API
// reference documents: GET a variable, PATCH a contextual value, POST create.
type netlifyAPIDouble struct {
	server *httptest.Server
	mu     sync.Mutex
	vars   map[string]map[string]string // key → context → value
	secret map[string]bool
	calls  []string
}

func newNetlifyAPIDouble(t *testing.T) *netlifyAPIDouble {
	t.Helper()
	d := &netlifyAPIDouble{vars: map[string]map[string]string{}, secret: map[string]bool{}}
	d.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.calls = append(d.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("Authorization") != "Bearer netlify-pat" || r.URL.Query().Get("site_id") != "site-1" {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		const base = "/api/v1/accounts/team-1/env"
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"/"):
			key := strings.TrimPrefix(r.URL.Path, base+"/")
			if _, ok := d.vars[key]; !ok {
				http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"key": key})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, base+"/"):
			key := strings.TrimPrefix(r.URL.Path, base+"/")
			var in struct{ Context, Value string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			d.vars[key][in.Context] = in.Value
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == base:
			var in []struct {
				Key      string
				IsSecret bool `json:"is_secret"`
				Values   []struct{ Value, Context string }
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			for _, v := range in {
				d.vars[v.Key] = map[string]string{}
				for _, value := range v.Values {
					d.vars[v.Key][value.Context] = value.Value
				}
				d.secret[v.Key] = v.IsSecret
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(d.server.Close)
	return d
}

// TestServedSecretSyncToNetlify is A202 for Netlify through the config-built
// target, against a double built from Netlify's API reference (a live account
// proof needs an account): the first delivery creates a secret variable with
// the production value; the next version sets that value on the existing one.
func TestServedSecretSyncToNetlify(t *testing.T) {
	ctx := context.Background()
	netlify := newNetlifyAPIDouble(t)
	registry, minter, err := secretSyncTargetsFromConfig(ctx, []config.SecretSyncTargetConfig{{
		TenantID: servedTestTenant, ID: "site-env", Type: "netlify", Endpoint: netlify.server.URL + "/api/v1",
		AllowInsecureLoopback: true, TokenRef: writeServedCredentialFile(t, "netlify-pat", "netlify-pat"),
		AccountID: "team-1", SiteID: "site-1", DeployContext: "production",
	}}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(minter.Close)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantSecretSyncTargets = registry
	})
	registerServedTenant(t, h, "netlify tenant")
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "netlify-syncer", "secrets:read", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{"name": "app/api", "value": "netlify-v1"}); status != http.StatusCreated {
		t.Fatalf("create secret: %d %s", status, body)
	}
	sync := func(idem string) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/syncs", tok, idem,
			map[string]any{"name": "app/api", "target": "site-env", "remote_key": "API_TOKEN"})
		if status != http.StatusOK {
			t.Fatalf("queue the sync: %d %s", status, body)
		}
		if job := drainSecretSyncUntil(t, h, currentSecretSyncJobIDForTest(t, h.store, h.tenant, idem), store.SecretSyncJobDelivered, 3); job.Status != store.SecretSyncJobDelivered {
			t.Fatalf("the sync = %+v, want delivered", job)
		}
	}
	sync("netlify-sync-1")
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/secrets/store/app/api", tok, map[string]any{"value": "netlify-v2"}); status != http.StatusOK {
		t.Fatalf("rotate the secret: %d %s", status, body)
	}
	sync("netlify-sync-2")
	netlify.mu.Lock()
	defer netlify.mu.Unlock()
	if netlify.vars["API_TOKEN"]["production"] != "netlify-v2" || !netlify.secret["API_TOKEN"] {
		t.Fatalf("Netlify holds %v (secret %v)", netlify.vars["API_TOKEN"], netlify.secret["API_TOKEN"])
	}
	want := []string{
		"GET /api/v1/accounts/team-1/env/API_TOKEN?site_id=site-1",
		"POST /api/v1/accounts/team-1/env?site_id=site-1",
		"GET /api/v1/accounts/team-1/env/API_TOKEN?site_id=site-1",
		"PATCH /api/v1/accounts/team-1/env/API_TOKEN?site_id=site-1",
	}
	if strings.Join(netlify.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Netlify calls:\n%s", strings.Join(netlify.calls, "\n"))
	}
}
