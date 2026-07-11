// SPDX-License-Identifier: MPL-2.0

package secretsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type responseDoerFunc func(*http.Request) (*http.Response, error)

func (f responseDoerFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }

type retainedResponseReadCloser struct {
	remaining    []byte
	destinations [][]byte
}

func (r *retainedResponseReadCloser) Read(destination []byte) (int, error) {
	if len(r.remaining) == 0 {
		return 0, io.EOF
	}
	const chunk = 257
	n := len(destination)
	if n > chunk {
		n = chunk
	}
	if n > len(r.remaining) {
		n = len(r.remaining)
	}
	copy(destination[:n], r.remaining[:n])
	r.destinations = append(r.destinations, destination[:n:n])
	r.remaining = r.remaining[n:]
	return n, nil
}

func (*retainedResponseReadCloser) Close() error { return nil }

type scriptedHTTPDoer struct {
	t       *testing.T
	handler func(*http.Request, []byte) (int, string)
	calls   []string
	bodies  [][]byte
}

func (d *scriptedHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	d.t.Helper()
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			d.t.Fatal(err)
		}
	}
	d.calls = append(d.calls, req.Method+" "+req.URL.RequestURI())
	d.bodies = append(d.bodies, append([]byte(nil), body...))
	status, response := d.handler(req, body)
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(response)),
		Request:    req,
	}, nil
}

func TestGitHubActionsPusherUsesRepositoryPublicKey(t *testing.T) {
	doer := &scriptedHTTPDoer{t: t}
	doer.handler = func(req *http.Request, body []byte) (int, string) {
		if req.Header.Get("Authorization") != "Bearer github-token" {
			t.Fatalf("authorization = %q", req.Header.Get("Authorization"))
		}
		if req.Method == http.MethodGet {
			return http.StatusOK, `{"key_id":"kid-7","key":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)) + `"}`
		}
		var payload struct {
			Encrypted string `json:"encrypted_value"`
			KeyID     string `json:"key_id"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(payload.Encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if payload.KeyID != "kid-7" || bytes.Equal(decoded, []byte("github-secret")) || len(decoded) <= len("github-secret") {
			t.Fatalf("GitHub payload key=%q encrypted_len=%d", payload.KeyID, len(decoded))
		}
		return http.StatusNoContent, ""
	}
	pusher, err := NewGitHubActionsPusher(GitHubActionsConfig{
		Endpoint: "https://api.github.test", HTTPClient: doer, Owner: "acme", Repo: "payments", Token: []byte("github-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pusher.Close()
	if err := pusher.Push(context.Background(), "DEPLOY_TOKEN", []byte("github-secret")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /repos/acme/payments/actions/secrets/public-key",
		"PUT /repos/acme/payments/actions/secrets/DEPLOY_TOKEN",
	}
	if strings.Join(doer.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %#v, want %#v", doer.calls, want)
	}
}

func TestResponseStatusErrorDoesNotRetainEchoedSecretBody(t *testing.T) {
	echoed := []byte("receiver-echoed-secret-material")
	doer := &scriptedHTTPDoer{t: t, handler: func(*http.Request, []byte) (int, string) {
		return http.StatusBadGateway, string(echoed)
	}}
	req, err := http.NewRequest(http.MethodPost, "https://receiver.example.test/write", bytes.NewReader(echoed))
	if err != nil {
		t.Fatal(err)
	}
	err = readJSON2xx(doer, req, nil)
	if err == nil || strings.Contains(err.Error(), string(echoed)) {
		t.Fatalf("closed response error = %v", err)
	}
	status, ok := err.(*responseStatusError)
	if !ok || status.code != http.StatusBadGateway || status.kind != responseStatusGeneric {
		t.Fatalf("status classification = %#v", err)
	}
	value := reflect.ValueOf(status).Elem()
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8 && bytes.Contains(field.Bytes(), echoed) {
			t.Fatalf("response error retained echoed secret bytes in field %s", value.Type().Field(index).Name)
		}
	}
}

func TestReadJSON2xxWipesEveryReaderDestination(t *testing.T) {
	body := &retainedResponseReadCloser{remaining: bytes.Repeat([]byte("receiver-echoed-secret"), 4096)}
	doer := responseDoerFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Body: body, Request: req}, nil
	})
	req, err := http.NewRequest(http.MethodPost, "https://receiver.example.test/write", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := readJSON2xx(doer, req, nil); err == nil {
		t.Fatal("expected closed status error")
	}
	if len(body.destinations) < 2 {
		t.Fatalf("reader calls = %d, want multiple chunks", len(body.destinations))
	}
	for call, destination := range body.destinations {
		for offset, value := range destination {
			if value != 0 {
				t.Fatalf("reader destination call=%d offset=%d retained secret byte %#x", call, offset, value)
			}
		}
	}
}

func TestCloudSecretManagerPushersPerformRealUpserts(t *testing.T) {
	t.Run("AWS create fallback", func(t *testing.T) {
		doer := &scriptedHTTPDoer{t: t}
		doer.handler = func(req *http.Request, body []byte) (int, string) {
			if !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				t.Fatalf("missing SigV4 authorization")
			}
			switch req.Header.Get("X-Amz-Target") {
			case "secretsmanager.PutSecretValue":
				return http.StatusBadRequest, `{"__type":"ResourceNotFoundException"}`
			case "secretsmanager.CreateSecret":
				var payload struct {
					Name   string `json:"Name"`
					Secret []byte `json:"SecretBinary"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatal(err)
				}
				if payload.Name != "DATABASE_URL" || !bytes.Equal(payload.Secret, []byte("aws-secret")) {
					t.Fatalf("AWS payload = %+v", payload)
				}
				return http.StatusOK, `{}`
			default:
				t.Fatalf("unexpected AWS target %q", req.Header.Get("X-Amz-Target"))
				return 0, ""
			}
		}
		pusher, err := NewAWSSecretsManagerPusher(AWSSecretsManagerConfig{
			Endpoint: "https://secretsmanager.test", HTTPClient: doer, Region: "us-east-1",
			AccessKeyID: "AKID", SecretAccessKey: []byte("secret-key"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pusher.Close()
		if err := pusher.Push(context.Background(), "DATABASE_URL", []byte("aws-secret")); err != nil {
			t.Fatal(err)
		}
		if len(doer.calls) != 2 {
			t.Fatalf("AWS calls = %#v", doer.calls)
		}
	})

	t.Run("GCP container create fallback", func(t *testing.T) {
		doer := &scriptedHTTPDoer{t: t}
		step := 0
		doer.handler = func(req *http.Request, body []byte) (int, string) {
			step++
			if req.Header.Get("Authorization") != "Bearer gcp-token" {
				t.Fatalf("authorization = %q", req.Header.Get("Authorization"))
			}
			switch step {
			case 1:
				return http.StatusNotFound, `{}`
			case 2:
				if req.URL.Query().Get("secretId") != "DATABASE_URL" || !bytes.Contains(body, []byte(`"automatic"`)) {
					t.Fatalf("GCP create request uri=%s body=%s", req.URL.RequestURI(), body)
				}
				return http.StatusOK, `{}`
			case 3:
				var payload struct {
					Payload struct {
						Data []byte `json:"data"`
					} `json:"payload"`
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(payload.Payload.Data, []byte("gcp-secret")) {
					t.Fatalf("GCP payload data = %q", payload.Payload.Data)
				}
				return http.StatusOK, `{}`
			default:
				t.Fatal("too many GCP calls")
				return 0, ""
			}
		}
		pusher, err := NewGCPSecretManagerPusher(GCPSecretManagerConfig{
			Endpoint: "https://secretmanager.test", HTTPClient: doer, Project: "acme", BearerToken: []byte("gcp-token"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pusher.Close()
		if err := pusher.Push(context.Background(), "DATABASE_URL", []byte("gcp-secret")); err != nil {
			t.Fatal(err)
		}
		if step != 3 {
			t.Fatalf("GCP steps = %d", step)
		}
	})
}

func TestVersionCreatingPushersReconcileStableOutboxOperation(t *testing.T) {
	const operationID = "sync-11111111-1111-4111-8111-111111111111"
	value := []byte("replay-safe-secret")

	t.Run("GCP latest readback suppresses duplicate version", func(t *testing.T) {
		doer := &scriptedHTTPDoer{t: t}
		var latest []byte
		adds := 0
		doer.handler = func(req *http.Request, body []byte) (int, string) {
			if req.Header.Get("Idempotency-Key") != operationID {
				t.Fatalf("idempotency header = %q", req.Header.Get("Idempotency-Key"))
			}
			if req.Method == http.MethodGet {
				if len(latest) == 0 {
					return http.StatusNotFound, `{}`
				}
				return http.StatusOK, `{"payload":{"data":"` + base64.StdEncoding.EncodeToString(latest) + `"}}`
			}
			adds++
			var payload struct {
				Payload struct {
					Data []byte `json:"data"`
				} `json:"payload"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			latest = bytes.Clone(payload.Payload.Data)
			return http.StatusOK, `{}`
		}
		pusher, err := NewGCPSecretManagerPusher(GCPSecretManagerConfig{
			Endpoint: "https://secretmanager.test", HTTPClient: doer, Project: "acme",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pusher.Close()
		target := NewTarget("gcp", pusher)
		for i := 0; i < 2; i++ {
			if err := target.DeliverOperation(context.Background(), operationID, "DATABASE_URL", value); err != nil {
				t.Fatal(err)
			}
		}
		if adds != 1 {
			t.Fatalf("GCP addVersion calls = %d, want 1 after redelivery", adds)
		}
	})

	t.Run("Azure latest readback suppresses duplicate version", func(t *testing.T) {
		doer := &scriptedHTTPDoer{t: t}
		var latest []byte
		puts := 0
		doer.handler = func(req *http.Request, body []byte) (int, string) {
			if req.Header.Get("Idempotency-Key") != operationID {
				t.Fatalf("idempotency header = %q", req.Header.Get("Idempotency-Key"))
			}
			if req.Method == http.MethodGet {
				if len(latest) == 0 {
					return http.StatusNotFound, `{}`
				}
				return http.StatusOK, `{"value":"` + base64.StdEncoding.EncodeToString(latest) + `"}`
			}
			puts++
			var payload struct {
				Value []byte `json:"value"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			latest = bytes.Clone(payload.Value)
			return http.StatusOK, `{}`
		}
		pusher, err := NewAzureKeyVaultPusher(AzureKeyVaultConfig{
			Endpoint: "https://vault.test", HTTPClient: doer,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pusher.Close()
		target := NewTarget("azure", pusher)
		for i := 0; i < 2; i++ {
			if err := target.DeliverOperation(context.Background(), operationID, "DATABASE_URL", value); err != nil {
				t.Fatal(err)
			}
		}
		if puts != 1 {
			t.Fatalf("Azure set-secret calls = %d, want 1 after redelivery", puts)
		}
	})

	t.Run("AWS sends native client request token", func(t *testing.T) {
		doer := &scriptedHTTPDoer{t: t}
		calls := 0
		doer.handler = func(req *http.Request, body []byte) (int, string) {
			calls++
			var payload struct {
				ClientRequestToken string `json:"ClientRequestToken"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.ClientRequestToken != operationID || req.Header.Get("Idempotency-Key") != operationID {
				t.Fatalf("AWS operation binding body=%q header=%q", payload.ClientRequestToken, req.Header.Get("Idempotency-Key"))
			}
			return http.StatusOK, `{}`
		}
		pusher, err := NewAWSSecretsManagerPusher(AWSSecretsManagerConfig{
			Endpoint: "https://secretsmanager.test", HTTPClient: doer, Region: "us-east-1",
			AccessKeyID: "AKID", SecretAccessKey: []byte("secret-key"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pusher.Close()
		target := NewTarget("aws", pusher)
		for i := 0; i < 2; i++ {
			if err := target.DeliverOperation(context.Background(), operationID, "DATABASE_URL", value); err != nil {
				t.Fatal(err)
			}
		}
		if calls != 2 {
			t.Fatalf("AWS receiver calls = %d, want two idempotent replays", calls)
		}
	})
}

func TestCITargetPushersUseVendorCreateUpdateSemantics(t *testing.T) {
	t.Run("GitLab update then create", func(t *testing.T) {
		doer := &scriptedHTTPDoer{t: t}
		doer.handler = func(req *http.Request, body []byte) (int, string) {
			if req.Header.Get("PRIVATE-TOKEN") != "gitlab-token" {
				t.Fatalf("PRIVATE-TOKEN = %q", req.Header.Get("PRIVATE-TOKEN"))
			}
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload["value"] != "gitlab-secret" {
				t.Fatalf("GitLab value = %#v", payload["value"])
			}
			if req.Method == http.MethodPut {
				return http.StatusNotFound, `{}`
			}
			return http.StatusCreated, `{}`
		}
		pusher, err := NewGitLabCIPusher(GitLabCIConfig{
			Endpoint: "https://gitlab.test", HTTPClient: doer, ProjectID: "42", Token: []byte("gitlab-token"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pusher.Close()
		if err := pusher.Push(context.Background(), "DATABASE_URL", []byte("gitlab-secret")); err != nil {
			t.Fatal(err)
		}
		if len(doer.calls) != 2 || !strings.HasPrefix(doer.calls[0], "PUT ") || !strings.HasPrefix(doer.calls[1], "POST ") {
			t.Fatalf("GitLab calls = %#v", doer.calls)
		}
	})

	t.Run("Kubernetes get then create", func(t *testing.T) {
		doer := &scriptedHTTPDoer{t: t}
		doer.handler = func(req *http.Request, body []byte) (int, string) {
			if req.Header.Get("Authorization") != "Bearer k8s-token" {
				t.Fatalf("authorization = %q", req.Header.Get("Authorization"))
			}
			if req.Method == http.MethodGet {
				return http.StatusNotFound, `{}`
			}
			var payload struct {
				Data map[string]string `json:"data"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			decoded, err := base64.StdEncoding.DecodeString(payload.Data["value"])
			if err != nil || !bytes.Equal(decoded, []byte("k8s-secret")) {
				t.Fatalf("Kubernetes data = %q err=%v", decoded, err)
			}
			return http.StatusCreated, `{}`
		}
		pusher, err := NewKubernetesPusher(KubernetesConfig{
			Endpoint: "https://kubernetes.test", HTTPClient: doer, Namespace: "apps", BearerToken: []byte("k8s-token"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pusher.Close()
		if err := pusher.Push(context.Background(), "database-url", []byte("k8s-secret")); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"GET /api/v1/namespaces/apps/secrets/database-url",
			"POST /api/v1/namespaces/apps/secrets",
		}
		if strings.Join(doer.calls, "|") != strings.Join(want, "|") {
			t.Fatalf("Kubernetes calls = %#v", doer.calls)
		}
	})
}
