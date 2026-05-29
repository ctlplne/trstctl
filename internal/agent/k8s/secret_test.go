package k8s_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"certctl.io/certctl/internal/agent/destination"
	"certctl.io/certctl/internal/agent/k8s"
)

// fakeAPIServer is a tiny in-memory stand-in for the Kubernetes Secrets API: it
// serves GET/POST/PUT on /api/v1/namespaces/{ns}/secrets[/{name}], which is
// exactly the wire contract the secret destination drives.
type fakeAPIServer struct {
	mu        sync.Mutex
	secrets   map[string]map[string]any // name -> object
	gotBearer string
}

func newFakeAPIServer() *fakeAPIServer {
	return &fakeAPIServer{secrets: map[string]map[string]any{}}
}

func (f *fakeAPIServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.gotBearer = r.Header.Get("Authorization")
		// path: /api/v1/namespaces/{ns}/secrets   (collection)
		//       /api/v1/namespaces/{ns}/secrets/{name} (item)
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		// api v1 namespaces {ns} secrets [name]
		var name string
		if len(parts) == 6 {
			name = parts[5]
		}
		switch r.Method {
		case http.MethodGet:
			obj, ok := f.secrets[name]
			if !ok {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(obj)
		case http.MethodPost:
			var obj map[string]any
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &obj); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			meta := obj["metadata"].(map[string]any)
			n := meta["name"].(string)
			if _, exists := f.secrets[n]; exists {
				http.Error(w, `{"kind":"Status","code":409}`, http.StatusConflict)
				return
			}
			meta["resourceVersion"] = "1"
			f.secrets[n] = obj
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)
		case http.MethodPut:
			var obj map[string]any
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &obj); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			f.secrets[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func (f *fakeAPIServer) stored(t *testing.T, name string) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.secrets[name]
	if !ok {
		t.Fatalf("secret %q not stored", name)
	}
	return obj
}

func decodeSecretData(t *testing.T, obj map[string]any, key string) []byte {
	t.Helper()
	data, ok := obj["data"].(map[string]any)
	if !ok {
		t.Fatal("secret has no data map")
	}
	b64, ok := data[key].(string)
	if !ok {
		t.Fatalf("secret data missing %q", key)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("data[%q] is not valid base64: %v", key, err)
	}
	return raw
}

// TestSecretDestinationCreatesTLSSecret is the acceptance core ("writes a cert
// into a K8s secret"): installing a credential creates a kubernetes.io/tls
// Secret whose tls.crt / tls.key carry the PEM bytes, base64-encoded as the API
// requires, and the request is authenticated with the service-account token.
func TestSecretDestinationCreatesTLSSecret(t *testing.T) {
	api := newFakeAPIServer()
	srv := httptest.NewServer(api.handler(t))
	defer srv.Close()

	client := k8s.New(srv.URL, "sa-token-123", "workloads", srv.Client())
	dest := k8s.NewSecretDestination(client, "workloads", "web-tls")

	cred := destination.Credential{CertPEM: []byte("CERT-PEM-BYTES"), KeyPEM: []byte("KEY-PEM-BYTES")}
	if err := dest.Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}

	obj := api.stored(t, "web-tls")
	if obj["type"] != "kubernetes.io/tls" {
		t.Errorf("secret type = %v, want kubernetes.io/tls", obj["type"])
	}
	if got := decodeSecretData(t, obj, "tls.crt"); string(got) != "CERT-PEM-BYTES" {
		t.Errorf("tls.crt = %q, want the cert PEM", got)
	}
	if got := decodeSecretData(t, obj, "tls.key"); string(got) != "KEY-PEM-BYTES" {
		t.Errorf("tls.key = %q, want the key PEM", got)
	}
	if !strings.Contains(api.gotBearer, "sa-token-123") {
		t.Errorf("request not authenticated with the SA token; Authorization=%q", api.gotBearer)
	}
}

// TestSecretDestinationUpdatesExisting: installing over an existing secret
// updates it in place (idempotent destination contract), preserving identity.
func TestSecretDestinationUpdatesExisting(t *testing.T) {
	api := newFakeAPIServer()
	// Pre-seed an existing secret with stale data.
	api.secrets["web-tls"] = map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
		"metadata": map[string]any{"name": "web-tls", "namespace": "workloads", "resourceVersion": "7"},
		"data":     map[string]any{"tls.crt": base64.StdEncoding.EncodeToString([]byte("OLD")), "tls.key": base64.StdEncoding.EncodeToString([]byte("OLD"))},
	}
	srv := httptest.NewServer(api.handler(t))
	defer srv.Close()

	client := k8s.New(srv.URL, "tok", "workloads", srv.Client())
	dest := k8s.NewSecretDestination(client, "workloads", "web-tls")
	cred := destination.Credential{CertPEM: []byte("NEW-CERT"), KeyPEM: []byte("NEW-KEY")}
	if err := dest.Install(context.Background(), cred); err != nil {
		t.Fatalf("Install (update): %v", err)
	}

	obj := api.stored(t, "web-tls")
	if got := decodeSecretData(t, obj, "tls.crt"); string(got) != "NEW-CERT" {
		t.Errorf("tls.crt after update = %q, want NEW-CERT", got)
	}
	meta := obj["metadata"].(map[string]any)
	if meta["resourceVersion"] != "7" {
		t.Errorf("update did not carry the resourceVersion (got %v) — optimistic concurrency lost", meta["resourceVersion"])
	}
}

// TestSecretDestinationRejectsEmptyCertificate: no certificate, no install.
func TestSecretDestinationRejectsEmptyCertificate(t *testing.T) {
	client := k8s.New("http://unused", "tok", "ns", http.DefaultClient)
	dest := k8s.NewSecretDestination(client, "ns", "x")
	if err := dest.Install(context.Background(), destination.Credential{KeyPEM: []byte("k")}); err == nil {
		t.Error("Install with empty certificate succeeded, want error")
	}
}

// The secret destination satisfies the Destination interface.
var _ destination.Destination = (*k8s.SecretDestination)(nil)
