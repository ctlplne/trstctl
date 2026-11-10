// SPDX-License-Identifier: BUSL-1.1

package k8s_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/k8s"
)

// fakeAPIServer is a tiny in-memory stand-in for the Kubernetes Secrets API: it
// serves GET/POST/PUT and JSON merge PATCH on
// /api/v1/namespaces/{ns}/secrets[/{name}], which is exactly the wire
// contract the secret destination drives.
type fakeAPIServer struct {
	mu        sync.Mutex
	secrets   map[string]map[string]any // name -> object
	gotBearer string
	// patchRV is the resourceVersion the last patch was conditional on.
	patchRV string
}

// mergePatch applies an RFC 7386 JSON merge patch the way the API server
// does: the patch's fields replace the target's, null removes a field, and
// every field the patch does not name stays as it is.
func mergePatch(target, patch any) any {
	fields, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	out := map[string]any{}
	if current, ok := target.(map[string]any); ok {
		for k, v := range current {
			out[k] = v
		}
	}
	for k, v := range fields {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = mergePatch(out[k], v)
	}
	return out
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
			meta["uid"] = "uid-" + n
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
			// Like the API server, an update keeps the object's uid.
			if meta, ok := obj["metadata"].(map[string]any); ok {
				if old, exists := f.secrets[name]; exists {
					if oldMeta, ok := old["metadata"].(map[string]any); ok {
						meta["uid"] = oldMeta["uid"]
					}
				}
			}
			f.secrets[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		case http.MethodPatch:
			if r.Header.Get("Content-Type") != "application/merge-patch+json" {
				http.Error(w, `{"kind":"Status","code":415}`, http.StatusUnsupportedMediaType)
				return
			}
			live, exists := f.secrets[name]
			if !exists {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			var patch map[string]any
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &patch); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			// Like the API server, a resourceVersion in the patch is a
			// precondition and the type of a Secret cannot change.
			if meta, ok := patch["metadata"].(map[string]any); ok {
				if rv, _ := meta["resourceVersion"].(string); rv != "" {
					f.patchRV = rv
					if liveMeta, _ := live["metadata"].(map[string]any); liveMeta["resourceVersion"] != rv {
						http.Error(w, `{"kind":"Status","code":409}`, http.StatusConflict)
						return
					}
				}
			}
			if kind, ok := patch["type"]; ok && kind != live["type"] {
				http.Error(w, `{"kind":"Status","code":422,"message":"field is immutable"}`, http.StatusUnprocessableEntity)
				return
			}
			merged, _ := mergePatch(live, patch).(map[string]any)
			f.secrets[name] = merged
			_ = json.NewEncoder(w).Encode(merged)
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
	if meta["resourceVersion"] != "7" || api.patchRV != "7" {
		t.Errorf("update did not carry the resourceVersion (stored %v, conditional on %q) — optimistic concurrency lost",
			meta["resourceVersion"], api.patchRV)
	}
}

// K8S-O2: the Secret an Ingress or Gateway names is often owned and guarded by
// another controller. Renewing its certificate in place keeps the
// ownerReferences that tie it to its owner's garbage collection, the
// finalizers that hold its deletion for a cleanup hook, and the data keys the
// write does not name, such as a ca.crt. A credential without a key (the
// destination already holds it) leaves the Secret's key as it is.
func TestSecretDestinationKeepsOwnersFinalizersAndOtherData(t *testing.T) {
	api := newFakeAPIServer()
	owners := []any{map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "name": "web-owner", "uid": "uid-web-owner", "controller": true,
	}}
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	api.secrets["web-tls"] = map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
		"metadata": map[string]any{
			"name": "web-tls", "namespace": "payments", "resourceVersion": "7", "uid": "uid-web-tls",
			"ownerReferences": owners, "finalizers": []any{"example.test/keep"},
		},
		"data": map[string]any{"tls.crt": encode("OLD"), "tls.key": encode("OLD"), "ca.crt": encode("ISSUING-CA")},
	}
	srv := httptest.NewServer(api.handler(t))
	defer srv.Close()

	client := k8s.New(srv.URL, "tok", "payments", srv.Client())
	dest := k8s.NewSecretDestination(client, "payments", "web-tls")
	if _, err := dest.InstallAndRead(context.Background(), destination.Credential{CertPEM: []byte("NEW-CERT"), KeyPEM: []byte("NEW-KEY")}); err != nil {
		t.Fatalf("InstallAndRead: %v", err)
	}
	obj := api.stored(t, "web-tls")
	meta := obj["metadata"].(map[string]any)
	if !reflect.DeepEqual(meta["ownerReferences"], owners) {
		t.Fatalf("renewal dropped the Secret's ownerReferences: %+v", meta)
	}
	if !reflect.DeepEqual(meta["finalizers"], []any{"example.test/keep"}) {
		t.Fatalf("renewal dropped the Secret's finalizers: %+v", meta)
	}
	if got := decodeSecretData(t, obj, "ca.crt"); string(got) != "ISSUING-CA" {
		t.Fatalf("renewal dropped the Secret's ca.crt (got %q)", got)
	}
	if crt, key := decodeSecretData(t, obj, "tls.crt"), decodeSecretData(t, obj, "tls.key"); string(crt) != "NEW-CERT" || string(key) != "NEW-KEY" {
		t.Fatalf("after renewal tls.crt=%q tls.key=%q", crt, key)
	}

	if err := dest.Install(context.Background(), destination.Credential{CertPEM: []byte("CERT-ONLY")}); err != nil {
		t.Fatalf("Install (certificate only): %v", err)
	}
	obj = api.stored(t, "web-tls")
	if crt, key := decodeSecretData(t, obj, "tls.crt"), decodeSecretData(t, obj, "tls.key"); string(crt) != "CERT-ONLY" || string(key) != "NEW-KEY" {
		t.Fatalf("a certificate-only write left tls.crt=%q tls.key=%q; want the new certificate and the key the Secret holds", crt, key)
	}
}

// An in-cluster delivery writes over a Secret an Ingress or Gateway already
// names. The write keeps the labels and annotations other tools put there, and
// it returns what the cluster now holds — uid, resourceVersion and tls.crt —
// so the caller can prove the certificate it installed is the one stored.
func TestSecretDestinationKeepsMetadataAndReadsBack(t *testing.T) {
	api := newFakeAPIServer()
	api.secrets["web-tls"] = map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
		"metadata": map[string]any{
			"name": "web-tls", "namespace": "payments", "resourceVersion": "7", "uid": "uid-web-tls",
			"labels":      map[string]any{"app.kubernetes.io/name": "web"},
			"annotations": map[string]any{"example.test/owner": "payments-team"},
		},
		"data": map[string]any{"tls.crt": base64.StdEncoding.EncodeToString([]byte("OLD")), "tls.key": base64.StdEncoding.EncodeToString([]byte("OLD"))},
	}
	srv := httptest.NewServer(api.handler(t))
	defer srv.Close()

	client := k8s.New(srv.URL, "tok", "payments", srv.Client())
	dest := k8s.NewSecretDestination(client, "payments", "web-tls")
	readback, err := dest.InstallAndRead(context.Background(), destination.Credential{CertPEM: []byte("NEW-CERT"), KeyPEM: []byte("NEW-KEY")})
	if err != nil {
		t.Fatalf("InstallAndRead: %v", err)
	}
	if readback.Namespace != "payments" || readback.Name != "web-tls" || readback.UID != "uid-web-tls" ||
		readback.ResourceVersion != "7" || string(readback.CertPEM) != "NEW-CERT" {
		t.Fatalf("readback = %+v", readback)
	}
	meta := api.stored(t, "web-tls")["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	annotations, _ := meta["annotations"].(map[string]any)
	if labels["app.kubernetes.io/name"] != "web" || annotations["example.test/owner"] != "payments-team" {
		t.Fatalf("update dropped the Secret's labels or annotations: %+v", meta)
	}

	created, err := k8s.NewSecretDestination(client, "payments", "api-tls").InstallAndRead(context.Background(),
		destination.Credential{CertPEM: []byte("API-CERT"), KeyPEM: []byte("API-KEY")})
	if err != nil {
		t.Fatalf("InstallAndRead (create): %v", err)
	}
	if created.UID != "uid-api-tls" || created.ResourceVersion != "1" || string(created.CertPEM) != "API-CERT" {
		t.Fatalf("created readback = %+v", created)
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
