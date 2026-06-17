package k8s_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// caSigner backs the bridge with the crypto boundary's mTLS CA: it signs the
// CSR cert-manager carries in a CertificateRequest.
func caSigner(t *testing.T) (k8s.Signer, *mtls.CA) {
	t.Helper()
	ca, err := mtls.NewCA("cert-manager bridge CA")
	if err != nil {
		t.Fatal(err)
	}
	return k8s.SignerFunc(func(_ context.Context, csrDER []byte) ([]byte, error) {
		return ca.SignClientCSR(csrDER, time.Hour)
	}), ca
}

// csrRequestField builds the base64-of-PEM CSR that cert-manager puts in
// CertificateRequest.spec.request.
func csrRequestField(t *testing.T) string {
	t.Helper()
	id, err := mtls.GenerateAgentKey("workload.svc")
	if err != nil {
		t.Fatal(err)
	}
	der, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	pemCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return base64.StdEncoding.EncodeToString(pemCSR)
}

// fakeCertManager serves the CertificateRequest list and records status writes.
type fakeCertManager struct {
	mu        sync.Mutex
	items     []map[string]any
	statusPut map[string]map[string]any // name -> updated object
}

func (f *fakeCertManager) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certificaterequests"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "cert-manager.io/v1", "kind": "CertificateRequestList", "items": f.items,
			})
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/status"):
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			name := parts[len(parts)-2]
			var obj map[string]any
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &obj)
			if f.statusPut == nil {
				f.statusPut = map[string]map[string]any{}
			}
			f.statusPut[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotImplemented)
		}
	})
}

func certRequest(name, issuer, group string, ready bool) map[string]any {
	cr := map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
		"metadata": map[string]any{"name": name, "namespace": "apps"},
		"spec": map[string]any{
			"issuerRef": map[string]any{"name": issuer, "kind": "ClusterIssuer", "group": group},
		},
	}
	if ready {
		cr["status"] = map[string]any{"conditions": []any{
			map[string]any{"type": "Ready", "status": "True"},
		}}
	}
	return cr
}

func readyCondition(t *testing.T, obj map[string]any) (status, certificate string) {
	t.Helper()
	st, _ := obj["status"].(map[string]any)
	if st == nil {
		return "", ""
	}
	if c, ok := st["certificate"].(string); ok {
		certificate = c
	}
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" {
			status, _ = m["status"].(string)
		}
	}
	return status, certificate
}

// TestBridgeSignsPendingRequest is the acceptance core ("bridges to
// cert-manager"): a pending CertificateRequest naming our issuer is signed and
// its status is updated to Ready with the issued certificate.
func TestBridgeSignsPendingRequest(t *testing.T) {
	signer, _ := caSigner(t)
	cm := &fakeCertManager{items: []map[string]any{
		func() map[string]any {
			cr := certRequest("req-1", "trstctl", "trstctl.com", false)
			cr["spec"].(map[string]any)["request"] = csrRequestField(t)
			return cr
		}(),
	}}
	srv := httptest.NewServer(cm.handler())
	defer srv.Close()

	client := k8s.New(srv.URL, "tok", "apps", srv.Client())
	bridge := k8s.NewBridge(client, signer, "trstctl", "trstctl.com")

	n, err := bridge.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("signed %d requests, want 1", n)
	}
	obj, ok := cm.statusPut["req-1"]
	if !ok {
		t.Fatal("no status update was written for req-1")
	}
	status, certificate := readyCondition(t, obj)
	if status != "True" {
		t.Errorf("Ready condition = %q, want True", status)
	}
	// status.certificate is a []byte API field: base64-encoded PEM.
	der, err := base64.StdEncoding.DecodeString(certificate)
	if err != nil {
		t.Fatalf("status.certificate is not base64-encoded: %v", err)
	}
	if block, _ := pem.Decode(der); block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("status.certificate does not decode to a PEM certificate")
	}
}

func TestBridgeRejectsEmptySignerCertificate(t *testing.T) {
	cm := &fakeCertManager{items: []map[string]any{
		func() map[string]any {
			cr := certRequest("req-empty", "trstctl", "trstctl.com", false)
			cr["spec"].(map[string]any)["request"] = csrRequestField(t)
			return cr
		}(),
	}}
	srv := httptest.NewServer(cm.handler())
	defer srv.Close()

	signer := k8s.SignerFunc(func(context.Context, []byte) ([]byte, error) {
		return []byte(" \n"), nil
	})
	bridge := k8s.NewBridge(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl", "trstctl.com")

	n, err := bridge.Reconcile(context.Background(), "apps")
	if err == nil {
		t.Fatal("Reconcile succeeded with an empty signer certificate")
	}
	if !strings.Contains(err.Error(), "empty certificate chain") {
		t.Fatalf("error %q should name the empty certificate", err)
	}
	if n != 0 {
		t.Fatalf("signed count = %d, want 0", n)
	}
	if len(cm.statusPut) != 0 {
		t.Fatalf("empty signer certificate wrote Ready status: %#v", cm.statusPut)
	}
}

// TestBridgeSkipsOtherIssuers: a request for a different issuer is left alone.
func TestBridgeSkipsOtherIssuers(t *testing.T) {
	signer, _ := caSigner(t)
	cm := &fakeCertManager{items: []map[string]any{
		func() map[string]any {
			cr := certRequest("other", "letsencrypt", "cert-manager.io", false)
			cr["spec"].(map[string]any)["request"] = csrRequestField(t)
			return cr
		}(),
	}}
	srv := httptest.NewServer(cm.handler())
	defer srv.Close()

	bridge := k8s.NewBridge(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl", "trstctl.com")
	n, err := bridge.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("signed %d requests for another issuer, want 0", n)
	}
	if len(cm.statusPut) != 0 {
		t.Errorf("wrote status for another issuer's request")
	}
}

// TestBridgePreservesExistingConditions: signing an Approved (but not yet
// Ready) request adds the Ready condition and the certificate while keeping the
// Approved condition — cert-manager requires Approved to remain for issuance.
func TestBridgePreservesExistingConditions(t *testing.T) {
	signer, _ := caSigner(t)
	cm := &fakeCertManager{items: []map[string]any{
		func() map[string]any {
			cr := certRequest("approved", "trstctl", "trstctl.com", false)
			cr["spec"].(map[string]any)["request"] = csrRequestField(t)
			cr["status"] = map[string]any{"conditions": []any{
				map[string]any{"type": "Approved", "status": "True", "reason": "cert-manager.io"},
			}}
			return cr
		}(),
	}}
	srv := httptest.NewServer(cm.handler())
	defer srv.Close()

	bridge := k8s.NewBridge(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl", "trstctl.com")
	if n, err := bridge.Reconcile(context.Background(), "apps"); err != nil || n != 1 {
		t.Fatalf("Reconcile n=%d err=%v, want 1", n, err)
	}

	obj := cm.statusPut["approved"]
	if obj == nil {
		t.Fatal("no status update written")
	}
	status, _ := obj["status"].(map[string]any)
	conds, _ := status["conditions"].([]any)
	var approved, ready bool
	for _, c := range conds {
		m, _ := c.(map[string]any)
		switch m["type"] {
		case "Approved":
			approved = true
		case "Ready":
			ready = m["status"] == "True"
		}
	}
	if !approved {
		t.Error("Approved condition was dropped during the status update")
	}
	if !ready {
		t.Error("Ready=True condition was not added")
	}
	if _, ok := status["certificate"].(string); !ok {
		t.Error("issued certificate was not set on the status")
	}
}

// TestBridgeIdempotentOnReady: an already-Ready request is not re-signed.
func TestBridgeIdempotentOnReady(t *testing.T) {
	signer, _ := caSigner(t)
	cm := &fakeCertManager{items: []map[string]any{
		func() map[string]any {
			cr := certRequest("done", "trstctl", "trstctl.com", true)
			cr["spec"].(map[string]any)["request"] = csrRequestField(t)
			return cr
		}(),
	}}
	srv := httptest.NewServer(cm.handler())
	defer srv.Close()

	bridge := k8s.NewBridge(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl", "trstctl.com")
	n, err := bridge.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("re-signed %d already-Ready requests, want 0", n)
	}
}
