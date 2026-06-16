//go:build e2e

// Package kubernetes_e2e is the in-cluster acceptance for S5.4: against a real
// Kubernetes API server (kind/k3s in CI), the agent writes a certificate into a
// Secret and bridges a cert-manager CertificateRequest to trstctl issuance.
//
// It runs only under `go test -tags e2e` with the cluster coordinates in the
// environment (K8S_SERVER, K8S_TOKEN, K8S_CA_FILE, K8S_NAMESPACE), which the CI
// job provides after creating the cluster and a service account.
package kubernetes_e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

func env(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; e2e requires a live cluster", key)
	}
	return v
}

// cluster builds the agent's k8s.Client (the code under test, using the
// restricted agent service-account token) plus a raw HTTP helper that uses an
// admin token for test fixtures and verification — because the agent SA is
// least-privilege and cannot, for example, create CertificateRequests.
func cluster(t *testing.T) (*k8s.Client, func(method, path string, body any) (int, []byte), string) {
	t.Helper()
	server := env(t, "K8S_SERVER")
	token := env(t, "K8S_TOKEN")
	caFile := env(t, "K8S_CA_FILE")
	adminToken := os.Getenv("K8S_ADMIN_TOKEN")
	if adminToken == "" {
		adminToken = token // local single-token runs
	}
	ns := os.Getenv("K8S_NAMESPACE")
	if ns == "" {
		ns = "default"
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	client := k8s.New(server, token, ns, httpClient)

	// raw uses the admin token: fixtures and verification, not the code path
	// under test (the agent client / bridge use the restricted agent token).
	raw := func(method, path string, body any) (int, []byte) {
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, server+path, r)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}
	return client, raw, ns
}

// TestSecretDestinationWritesToCluster: the agent writes a cert into a real
// Secret, which is then readable from the API server.
func TestSecretDestinationWritesToCluster(t *testing.T) {
	client, raw, ns := cluster(t)
	name := fmt.Sprintf("trstctl-e2e-%d", time.Now().Unix())

	cred := destination.Credential{CertPEM: []byte("E2E-CERT-PEM"), KeyPEM: []byte("E2E-KEY-PEM")}
	if err := k8s.NewSecretDestination(client, ns, name).Install(context.Background(), cred); err != nil {
		t.Fatalf("Install: %v", err)
	}
	t.Cleanup(func() { raw(http.MethodDelete, "/api/v1/namespaces/"+ns+"/secrets/"+name, nil) })

	st, body := raw(http.MethodGet, "/api/v1/namespaces/"+ns+"/secrets/"+name, nil)
	if st != 200 {
		t.Fatalf("GET secret: status %d", st)
	}
	var obj struct {
		Type string            `json:"type"`
		Data map[string]string `json:"data"`
	}
	_ = json.Unmarshal(body, &obj)
	if obj.Type != "kubernetes.io/tls" {
		t.Errorf("secret type = %q, want kubernetes.io/tls", obj.Type)
	}
	crt, _ := base64.StdEncoding.DecodeString(obj.Data["tls.crt"])
	if string(crt) != "E2E-CERT-PEM" {
		t.Errorf("tls.crt = %q, want E2E-CERT-PEM", crt)
	}
}

// TestCertManagerBridgeInCluster: a pending cert-manager CertificateRequest is
// signed by the bridge and its status goes Ready with an issued certificate.
func TestCertManagerBridgeInCluster(t *testing.T) {
	client, raw, ns := cluster(t)

	ca, err := mtls.NewCA("trstctl e2e issuer")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mtls.GenerateAgentKey("e2e.workload")
	if err != nil {
		t.Fatal(err)
	}
	der, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	reqPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	name := fmt.Sprintf("e2e-cr-%d", time.Now().Unix())
	cr := map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"request":   base64.StdEncoding.EncodeToString(reqPEM),
			"issuerRef": map[string]any{"name": "trstctl", "kind": "ClusterIssuer", "group": "trstctl.com"},
		},
	}
	if st, body := raw(http.MethodPost, "/apis/cert-manager.io/v1/namespaces/"+ns+"/certificaterequests", cr); st/100 != 2 {
		t.Fatalf("create CertificateRequest: status %d: %s", st, body)
	}
	t.Cleanup(func() {
		raw(http.MethodDelete, "/apis/cert-manager.io/v1/namespaces/"+ns+"/certificaterequests/"+name, nil)
	})

	bridge := k8s.NewBridge(client, k8s.SignerFunc(func(_ context.Context, csrDER []byte) ([]byte, error) {
		return ca.SignClientCSR(csrDER, time.Hour)
	}), "trstctl", "trstctl.com")

	n, err := bridge.Reconcile(context.Background(), ns)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("signed %d requests, want 1", n)
	}

	st, body := raw(http.MethodGet, "/apis/cert-manager.io/v1/namespaces/"+ns+"/certificaterequests/"+name, nil)
	if st != 200 {
		t.Fatalf("GET CertificateRequest: status %d", st)
	}
	var got struct {
		Status struct {
			Certificate []byte `json:"certificate"` // []byte: base64 in JSON, decoded here
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode CertificateRequest: %v", err)
	}
	if block, _ := pem.Decode(got.Status.Certificate); block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("CertificateRequest status carries no issued PEM certificate: %s", body)
	}
}
