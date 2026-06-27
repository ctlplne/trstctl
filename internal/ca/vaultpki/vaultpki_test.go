package vaultpki_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/ca/vaultpki"
	"trstctl.com/trstctl/internal/crypto"
	boundaryca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestPluginIssuesThroughVaultPKIMount(t *testing.T) {
	stub := newVaultStub(t, "vault-token-sensitive")
	defer stub.Close()

	cfg := vaultpki.Config{
		Name:       "vault-pki",
		BaseURL:    stub.URL(),
		Token:      []byte("vault-token-sensitive"),
		Mount:      "pki_int",
		Role:       "web",
		DefaultTTL: 72 * time.Hour,
	}
	if rendered := fmt.Sprintf("%+v %#v", cfg, cfg); strings.Contains(rendered, "vault-token-sensitive") {
		t.Fatalf("Vault config rendering leaked token: %s", rendered)
	}

	p := vaultpki.New(cfg, vaultpki.WithHTTPClient(stub.Client()))
	var _ ca.CA = p

	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      vaultCSR(t, "svc.vault.test", []string{"svc.vault.test", "www.vault.test"}),
		DNSNames: []string{"svc.vault.test", "www.vault.test"},
		TTL:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "vault-pki" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	if !containsDNS(info.DNSNames, "svc.vault.test") || !containsDNS(info.DNSNames, "www.vault.test") {
		t.Fatalf("issued cert DNSNames = %v, want both requested names", info.DNSNames)
	}
	got := stub.LastRequest()
	if got.method != http.MethodPost || got.path != "/v1/pki_int/sign/web" {
		t.Fatalf("Vault request = %s %s, want POST /v1/pki_int/sign/web", got.method, got.path)
	}
	if got.token != "vault-token-sensitive" {
		t.Fatalf("X-Vault-Token = %q, want configured token", got.token)
	}
	if got.commonName != "svc.vault.test" || got.altNames != "svc.vault.test,www.vault.test" {
		t.Fatalf("Vault request names common=%q alt=%q", got.commonName, got.altNames)
	}
	if got.ttl != "86400s" {
		t.Fatalf("Vault request ttl = %q, want 86400s", got.ttl)
	}
}

func TestPluginSurfacesVaultErrorsWithoutLeakingToken(t *testing.T) {
	stub := newVaultStub(t, "vault-token-sensitive")
	defer stub.Close()
	stub.Fail("denied by policy")

	p := vaultpki.New(vaultpki.Config{
		Name: "vault-pki", BaseURL: stub.URL(), Token: []byte("vault-token-sensitive"), Mount: "pki", Role: "denied",
	}, vaultpki.WithHTTPClient(stub.Client()))
	_, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      vaultCSR(t, "denied.vault.test", []string{"denied.vault.test"}),
		DNSNames: []string{"denied.vault.test"},
		TTL:      time.Hour,
	})
	if err == nil {
		t.Fatal("Issue succeeded; want Vault error")
	}
	if !strings.Contains(err.Error(), "vaultpki: api error 403: denied by policy") {
		t.Fatalf("Issue error = %q, want structured Vault error", err)
	}
	if strings.Contains(err.Error(), "vault-token-sensitive") {
		t.Fatalf("Issue error leaked Vault token: %q", err)
	}
}

func TestPluginPassesConformance(t *testing.T) {
	stub := newVaultStub(t, "vault-token-sensitive")
	defer stub.Close()
	p := vaultpki.New(vaultpki.Config{
		Name: "vault-pki", BaseURL: stub.URL(), Token: []byte("vault-token-sensitive"), Mount: "pki", Role: "web",
	}, vaultpki.WithHTTPClient(stub.Client()))
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("Vault PKI plugin failed conformance: %+v", report.Checks)
	}
}

func vaultCSR(t *testing.T, cn string, dns []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

type vaultRequest struct {
	method     string
	path       string
	token      string
	commonName string
	altNames   string
	ttl        string
}

type vaultStub struct {
	t         *testing.T
	token     string
	authority *boundaryca.Authority
	server    *httptest.Server

	mu       sync.Mutex
	last     vaultRequest
	failWith string
}

func newVaultStub(t *testing.T, token string) *vaultStub {
	t.Helper()
	auth, err := boundaryca.NewAuthority("Vault PKI Test Root")
	if err != nil {
		t.Fatal(err)
	}
	stub := &vaultStub{t: t, token: token, authority: auth}
	stub.server = httptest.NewServer(http.HandlerFunc(stub.handle))
	return stub
}

func (v *vaultStub) URL() string { return v.server.URL }

func (v *vaultStub) Client() *http.Client { return v.server.Client() }

func (v *vaultStub) Close() {
	v.server.Close()
	v.authority.Destroy()
}

func (v *vaultStub) Fail(message string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.failWith = message
}

func (v *vaultStub) LastRequest() vaultRequest {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.last
}

func (v *vaultStub) handle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSR        string `json:"csr"`
		CommonName string `json:"common_name"`
		AltNames   string `json:"alt_names"`
		TTL        string `json:"ttl"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	v.mu.Lock()
	v.last = vaultRequest{
		method: r.Method, path: r.URL.Path, token: r.Header.Get("X-Vault-Token"),
		commonName: body.CommonName, altNames: body.AltNames, ttl: body.TTL,
	}
	failWith := v.failWith
	v.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if failWith != "" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{failWith}})
		return
	}
	if r.Header.Get("X-Vault-Token") != v.token {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
		return
	}
	block, _ := pem.Decode([]byte(body.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"csr must be a PEM certificate request"}})
		return
	}
	issued, err := v.authority.IssueFromCSR(block.Bytes, 48*time.Hour)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{err.Error()}})
		return
	}
	blocks := splitPEMBlocks(issued.CertificatePEM)
	if len(blocks) < 2 {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"test authority returned no chain"}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"certificate":      blocks[0],
			"issuing_ca":       blocks[1],
			"ca_chain":         blocks[1:],
			"serial_number":    issued.Serial,
			"expiration":       issued.NotAfter.Unix(),
			"private_key":      "",
			"private_key_type": "",
		},
	})
}

func splitPEMBlocks(chain []byte) []string {
	var out []string
	rest := chain
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			return out
		}
		out = append(out, string(pem.EncodeToMemory(block)))
		rest = next
	}
}

func containsDNS(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}
