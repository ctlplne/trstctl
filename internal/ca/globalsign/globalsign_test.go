package globalsign_test

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
	"trstctl.com/trstctl/internal/ca/globalsign"
	"trstctl.com/trstctl/internal/crypto"
	boundaryca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestPluginIssuesThroughOrderRetrieveFlow(t *testing.T) {
	stub := newGlobalSignStub(t, "gs-key-sensitive", "gs-secret-sensitive")
	defer stub.Close()

	cfg := globalsign.Config{
		Name:      "globalsign",
		BaseURL:   stub.URL(),
		APIKey:    []byte("gs-key-sensitive"),
		APISecret: []byte("gs-secret-sensitive"),
	}
	if rendered := fmt.Sprintf("%+v %#v", cfg, cfg); strings.Contains(rendered, "gs-key-sensitive") || strings.Contains(rendered, "gs-secret-sensitive") {
		t.Fatalf("GlobalSign config rendering leaked credentials: %s", rendered)
	}

	p := globalsign.New(cfg, globalsign.WithHTTPClient(stub.Client()), globalsign.WithPollInterval(time.Millisecond))
	var _ ca.CA = p

	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      globalsignCSR(t, "svc.globalsign.test", []string{"svc.globalsign.test", "www.globalsign.test"}),
		DNSNames: []string{"svc.globalsign.test", "www.globalsign.test"},
		TTL:      90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "globalsign" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	if !containsDNS(info.DNSNames, "svc.globalsign.test") || !containsDNS(info.DNSNames, "www.globalsign.test") {
		t.Fatalf("issued cert DNSNames = %v, want both requested names", info.DNSNames)
	}

	calls := stub.Calls()
	if len(calls) != 2 {
		t.Fatalf("GlobalSign call count = %d, want POST + GET", len(calls))
	}
	if calls[0].method != http.MethodPost || calls[0].path != "/v2/certificates" {
		t.Fatalf("first call = %s %s, want POST /v2/certificates", calls[0].method, calls[0].path)
	}
	if calls[1].method != http.MethodGet || calls[1].path != "/v2/certificates/GS-12345" {
		t.Fatalf("second call = %s %s, want GET /v2/certificates/GS-12345", calls[1].method, calls[1].path)
	}
	if calls[0].apiKey != "gs-key-sensitive" || calls[0].apiSecret != "gs-secret-sensitive" {
		t.Fatalf("auth headers apiKey=%q apiSecret=%q", calls[0].apiKey, calls[0].apiSecret)
	}
	if calls[0].commonName != "svc.globalsign.test" {
		t.Fatalf("subject common_name = %q, want svc.globalsign.test", calls[0].commonName)
	}
	if strings.Join(calls[0].dnsNames, ",") != "svc.globalsign.test,www.globalsign.test" {
		t.Fatalf("dns_names = %v, want both requested names", calls[0].dnsNames)
	}
}

func TestPluginSurfacesAuthFailureAsStructuredError(t *testing.T) {
	stub := newGlobalSignStub(t, "gs-key-sensitive", "gs-secret-sensitive")
	defer stub.Close()

	p := globalsign.New(globalsign.Config{
		Name: "globalsign", BaseURL: stub.URL(), APIKey: []byte("gs-key-sensitive"), APISecret: []byte("wrong-secret-sensitive"),
	}, globalsign.WithHTTPClient(stub.Client()), globalsign.WithPollInterval(time.Millisecond))
	_, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      globalsignCSR(t, "denied.globalsign.test", []string{"denied.globalsign.test"}),
		DNSNames: []string{"denied.globalsign.test"},
		TTL:      time.Hour,
	})
	if err == nil {
		t.Fatal("Issue succeeded; want auth error")
	}
	if !strings.Contains(err.Error(), "globalsign: api error 401: invalid credentials") {
		t.Fatalf("Issue error = %q, want structured GlobalSign auth error", err)
	}
	if strings.Contains(err.Error(), "wrong-secret-sensitive") || strings.Contains(err.Error(), "gs-key-sensitive") {
		t.Fatalf("Issue error leaked credentials: %q", err)
	}
}

func TestPluginPassesConformance(t *testing.T) {
	stub := newGlobalSignStub(t, "gs-key-sensitive", "gs-secret-sensitive")
	defer stub.Close()

	p := globalsign.New(globalsign.Config{
		Name: "globalsign", BaseURL: stub.URL(), APIKey: []byte("gs-key-sensitive"), APISecret: []byte("gs-secret-sensitive"),
	}, globalsign.WithHTTPClient(stub.Client()), globalsign.WithPollInterval(time.Millisecond))
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("GlobalSign plugin failed conformance: %+v", report.Checks)
	}
}

func globalsignCSR(t *testing.T, cn string, dns []string) []byte {
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

type globalSignCall struct {
	method     string
	path       string
	apiKey     string
	apiSecret  string
	commonName string
	dnsNames   []string
}

type globalSignStub struct {
	t         *testing.T
	apiKey    string
	apiSecret string
	authority *boundaryca.Authority
	server    *httptest.Server

	mu     sync.Mutex
	calls  []globalSignCall
	issued map[string][]string
}

func newGlobalSignStub(t *testing.T, apiKey, apiSecret string) *globalSignStub {
	t.Helper()
	auth, err := boundaryca.NewAuthority("GlobalSign Test Root")
	if err != nil {
		t.Fatal(err)
	}
	stub := &globalSignStub{
		t: t, apiKey: apiKey, apiSecret: apiSecret, authority: auth,
		issued: map[string][]string{},
	}
	stub.server = httptest.NewServer(http.HandlerFunc(stub.handle))
	return stub
}

func (g *globalSignStub) URL() string { return g.server.URL }

func (g *globalSignStub) Client() *http.Client { return g.server.Client() }

func (g *globalSignStub) Close() {
	g.server.Close()
	g.authority.Destroy()
}

func (g *globalSignStub) Calls() []globalSignCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]globalSignCall(nil), g.calls...)
}

func (g *globalSignStub) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("ApiKey") != g.apiKey || r.Header.Get("ApiSecret") != g.apiSecret {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid credentials"})
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v2/certificates":
		g.handleOrder(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/certificates/GS-12345":
		g.handleRetrieve(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (g *globalSignStub) handleOrder(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSR       string `json:"csr"`
		SubjectDN struct {
			CommonName string `json:"common_name"`
		} `json:"subject_dn"`
		SAN struct {
			DNSNames []string `json:"dns_names"`
		} `json:"san"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	g.record(globalSignCall{
		method: r.Method, path: r.URL.Path, apiKey: r.Header.Get("ApiKey"), apiSecret: r.Header.Get("ApiSecret"),
		commonName: body.SubjectDN.CommonName, dnsNames: append([]string(nil), body.SAN.DNSNames...),
	})
	block, _ := pem.Decode([]byte(body.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "csr must be a PEM certificate request"})
		return
	}
	issued, err := g.authority.IssueFromCSR(block.Bytes, 48*time.Hour)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	blocks := splitPEMBlocks(issued.CertificatePEM)
	if len(blocks) < 2 {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "test authority returned no chain"})
		return
	}
	g.mu.Lock()
	g.issued["GS-12345"] = blocks
	g.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"serial_number": "GS-12345", "status": "pending"})
}

func (g *globalSignStub) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	g.record(globalSignCall{method: r.Method, path: r.URL.Path, apiKey: r.Header.Get("ApiKey"), apiSecret: r.Header.Get("ApiSecret")})
	g.mu.Lock()
	blocks := append([]string(nil), g.issued["GS-12345"]...)
	g.mu.Unlock()
	if len(blocks) < 2 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "unknown serial"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"serial_number": "GS-12345",
		"status":        "issued",
		"certificate":   blocks[0],
		"chain":         strings.Join(blocks[1:], ""),
	})
}

func (g *globalSignStub) record(call globalSignCall) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, call)
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
