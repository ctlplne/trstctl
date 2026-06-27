package entrust_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/ca/entrust"
	"trstctl.com/trstctl/internal/crypto"
	boundaryca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestPluginIssuesThroughEnrollmentFlow(t *testing.T) {
	stub := newEntrustStub(t)
	defer stub.Close()

	p := entrust.New(entrust.Config{
		Name: "entrust", BaseURL: stub.URL(), CAID: "ca-123", ProfileID: "profile-web",
	}, entrust.WithHTTPClient(stub.Client()), entrust.WithPollInterval(time.Millisecond))
	var _ ca.CA = p

	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      entrustCSR(t, "svc.entrust.test", []string{"svc.entrust.test", "www.entrust.test"}),
		DNSNames: []string{"svc.entrust.test", "www.entrust.test"},
		TTL:      90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "entrust" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	if !containsDNS(info.DNSNames, "svc.entrust.test") || !containsDNS(info.DNSNames, "www.entrust.test") {
		t.Fatalf("issued cert DNSNames = %v, want both requested names", info.DNSNames)
	}

	calls := stub.Calls()
	if len(calls) != 2 {
		t.Fatalf("Entrust call count = %d, want POST + GET", len(calls))
	}
	if calls[0].method != http.MethodPost || calls[0].path != "/v1/certificate-authorities/ca-123/enrollments" {
		t.Fatalf("first call = %s %s, want POST enrollment", calls[0].method, calls[0].path)
	}
	if calls[1].method != http.MethodGet || calls[1].path != "/v1/certificate-authorities/ca-123/enrollments/ENR-12345" {
		t.Fatalf("second call = %s %s, want GET enrollment status", calls[1].method, calls[1].path)
	}
	if calls[0].profileID != "profile-web" {
		t.Fatalf("profileId = %q, want profile-web", calls[0].profileID)
	}
	if strings.Join(calls[0].dnsNames, ",") != "svc.entrust.test,www.entrust.test" {
		t.Fatalf("subjectAltNames = %v, want both requested names", calls[0].dnsNames)
	}
}

func TestPluginSurfacesGatewayErrorAsStructuredError(t *testing.T) {
	stub := newEntrustStub(t)
	defer stub.Close()
	stub.FailEnroll()

	p := entrust.New(entrust.Config{
		Name: "entrust", BaseURL: stub.URL(), CAID: "ca-123", ProfileID: "denied-profile",
	}, entrust.WithHTTPClient(stub.Client()), entrust.WithPollInterval(time.Millisecond))
	_, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      entrustCSR(t, "denied.entrust.test", []string{"denied.entrust.test"}),
		DNSNames: []string{"denied.entrust.test"},
		TTL:      time.Hour,
	})
	if err == nil {
		t.Fatal("Issue succeeded; want gateway error")
	}
	if !strings.Contains(err.Error(), "entrust: api error 400: E_PROFILE: profile denied") {
		t.Fatalf("Issue error = %q, want structured Entrust error", err)
	}
}

func TestPluginPassesConformance(t *testing.T) {
	stub := newEntrustStub(t)
	defer stub.Close()

	p := entrust.New(entrust.Config{
		Name: "entrust", BaseURL: stub.URL(), CAID: "ca-123",
	}, entrust.WithHTTPClient(stub.Client()), entrust.WithPollInterval(time.Millisecond))
	report := catemplate.Conformance(context.Background(), p)
	if !report.OK() {
		t.Fatalf("Entrust plugin failed conformance: %+v", report.Checks)
	}
}

func entrustCSR(t *testing.T, cn string, dns []string) []byte {
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

type entrustCall struct {
	method    string
	path      string
	profileID string
	dnsNames  []string
}

type entrustStub struct {
	t         *testing.T
	authority *boundaryca.Authority
	server    *httptest.Server

	mu         sync.Mutex
	calls      []entrustCall
	issued     map[string][]string
	failEnroll bool
}

func newEntrustStub(t *testing.T) *entrustStub {
	t.Helper()
	auth, err := boundaryca.NewAuthority("Entrust Test Root")
	if err != nil {
		t.Fatal(err)
	}
	stub := &entrustStub{t: t, authority: auth, issued: map[string][]string{}}
	stub.server = httptest.NewServer(http.HandlerFunc(stub.handle))
	return stub
}

func (e *entrustStub) URL() string { return e.server.URL }

func (e *entrustStub) Client() *http.Client { return e.server.Client() }

func (e *entrustStub) Close() {
	e.server.Close()
	e.authority.Destroy()
}

func (e *entrustStub) FailEnroll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failEnroll = true
}

func (e *entrustStub) Calls() []entrustCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]entrustCall(nil), e.calls...)
}

func (e *entrustStub) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/certificate-authorities/ca-123/enrollments":
		e.handleEnroll(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/certificate-authorities/ca-123/enrollments/ENR-12345":
		e.handleStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (e *entrustStub) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSR             string `json:"csr"`
		ProfileID       string `json:"profileId"`
		SubjectAltNames []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"subjectAltNames"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	var dns []string
	for _, san := range body.SubjectAltNames {
		if san.Type == "dNSName" {
			dns = append(dns, san.Value)
		}
	}
	e.record(entrustCall{method: r.Method, path: r.URL.Path, profileID: body.ProfileID, dnsNames: dns})
	e.mu.Lock()
	fail := e.failEnroll
	e.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "E_PROFILE", "message": "profile denied"})
		return
	}
	block, _ := pem.Decode([]byte(body.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "csr must be a PEM certificate request"})
		return
	}
	issued, err := e.authority.IssueFromCSR(block.Bytes, 48*time.Hour)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": err.Error()})
		return
	}
	blocks := splitPEMBlocks(issued.CertificatePEM)
	if len(blocks) < 2 {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "test authority returned no chain"})
		return
	}
	e.mu.Lock()
	e.issued["ENR-12345"] = blocks
	e.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"trackingId": "ENR-12345", "status": "PENDING"})
}

func (e *entrustStub) handleStatus(w http.ResponseWriter, r *http.Request) {
	e.record(entrustCall{method: r.Method, path: r.URL.Path})
	e.mu.Lock()
	blocks := append([]string(nil), e.issued["ENR-12345"]...)
	e.mu.Unlock()
	if len(blocks) < 2 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "unknown tracking ID"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"trackingId":  "ENR-12345",
		"status":      "ISSUED",
		"certificate": blocks[0],
		"chain":       strings.Join(blocks[1:], ""),
	})
}

func (e *entrustStub) record(call entrustCall) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, call)
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
