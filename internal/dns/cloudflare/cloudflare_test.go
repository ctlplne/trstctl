package cloudflare_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/dns/cloudflare"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/protocols/acme"
)

const (
	testToken = "cf-token-do-not-log"
	zoneID    = "0123456789abcdef0123456789abcdef"
)

func newProvider(t *testing.T, srv *fakeCF, creds cloudflare.Credentials) *cloudflare.Provider {
	t.Helper()
	return cloudflare.New(zoneID, creds,
		cloudflare.WithEndpoint(srv.URL()),
		cloudflare.WithHTTPClient(srv.Client()))
}

func goodCreds() cloudflare.Credentials {
	return cloudflare.Credentials{APIToken: testToken}
}

// TestCloudflarePassesConformance drives the full present -> validate -> cleanup ->
// assert-fails-after cycle through the shared DNS-01 conformance harness, against the
// token-verifying double. Cleanup is asserted, not just issuance.
func TestCloudflarePassesConformance(t *testing.T) {
	srv := newFakeCF(testToken)
	defer srv.Close()
	p := newProvider(t, srv, goodCreds())

	if err := acme.ConformDNSProvider(context.Background(), p, srv); err != nil {
		t.Fatalf("Cloudflare provider failed DNS-01 conformance: %v", err)
	}
	if srv.Calls() == 0 {
		t.Fatal("conformance ran but the double served no authenticated calls")
	}
}

// TestPresentCleanupIdempotent proves a retried challenge orphans no records (AN-5):
// presenting twice yields exactly one record, and cleaning up twice (the second time
// the record is already gone) still succeeds and leaves the zone empty.
func TestPresentCleanupIdempotent(t *testing.T) {
	srv := newFakeCF(testToken)
	defer srv.Close()
	p := newProvider(t, srv, goodCreds())
	ctx := context.Background()
	const name, value = "_acme-challenge.example.com", "token-digest-value"

	for i := 0; i < 2; i++ {
		if err := p.PresentTXT(ctx, name, value); err != nil {
			t.Fatalf("present #%d: %v", i+1, err)
		}
	}
	if got := srv.Records(name); len(got) != 1 || got[0] != value {
		t.Fatalf("after idempotent present, records = %v, want exactly [%q]", got, value)
	}
	for i := 0; i < 2; i++ {
		if err := p.CleanupTXT(ctx, name, value); err != nil {
			t.Fatalf("cleanup #%d (must be idempotent): %v", i+1, err)
		}
	}
	if got := srv.Records(name); len(got) != 0 {
		t.Fatalf("after cleanup, records = %v, want none", got)
	}
}

// TestBadTokenRejected: a wrong token must fail closed at the auth check (the double
// verifies the bearer token like the real API), not silently succeed.
func TestBadTokenRejected(t *testing.T) {
	srv := newFakeCF(testToken)
	defer srv.Close()
	p := newProvider(t, srv, cloudflare.Credentials{APIToken: "wrong-token"})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("present with a wrong token succeeded; bearer auth was not enforced")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("want a 403 auth rejection, got: %v", err)
	}
}

// TestCredentialsNeverLogged (AN-8): a returned error must never leak the API token,
// even on the failure path.
func TestCredentialsNeverLogged(t *testing.T) {
	srv := newFakeCF(testToken)
	defer srv.Close()
	const secret = "ultra-secret-api-token"
	p := newProvider(t, srv, cloudflare.Credentials{APIToken: secret})

	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the mismatched token")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the API token: %v", err)
	}
}

// TestErrorBodyBoundIsCloudhttps proves the provider's non-2xx error body is bounded
// by the SHARED cloudhttp knob, not a bespoke per-provider literal (CODE-006): the
// upstream returns a >MaxErrorBytes error body, and the error the provider surfaces is
// truncated to exactly cloudhttp.MaxErrorBytes. This is the "single bound change
// reflects in a provider" acceptance — lowering cloudhttp.MaxErrorBytes changes what
// cloudflare (and every other provider) observes, because the read is now central.
func TestErrorBodyBoundIsCloudhttps(t *testing.T) {
	huge := strings.Repeat("E", cloudhttp.MaxErrorBytes*3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, huge)
	}))
	defer srv.Close()

	p := cloudflare.New(zoneID, goodCreds(),
		cloudflare.WithEndpoint(srv.URL), cloudflare.WithHTTPClient(srv.Client()))

	// PresentTXT first LISTs (GET) — that is the call that hits the 502 here.
	err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("expected an error from the 502 upstream")
	}
	// The provider wraps cloudhttp's bounded body in "cloudflare: status 502: <body>".
	// The body portion must be capped at the shared cloudhttp.MaxErrorBytes.
	msg := err.Error()
	if !strings.Contains(msg, "502") {
		t.Fatalf("error should carry the upstream status: %v", err)
	}
	bodyLen := strings.Count(msg, "E")
	if bodyLen > cloudhttp.MaxErrorBytes {
		t.Fatalf("error body = %d 'E's, exceeds the shared cloudhttp.MaxErrorBytes cap %d — the bound is not centrally applied (CODE-006)", bodyLen, cloudhttp.MaxErrorBytes)
	}
	if bodyLen == 0 {
		t.Fatal("error carried no body snippet; the shared bounded read did not run")
	}
}

// TestCapabilitiesAreLeastPrivilege: the provider grants only net.dial, scoped to the
// Cloudflare API host, and nothing else (the connector-SDK least-privilege rule).
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := newFakeCF(testToken)
	defer srv.Close()
	p := newProvider(t, srv, goodCreds())
	g := p.Capabilities()

	if !g.Has(pluginhost.CapNetDial) {
		t.Error("provider must declare net.dial")
	}
	if g.Has(pluginhost.CapFSRead) || g.Has(pluginhost.CapFSWrite) {
		t.Error("provider must not declare filesystem capabilities")
	}
	host := mustHost(t, srv.URL())
	if !g.Allows(pluginhost.CapNetDial, host) {
		t.Errorf("net.dial grant should allow the Cloudflare host %q", host)
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example.com") {
		t.Error("net.dial grant must be scoped to the Cloudflare host only")
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Host
}

// --- fakeCF: a faithful in-process double of the Cloudflare DNS Records API ---------
//
// It verifies the Authorization bearer token the way the real service does (rejecting a
// mismatch with a 403 JSON error so a missing/wrong-header bug in the provider is
// caught here), implements the list (GET, filtered by name and, when present, content),
// create (POST, assigning an incrementing string id), and delete (DELETE by id), and
// serves the published TXT records back via LookupTXT (satisfying acme.Resolver) so the
// DNS-01 conformance harness can validate end-to-end. Cloudflare TXT content is the raw
// value (not quoted), so LookupTXT returns it verbatim. No crypto/* (AN-3) — bearer
// auth needs none.

type storedRecord struct {
	id      string
	content string
}

type fakeCF struct {
	srv   *httptest.Server
	token string

	mu      sync.Mutex
	records map[string][]storedRecord // record name -> stored records
	nextID  int
	calls   int
}

func newFakeCF(token string) *fakeCF {
	s := &fakeCF{
		token:   token,
		records: map[string][]storedRecord{},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *fakeCF) URL() string { return s.srv.URL }

func (s *fakeCF) Client() *http.Client { return s.srv.Client() }

func (s *fakeCF) Close() { s.srv.Close() }

// Calls is the number of authenticated requests served.
func (s *fakeCF) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Records returns the TXT contents currently published for name (raw, unquoted).
func (s *fakeCF) Records(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.records[name] {
		out = append(out, r.content)
	}
	return out
}

// LookupTXT satisfies acme.Resolver, returning the published contents for name so the
// DNS-01 validator can read back what the provider wrote.
func (s *fakeCF) LookupTXT(_ context.Context, name string) ([]string, error) {
	return s.Records(name), nil
}

func (s *fakeCF) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		s.fail(w, http.StatusForbidden, "invalid api token")
		return
	}

	s.mu.Lock()
	s.calls++
	s.mu.Unlock()

	// Routes:
	//   GET    /zones/{zone}/dns_records?type=TXT&name=&content=
	//   POST   /zones/{zone}/dns_records
	//   DELETE /zones/{zone}/dns_records/{id}
	const marker = "/dns_records"
	idx := strings.Index(r.URL.Path, marker)
	if idx < 0 {
		s.fail(w, http.StatusNotFound, "not found")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path[idx+len(marker):], "/")

	switch r.Method {
	case http.MethodGet:
		s.handleList(w, r)
	case http.MethodPost:
		s.handleCreate(w, r)
	case http.MethodDelete:
		s.handleDelete(w, rest)
	default:
		s.fail(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *fakeCF) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("name")
	content := q.Get("content")

	s.mu.Lock()
	var matches []txtJSON
	for _, rec := range s.records[name] {
		if content != "" && rec.content != content {
			continue
		}
		matches = append(matches, txtJSON{
			ID:      rec.id,
			Type:    "TXT",
			Name:    name,
			Content: rec.content,
		})
	}
	s.mu.Unlock()

	s.ok(w, map[string]any{"success": true, "result": matches})
}

func (s *fakeCF) handleCreate(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var rec txtJSON
	if err := json.Unmarshal(body, &rec); err != nil {
		s.fail(w, http.StatusBadRequest, "malformed record")
		return
	}
	if !strings.EqualFold(rec.Type, "TXT") {
		s.fail(w, http.StatusBadRequest, "unsupported record type")
		return
	}

	s.mu.Lock()
	s.nextID++
	id := "rec-" + strconv.Itoa(s.nextID)
	s.records[rec.Name] = append(s.records[rec.Name], storedRecord{id: id, content: rec.Content})
	s.mu.Unlock()

	rec.ID = id
	s.ok(w, map[string]any{"success": true, "result": rec})
}

func (s *fakeCF) handleDelete(w http.ResponseWriter, id string) {
	s.mu.Lock()
	for name, recs := range s.records {
		kept := recs[:0]
		for _, rec := range recs {
			if rec.id == id {
				continue
			}
			kept = append(kept, rec)
		}
		if len(kept) == 0 {
			delete(s.records, name)
		} else {
			s.records[name] = kept
		}
	}
	s.mu.Unlock()

	s.ok(w, map[string]any{"success": true, "result": map[string]string{"id": id}})
}

func (s *fakeCF) ok(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

// fail mirrors a Cloudflare error envelope. It deliberately never echoes the token, so
// surfacing this body as the provider's error text cannot leak credentials (AN-8).
func (s *fakeCF) fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"errors":  []map[string]any{{"code": status, "message": msg}},
	})
}

// txtJSON is the wire shape the double reads and writes; Content is the raw value.
type txtJSON struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}
