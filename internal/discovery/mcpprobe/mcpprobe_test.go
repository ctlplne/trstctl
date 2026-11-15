// SPDX-License-Identifier: BUSL-1.1

package mcpprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

// fakeServer answers initialize like an MCP server would, as configured, and
// records what the probe sent.
type fakeServer struct {
	mu       sync.Mutex
	requests []string
	headers  []http.Header
	sse      bool
	version  string
	auth     bool
	ts       *httptest.Server
}

func newFake(t *testing.T, configure func(*fakeServer)) *fakeServer {
	t.Helper()
	f := &fakeServer{version: "1.0.0"}
	if configure != nil {
		configure(f)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"resource":%q,"authorization_servers":["https://login.example.test/tenant"],"scopes_supported":["issues:read","issues:write"]}`, f.ts.URL+"/mcp")
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		switch {
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
			return
		case f.auth:
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope="issues:read"`, f.ts.URL+"/.well-known/oauth-protected-resource/mcp"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var msg struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(body, &msg) != nil || msg.Method != "initialize" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Mcp-Session-Id", "session-1")
		result := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"issues","version":%q}}}`, f.version)
		if f.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", result)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, result)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		http.NotFound(w, r)
	})
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeServer) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.headers = append(f.headers, r.Header.Clone())
}

func (f *fakeServer) seen() ([]string, []http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...), append([]http.Header(nil), f.headers...)
}

// TestTheProbeFindsAnOpenMCPServerAndEndsItsSessionP7 (A20): an MCP server that
// answers initialize without a credential is found with its name, version and
// protocol, as JSON or as an event stream, and the session it opened is ended.
func TestTheProbeFindsAnOpenMCPServerAndEndsItsSessionP7(t *testing.T) {
	for _, sse := range []bool{false, true} {
		f := newFake(t, func(f *fakeServer) { f.sse = sse })
		p := &Prober{Approved: loopback}
		obs, found, err := p.Probe(context.Background(), f.ts.URL)
		if err != nil || !found {
			t.Fatalf("sse=%v: found=%v err=%v", sse, found, err)
		}
		if obs.Auth != AuthNone || obs.ServerName != "issues" || obs.ServerVersion != "1.0.0" || obs.ProtocolVersion != "2025-06-18" ||
			obs.Endpoint != f.ts.URL+"/mcp" || obs.Transport != "streamable-http" {
			t.Fatalf("sse=%v: observation = %+v", sse, obs)
		}
		requests, _ := f.seen()
		if strings.Join(requests, ",") != "POST /mcp,DELETE /mcp" {
			t.Fatalf("sse=%v: requests = %v, want the initialize and the session's end only", sse, requests)
		}
	}
}

// TestTheProbeRecordsOAuthRequirementsWithoutCredentialsP7 (A20, A22): a server
// that requires OAuth is recorded with its protected resource metadata, its
// authorization servers and scopes; the probe sent no credential and records no
// credential value.
func TestTheProbeRecordsOAuthRequirementsWithoutCredentialsP7(t *testing.T) {
	f := newFake(t, func(f *fakeServer) { f.auth = true })
	p := &Prober{Approved: loopback}
	obs, found, err := p.Probe(context.Background(), f.ts.URL)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if obs.Auth != AuthOAuth || obs.ResourceMetadataURL != f.ts.URL+"/.well-known/oauth-protected-resource/mcp" ||
		obs.Resource != f.ts.URL+"/mcp" || len(obs.AuthorizationServers) != 1 || len(obs.ScopesSupported) != 2 || obs.ServerName != "" {
		t.Fatalf("observation = %+v", obs)
	}
	_, headers := f.seen()
	for _, h := range headers {
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
			t.Fatalf("the probe sent a credential: %v", h)
		}
	}
	raw, _ := json.Marshal(obs)
	for _, forbidden := range []string{"token", "secret", "password", "Bearer"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the observation carries %q: %s", forbidden, raw)
		}
	}
}

// TestTheProbeTouchesOnlyApprovedRangesP7 (A22): a target outside the approved
// ranges is refused before any connection, and a name that resolves outside them
// is refused when it is dialed; the server sees nothing.
func TestTheProbeTouchesOnlyApprovedRangesP7(t *testing.T) {
	f := newFake(t, nil)
	p := &Prober{Approved: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	if _, found, err := p.Probe(context.Background(), f.ts.URL); found || !errors.Is(err, ErrNotApproved) {
		t.Fatalf("an address outside the ranges = found=%v err=%v", found, err)
	}
	byName := strings.Replace(f.ts.URL, "127.0.0.1", "localhost", 1)
	if _, found, err := p.Probe(context.Background(), byName); found || !errors.Is(err, ErrNotApproved) {
		t.Fatalf("a name resolving outside the ranges = found=%v err=%v", found, err)
	}
	if requests, _ := f.seen(); len(requests) != 0 {
		t.Fatalf("the server was touched: %v", requests)
	}
}

// TestARescanWithNoChangeKeepsItsFingerprintP7 (A21): two probes of an unchanged
// server observe the same fingerprint, so the caller writes no new event; a
// changed server observes a new one.
func TestARescanWithNoChangeKeepsItsFingerprintP7(t *testing.T) {
	f := newFake(t, nil)
	p := &Prober{Approved: loopback}
	first, _, _ := p.Probe(context.Background(), f.ts.URL)
	again, _, _ := p.Probe(context.Background(), f.ts.URL)
	if first.Fingerprint() == "" || first.Fingerprint() != again.Fingerprint() {
		t.Fatalf("an unchanged rescan changed the fingerprint: %s vs %s", first.Fingerprint(), again.Fingerprint())
	}
	f.mu.Lock()
	f.version = "1.1.0"
	f.mu.Unlock()
	changed, _, _ := p.Probe(context.Background(), f.ts.URL)
	if changed.Fingerprint() == first.Fingerprint() {
		t.Fatal("a changed server kept its fingerprint")
	}
}

// TestTheProbeIgnoresWhatIsNotMCPAndScansBoundedP7: a plain web server is not
// recorded; Scan probes every target with bounded concurrency and reports only
// the MCP endpoints.
func TestTheProbeIgnoresWhatIsNotMCPAndScansBoundedP7(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>hello</html>") }))
	defer plain.Close()
	p := &Prober{Approved: loopback}
	if _, found, _ := p.Probe(context.Background(), plain.URL); found {
		t.Fatal("a plain web server was recorded as MCP")
	}
	open, protected := newFake(t, nil), newFake(t, func(f *fakeServer) { f.auth = true })
	var inFlight, peak atomic.Int32
	counting := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			next.ServeHTTP(w, r)
		})
	}
	open.ts.Config.Handler = counting(open.ts.Config.Handler)
	var found []Observation
	hostport := func(u string) string { return strings.TrimPrefix(u, "http://") }
	outcomes := 0
	if err := p.Scan(context.Background(), []string{hostport(open.ts.URL), hostport(plain.URL), hostport(protected.ts.URL)}, []string{"http"}, 2,
		func(_ string, o Observation) { found = append(found, o) }, func(string, error) { outcomes++ }); err != nil {
		t.Fatal(err)
	}
	if outcomes != 3 {
		t.Fatalf("outcomes = %d, want one per target", outcomes)
	}
	if len(found) != 2 {
		t.Fatalf("found = %+v, want the open and the protected server", found)
	}
	if peak.Load() > 2 {
		t.Fatalf("concurrency peaked at %d", peak.Load())
	}
}
