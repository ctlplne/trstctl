// SPDX-License-Identifier: BUSL-1.1
package bearerhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestFixedOriginBearerReadsRefuseRedirectsWritesAndBadTLSA264(t *testing.T) {
	token := []byte("owned-metadata-reader")
	defer secret.Wipe(token)
	var borrowed, escaped atomic.Int32
	borrow := func(_ context.Context, use func([]byte) error) error { borrowed.Add(1); return use(token) }
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1) }))
	defer foreign.Close()
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := append([]byte("Bearer "), token...)
		defer secret.Wipe(want)
		if !bytes.Equal([]byte(r.Header.Get("Authorization")), want) {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", foreign.URL)
			w.WriteHeader(302)
			return
		}
		_, _ = w.Write([]byte(`{"id":"owned-public-id"}`))
	}))
	defer sink.Close()
	c, err := New(Config{Endpoint: sink.URL, AllowInsecureLoopback: true, UseToken: borrow})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := c.ReadJSON(t.Context(), http.MethodGet, "/v1/metadata", nil, &out); err != nil || out.ID != "owned-public-id" {
		t.Fatal("native metadata read failed", err)
	}
	before := borrowed.Load()
	for _, path := range []string{foreign.URL, "//another.example/metadata", "/v1/../unexpected", "/v1/%2e%2e/unexpected"} {
		if c.ReadJSON(t.Context(), http.MethodGet, path, nil, &out) == nil {
			t.Fatal("cross-origin path admitted")
		}
	}
	if c.ReadJSON(t.Context(), http.MethodDelete, "/v1/metadata", nil, &out) == nil || c.ReadJSON(t.Context(), http.MethodPost, "/v1/deleteKey", nil, &out) == nil || borrowed.Load() != before {
		t.Fatal("unapproved operation borrowed authority")
	}
	var status *StatusError
	if err := c.ReadJSON(t.Context(), http.MethodGet, "/redirect", nil, &out); !errors.As(err, &status) || status.Status != 302 || escaped.Load() != 0 {
		t.Fatal("credential-bearing redirect followed")
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS reached handler") }))
	defer tls.Close()
	c, err = New(Config{Endpoint: tls.URL, PrivateEgressCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, UseToken: borrow})
	if err != nil {
		t.Fatal(err)
	}
	before = borrowed.Load()
	if c.ReadJSON(t.Context(), http.MethodGet, "/v1/metadata", nil, &out) == nil || borrowed.Load() != before {
		t.Fatal("untrusted TLS borrowed or exposed the token")
	}

	publicPEM := []byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(tls.Certificate().Raw) + "\n-----END CERTIFICATE-----\n")
	pinned := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"id":"pinned-origin"}`)) }))
	defer pinned.Close()
	// httptest servers use the same public test certificate; no key is exported.
	c, err = New(Config{Endpoint: pinned.URL, CAPEM: publicPEM, PrivateEgressCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, UseToken: borrow})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ReadJSON(t.Context(), http.MethodGet, "/v1/metadata", nil, &out); err != nil || out.ID != "pinned-origin" {
		t.Fatal("pinned HTTPS metadata read failed", err)
	}
	if _, err := New(Config{Endpoint: sink.URL, UseToken: borrow}); err == nil {
		t.Fatal("plaintext origin enabled without opt-in")
	}
}
func TestPrivateReaderFileAndTokenFramingA264(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority")
	if err := os.WriteFile(path, []byte("owned-reader\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := FileToken(path)(t.Context(), func(raw []byte) error {
		if !bytes.Equal(raw, []byte("owned-reader")) {
			t.Fatal("unexpected private file bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, []byte("reader\r\nX-Injected: yes"), []byte("contains space"), []byte("invalid=padding"), []byte("==="), bytes.Repeat([]byte("x"), (32<<10)+1)} {
		if ValidToken(raw) {
			t.Fatal("unsafe token framing admitted")
		}
	}
	if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- negative fixture proves a public token file is refused (CWE-732)
		t.Fatal(err)
	}
	if FileToken(path)(t.Context(), func([]byte) error { t.Fatal("public reader file borrowed"); return nil }) == nil {
		t.Fatal("public reader file admitted")
	}
}
func TestBoundedMetadataJSONRejectsAmbiguousAndTrailingObjectsA264(t *testing.T) {
	for _, raw := range []string{`{"id":"first","id":"second"}`, `{"id":"first","ID":"second"}`, `{"nested":{"id":1,"ID":2}}`, `{} {}`, `[1,]`} {
		var out any
		if DecodeJSON([]byte(raw), &out) == nil {
			t.Fatal("ambiguous native metadata admitted")
		}
	}
	var out struct {
		ID string `json:"id"`
	}
	if DecodeJSON([]byte(`{"id":"public-id","secretText":"discarded-fixture-value"}`), &out) != nil || out.ID != "public-id" {
		t.Fatal("typed public field decoding failed")
	}
}
func FuzzCloudMetadataJSONA264(f *testing.F) {
	f.Add([]byte(`{"id":"public","nested":[1,2]}`))
	f.Add([]byte(`{"id":1,"ID":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxResponse {
			return
		}
		var out struct {
			ID string `json:"id"`
		}
		_ = DecodeJSON(raw, &out)
	})
}
func FuzzCloudBearerFramingA264(f *testing.F) {
	f.Add([]byte("owned-reader"))
	f.Add([]byte("owned\r\ninjected"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if !ValidToken(raw) {
			return
		}
		if len(raw) == 0 || len(raw) > 32<<10 || raw[0] == '=' || bytes.ContainsAny(raw, "\r\n\t ") {
			t.Fatal("unsafe bearer accepted")
		}
	})
}
