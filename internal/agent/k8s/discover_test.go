// SPDX-License-Identifier: BUSL-1.1

package k8s_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto"
)

const discoverCertPEM = `-----BEGIN CERTIFICATE-----
MIIBjDCCATGgAwIBAgIUbUBdvVyLGrRCJmc3v/XUcPHXkiMwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQZGlzY292ZXJ5LTEudGVzdDAeFw0yNjA1MzAxODA5NTFaFw0z
NjA1MjcxODA5NTFaMBsxGTAXBgNVBAMMEGRpc2NvdmVyeS0xLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS/wgFIHrQZaIbPLJiTFRAw7jskcfmHyR3bK9v4
SA1pf3qDdiQB251mv+nF3qDY23d/fY3C96wgySv56nhoW/N7o1MwUTAdBgNVHQ4E
FgQUagh6v1IAMWknG6X38HDrLuL/bN0wHwYDVR0jBBgwFoAUagh6v1IAMWknG6X3
8HDrLuL/bN0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA6Uv9
Q944+/6g4qbJ1TvNUXdphxwfq+j91btwxC9ENq8CIQDHIBCvC3Hvx4DN08ItES2l
vGsFCZlEd32emYdgZuAgcw==
-----END CERTIFICATE-----
`

// EnumerateCertificates lists TLS Secrets and returns their certificates,
// skipping non-TLS Secrets and decoding the base64 wire form.
func TestEnumerateCertificatesListsTLSSecrets(t *testing.T) {
	crt := base64.StdEncoding.EncodeToString([]byte(discoverCertPEM))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/apps/secrets" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"items":[
		  {"metadata":{"name":"web-tls"},"type":"kubernetes.io/tls","data":{"tls.crt":%q,"tls.key":"a2V5"}},
		  {"metadata":{"name":"db-creds"},"type":"Opaque","data":{"password":"c2VjcmV0"}},
		  {"metadata":{"name":"api-tls"},"type":"kubernetes.io/tls","data":{"tls.crt":%q}}
		]}`, crt, crt)
	}))
	defer srv.Close()

	client := k8s.New(srv.URL, "token", "apps", srv.Client())
	certs, err := client.EnumerateCertificates(context.Background())
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2 (only the TLS secrets): %v", len(certs), keys(certs))
	}
	if _, ok := certs["db-creds"]; ok {
		t.Error("a non-TLS secret must not be discovered")
	}
	want := crypto.SHA256Hex([]byte(discoverCertPEM))
	for name, pem := range certs {
		if crypto.SHA256Hex(pem) != want {
			t.Errorf("secret %s: decoded cert fingerprint mismatch", name)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A cross-namespace inventory lists namespaces and reads each one on its own;
// a namespace the service account may not list is an error for that namespace.
func TestEnumerateCertificatesAcrossNamespaces(t *testing.T) {
	crt := base64.StdEncoding.EncodeToString([]byte(discoverCertPEM))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/namespaces":
			_, _ = fmt.Fprint(w, `{"items":[{"metadata":{"name":"payments"}},{"metadata":{"name":"apps"}},{"metadata":{"name":"locked"}}]}`)
		case "/api/v1/namespaces/apps/secrets":
			_, _ = fmt.Fprintf(w, `{"items":[{"metadata":{"name":"web-tls"},"type":"kubernetes.io/tls","data":{"tls.crt":%q}}]}`, crt)
		case "/api/v1/namespaces/payments/secrets":
			_, _ = fmt.Fprintf(w, `{"items":[{"metadata":{"name":"api-tls"},"type":"kubernetes.io/tls","data":{"tls.crt":%q}}]}`, crt)
		case "/api/v1/namespaces/locked/secrets":
			http.Error(w, `{"reason":"Forbidden"}`, http.StatusForbidden)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	client := k8s.New(srv.URL, "token", "apps", srv.Client())
	namespaces, err := client.ListNamespaces(context.Background())
	if err != nil || len(namespaces) != 3 || namespaces[0] != "apps" || namespaces[2] != "payments" {
		t.Fatalf("namespaces=%v err=%v", namespaces, err)
	}
	certs, err := client.InNamespace("payments").EnumerateCertificates(context.Background())
	if err != nil || len(certs) != 1 {
		t.Fatalf("payments: certs=%v err=%v", keys(certs), err)
	}
	if _, ok := certs["api-tls"]; !ok {
		t.Fatalf("payments inventory missed api-tls: %v", keys(certs))
	}
	if _, err := client.InNamespace("locked").EnumerateCertificates(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a forbidden namespace must fail, not read as empty: %v", err)
	}
}
