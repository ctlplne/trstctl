// SPDX-License-Identifier: MPL-2.0

package azurekv

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestHTTPAPIDrivesCertificateOperation(t *testing.T) {
	var paths []string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.Method+" "+req.URL.Path)
		if req.Header.Get("Authorization") != "Bearer aad-token" || req.URL.Query().Get("api-version") != keyVaultAPIVersion {
			t.Fatalf("auth/version = %q / %q", req.Header.Get("Authorization"), req.URL.Query().Get("api-version"))
		}
		var body string
		switch req.Method + " " + req.URL.Path {
		case "PUT /certificates/stable/create":
			body = `{"status":"inProgress"}`
		case "GET /certificates/stable/pending":
			body = `{"status":"completed"}`
		case "GET /certificates/stable":
			body = `{"cer":"` + base64.RawURLEncoding.EncodeToString([]byte("leaf-der")) + `","chain":["` + base64.StdEncoding.EncodeToString([]byte("issuer-der")) + `"]}`
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	api, err := NewHTTPAPI(HTTPConfig{BearerToken: []byte("aad-token"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	op, err := api.CreateCertificate(context.Background(), CreateCertificateInput{
		VaultBaseURL: "https://vault.vault.azure.net", CertificateName: "stable", Subject: "CN=svc.example", DNSNames: []string{"svc.example"}, Csr: []byte("csr"), Lifetime: 90 * 24 * time.Hour,
	})
	if err != nil || op.Status != StatusInProgress {
		t.Fatalf("CreateCertificate = %+v, %v", op, err)
	}
	op, err = api.GetCertificateOperation(context.Background(), "https://vault.vault.azure.net", "stable")
	if err != nil || op.Status != StatusCompleted {
		t.Fatalf("GetCertificateOperation = %+v, %v", op, err)
	}
	cert, err := api.GetCertificate(context.Background(), "https://vault.vault.azure.net", "stable")
	if err != nil || string(cert.Cer) != "leaf-der" || len(cert.Chain) != 1 || string(cert.Chain[0]) != "issuer-der" {
		t.Fatalf("GetCertificate = %+v, %v", cert, err)
	}
	if len(paths) != 3 {
		t.Fatalf("paths = %v", paths)
	}
	api.Destroy()
	for _, value := range api.token {
		if value != 0 {
			t.Fatal("Destroy left bearer bytes in memory")
		}
	}
}

func TestCertificateNameDerivesFromProviderIdempotencyKey(t *testing.T) {
	b := &backend{cfg: Config{CertificatePrefix: "trstctl"}}
	key := "00112233445566778899aabbccddeeff"
	first, err := b.certificateName(key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.certificateName(key)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first != "trstctl-00112233445566778899aabb" {
		t.Fatalf("names = %q / %q", first, second)
	}
}
