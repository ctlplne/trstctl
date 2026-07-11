// SPDX-License-Identifier: MPL-2.0

package gcpcas

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestHTTPAPICallsCASCreateCertificate(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/projects/p/locations/l/caPools/pool/certificates" {
			t.Fatalf("request = %s %s", req.Method, req.URL.String())
		}
		if req.URL.Query().Get("certificateId") != "trstctl-stable" || req.URL.Query().Get("requestId") != "request-stable" {
			t.Fatalf("query = %v", req.URL.Query())
		}
		if req.Header.Get("Authorization") != "Bearer oauth-token" {
			t.Fatalf("authorization = %q", req.Header.Get("Authorization"))
		}
		body := `{"name":"cert","pemCertificate":"leaf","pemCertificateChain":["chain"]}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	api, err := NewHTTPAPI(HTTPConfig{Endpoint: "https://privateca.googleapis.com", BearerToken: []byte("oauth-token"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	got, err := api.CreateCertificate(context.Background(), CreateCertificateInput{
		Parent: "projects/p/locations/l/caPools/pool", CertificateID: "trstctl-stable", RequestID: "request-stable", PemCSR: []byte("csr"), Lifetime: 90 * time.Second,
	})
	if err != nil || got.PemCertificate != "leaf" || len(got.PemCertificateChain) != 1 {
		t.Fatalf("CreateCertificate = %+v, %v", got, err)
	}
	api.Destroy()
	for _, value := range api.token {
		if value != 0 {
			t.Fatal("Destroy left OAuth token bytes in memory")
		}
	}
}

func TestProviderIDsDeriveFromIdempotencyKey(t *testing.T) {
	key := "00112233445566778899aabbccddeeff"
	certA, requestA, err := providerIDs(key)
	if err != nil {
		t.Fatal(err)
	}
	certB, requestB, err := providerIDs(key)
	if err != nil {
		t.Fatal(err)
	}
	if certA != certB || requestA != requestB || certA != "trstctl-00112233445566778899aabb" || requestA != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("provider IDs = %q/%q then %q/%q", certA, requestA, certB, requestB)
	}
}
