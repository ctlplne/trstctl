// SPDX-License-Identifier: BUSL-1.1

package gcpcas

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/ca"
)

// A164: CAS revocation lists the pool by hex serial, then POSTs :revoke on the
// certificate's resource name with the reason and a request id; a certificate
// CAS lists as revoked is not revoked again, and CAS's already-revoked answer
// maps to ErrAlreadyRevoked.
func TestHTTPAPIRevokeWire(t *testing.T) {
	const pool = "projects/p/locations/l/caPools/pool"
	revoked := false
	var calls []string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls = append(calls, req.Method+" "+req.URL.Path)
		if req.Header.Get("Authorization") != "Bearer oauth-token" {
			t.Fatalf("Authorization = %q", req.Header.Get("Authorization"))
		}
		body := `{}`
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v1/"+pool+"/certificates":
			if got := req.URL.Query().Get("filter"); got != `certificate_description.subject_description.hex_serial_number = "0a1b"` {
				t.Fatalf("filter = %q", got)
			}
			details := ``
			if revoked {
				details = `,"revocationDetails":{"revocationState":"SUPERSEDED"}`
			}
			body = `{"certificates":[{"name":"` + pool + `/certificates/c1"` + details + `}]}`
		case req.Method == http.MethodPost && req.URL.Path == "/v1/"+pool+"/certificates/c1:revoke":
			raw, _ := io.ReadAll(req.Body)
			var sent map[string]string
			if err := json.Unmarshal(raw, &sent); err != nil || sent["reason"] != "SUPERSEDED" || sent["requestId"] == "" {
				t.Fatalf("revoke body %s", raw)
			}
			if revoked {
				return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{"error":{"status":"FAILED_PRECONDITION","message":"Certificate is already revoked."}}`))}, nil
			}
			revoked = true
		default:
			t.Fatalf("unexpected %s %s", req.Method, req.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	api, err := NewHTTPAPI(HTTPConfig{Endpoint: "https://privateca.googleapis.com", BearerToken: []byte("oauth-token"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer api.Destroy()
	p := New(Config{Name: "gcp-cas", CaPool: pool}, api)
	if err := p.Revoke(context.Background(), ca.RevokeRequest{Serial: "0A:1B", ReasonCode: 4}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := p.Revoke(context.Background(), ca.RevokeRequest{Serial: "0a1b", ReasonCode: 4}); err != nil {
		t.Fatalf("retried revoke: %v", err)
	}
	if want := []string{"GET /v1/" + pool + "/certificates", "POST /v1/" + pool + "/certificates/c1:revoke", "GET /v1/" + pool + "/certificates"}; strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	if err := api.RevokeCertificate(context.Background(), pool+"/certificates/c1", "SUPERSEDED", "req-2"); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("revoking a revoked certificate = %v, want ErrAlreadyRevoked", err)
	}
}
