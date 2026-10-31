// SPDX-License-Identifier: BUSL-1.1

package awspca

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A164: RevokeCertificate is ACMPrivateCA.RevokeCertificate with AWS's field
// names, and AWS's RequestAlreadyProcessedException maps to ErrAlreadyRevoked.
func TestHTTPAPIRevokeCertificateWire(t *testing.T) {
	processed := false
	var sent map[string]string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Amz-Target") != "ACMPrivateCA.RevokeCertificate" || !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Fatalf("target %q auth %q", req.Header.Get("X-Amz-Target"), req.Header.Get("Authorization"))
		}
		raw, _ := io.ReadAll(req.Body)
		sent = map[string]string{}
		if err := json.Unmarshal(raw, &sent); err != nil {
			t.Fatalf("body %s: %v", raw, err)
		}
		if processed {
			return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"__type":"RequestAlreadyProcessedException","message":"Your request has already been completed."}`))}, nil
		}
		processed = true
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	api, err := NewHTTPAPI(HTTPConfig{Endpoint: "https://pca.example", Region: "us-east-1", AccessKeyID: "AK", SecretAccessKey: []byte("SK"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer api.Destroy()
	in := RevokeCertificateInput{CertificateAuthorityArn: "arn:ca", CertificateSerial: "0a:1b", RevocationReason: "KEY_COMPROMISE"}
	if err := api.RevokeCertificate(context.Background(), in); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if sent["CertificateAuthorityArn"] != "arn:ca" || sent["CertificateSerial"] != "0a:1b" || sent["RevocationReason"] != "KEY_COMPROMISE" {
		t.Fatalf("sent %v", sent)
	}
	if err := api.RevokeCertificate(context.Background(), in); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("second revoke = %v, want ErrAlreadyRevoked", err)
	}
}
