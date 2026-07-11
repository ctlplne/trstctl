// SPDX-License-Identifier: MPL-2.0

package azurekv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

type existingKeyRoundTripFunc func(*http.Request) (*http.Response, error)

func (f existingKeyRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSignerForExistingManagedHSMKeyUsesJWKAndSignsDigestOnce(t *testing.T) {
	modulus := bytes.Repeat([]byte{0x55}, 256)
	modulus[0] = 0x80 // exactly 2048 bits
	digest := bytes.Repeat([]byte{0x2a}, 32)
	signature := bytes.Repeat([]byte{0x7e}, 256)
	requests := 0
	client := &http.Client{Transport: existingKeyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Header.Get("Authorization") != "Bearer short-lived-token" {
			t.Fatalf("authorization = %q", req.Header.Get("Authorization"))
		}
		if req.URL.Query().Get("api-version") != apiVersion {
			t.Fatalf("api-version = %q", req.URL.Query().Get("api-version"))
		}
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/keys/dod-ca-key/dod-version":
			return existingKeyJSONResponse(req, map[string]any{"key": map[string]any{
				"kid":     "https://managed-hsm.test/keys/dod-ca-key/dod-version",
				"kty":     "RSA-HSM",
				"n":       base64.RawURLEncoding.EncodeToString(modulus),
				"e":       "AQAB",
				"key_ops": []string{"verify", "sign"},
			}}), nil
		case req.Method == http.MethodPost && req.URL.Path == "/keys/dod-ca-key/dod-version/sign":
			var body struct {
				Algorithm string `json:"alg"`
				Value     string `json:"value"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Algorithm != "RS256" {
				t.Fatalf("sign algorithm = %q", body.Algorithm)
			}
			got, err := base64.RawURLEncoding.DecodeString(body.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, digest) {
				t.Fatalf("Azure sign value was changed or double-hashed: %x", got)
			}
			return existingKeyJSONResponse(req, map[string]string{"value": base64.RawURLEncoding.EncodeToString(signature)}), nil
		default:
			t.Fatalf("unexpected Azure request: %s %s", req.Method, req.URL)
			return nil, nil
		}
	})}
	backend := New("https://managed-hsm.test", Credentials{BearerToken: []byte("short-lived-token")},
		WithHTTPClient(client))
	signer, err := backend.SignerForKey(context.Background(), "dod-ca-key", "dod-version")
	if err != nil {
		t.Fatal(err)
	}
	if signer.Public().Algorithm != crypto.RSA2048 {
		t.Fatalf("public algorithm = %q", signer.Public().Algorithm)
	}
	got, err := signer.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, signature) {
		t.Fatalf("signature = %x", got)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want GET key + POST sign", requests)
	}

	backend.Destroy()
	if backend.token != nil {
		t.Fatal("bearer token buffer survived Destroy")
	}
}

func existingKeyJSONResponse(req *http.Request, value any) *http.Response {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(encoded)),
		Request:    req,
	}
}
