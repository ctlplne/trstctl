// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func gcpTestMaterial(t *testing.T) (*gcpGatewayMaterial, crypto.JWK) {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pem, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(pem)
	raw, err := json.Marshal(struct { // #nosec G117 -- owned provider-envelope fixture; private bytes are locked on parse and scratch is wiped (CWE-200)
		Type    string           `json:"type"`
		ID      string           `json:"private_key_id"`
		Subject string           `json:"client_email"`
		Key     secret.JSONBytes `json:"private_key"`
	}{"service_account", "owned-key", "reader@example.iam.gserviceaccount.com", pem})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	if other, err := parseGCPGatewayMaterial(raw, "other@example.iam.gserviceaccount.com"); err == nil {
		other.key.Destroy()
		t.Fatal("foreign service account accepted")
	}
	material, err := parseGCPGatewayMaterial(raw, "reader@example.iam.gserviceaccount.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(material.key.Destroy)
	jwk, err := crypto.PublicJWK(key.Public(), "owned-key")
	if err != nil {
		t.Fatal(err)
	}
	return material, jwk
}
func TestGCPOAuthAssertionBindsSubjectAudienceScopesAndSessionDeadline(t *testing.T) {
	material, jwk := gcpTestMaterial(t)
	now := time.Now().Truncate(time.Second)
	for _, deadline := range []time.Time{now.Add(25 * time.Second), now.Add(2 * time.Hour)} {
		intent := SessionIntent{OAuthTokenEndpoint: (&url.URL{Scheme: "https", Host: "oauth2.googleapis.com", Path: "/token"}).String(), OAuthScopes: []string{"https://www.googleapis.com/auth/devstorage.read_only"}, ExpiresAt: deadline}
		assertion, err := gcpAssertion(material, intent, now)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := crypto.VerifyJWTBytes(assertion, crypto.JWKS{Keys: []crypto.JWK{jwk}})
		secret.Wipe(assertion)
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Iss, Sub, Scope, Aud string
			Iat, Exp             int64
		}
		err = json.Unmarshal(raw, &claims)
		secret.Wipe(raw)
		if err != nil || claims.Iss != material.subject || claims.Sub != "" || claims.Scope != intent.OAuthScopes[0] || claims.Aud != intent.OAuthTokenEndpoint || claims.Iat != now.Unix() || claims.Exp != earliest(deadline, now.Add(time.Hour)).Unix() {
			t.Fatal("OAuth assertion changed reviewed authority or expiry")
		}
	}
	if assertion, err := gcpAssertion(material, SessionIntent{ExpiresAt: now}, now); err == nil {
		secret.Wipe(assertion)
		t.Fatal("expired session signed an assertion")
	}
	material.key.Destroy()
	if assertion, err := gcpAssertion(material, SessionIntent{ExpiresAt: now.Add(time.Minute)}, now); err == nil {
		secret.Wipe(assertion)
		t.Fatal("destroyed session key signed an assertion")
	}
}

func TestGCPOAuthExchangeRejectsUnboundedOrMalformedTokenResponses(t *testing.T) {
	material, _ := gcpTestMaterial(t)
	for _, body := range []string{`{"access_token":"owned-canary","token_type":"Basic","expires_in":20}`, `{"access_token":"owned-canary","token_type":"Bearer","expires_in":0}`, `{"access_token":"owned-canary","token_type":"Bearer","expires_in":3601}`, `{"access_token":"owned\\r\\ncanary","token_type":"Bearer","expires_in":20}`, `{"access_token":"owned\r\ncanary","token_type":"Bearer","expires_in":20}`, `{"access_token":"owned\tcanary","token_type":"Bearer","expires_in":20}`, strings.Repeat("x", 64<<10+1), `{"access_token":"owned-canary","token_type":"Bearer","expires_in":20}`} {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			defer secret.Wipe(raw)
			if r.URL.Path != "/fixed/token" || r.Header.Get("Authorization") != "" || !bytes.Contains(raw, []byte("&assertion=ey")) || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				http.Error(w, "bad token request", 400)
				return
			}
			_, _ = io.WriteString(w, body)
		}))
		intent := SessionIntent{OAuthTokenEndpoint: target.URL + "/fixed/token", OAuthScopes: []string{"https://www.googleapis.com/auth/devstorage.read_only"}, ExpiresAt: time.Now().Add(5 * time.Second)}
		token, expiry, err := gcpExchange(context.Background(), material, intent, nil)
		target.Close()
		valid := body == `{"access_token":"owned-canary","token_type":"Bearer","expires_in":20}`
		if valid {
			if err != nil || expiry.After(intent.ExpiresAt) {
				t.Fatal("valid token did not respect local session deadline")
			}
			if err := token.Use(func(raw []byte) error {
				if !bytes.Equal(raw, []byte("owned-canary")) {
					t.Fatal("token bytes changed")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			token.Destroy()
		} else if err == nil {
			token.Destroy()
			t.Fatal("unsafe OAuth token response accepted")
		}
	}
}
func FuzzGCPGatewayCredentialEnvelope(f *testing.F) {
	f.Add([]byte(`{"type":"service_account","client_email":"reader@example.iam.gserviceaccount.com","private_key_id":"x","private_key":"invalid"}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		material, err := parseGCPGatewayMaterial(raw, "reader@example.iam.gserviceaccount.com")
		if err == nil {
			if material.subject != "reader@example.iam.gserviceaccount.com" || material.key.Len() == 0 {
				t.Fatal("unbound credential")
			}
			material.key.Destroy()
		}
	})
}

func TestGCPRelayReplacesClientAuthAndRefreshesOnlyWithinSession(t *testing.T) {
	material, _ := gcpTestMaterial(t)
	var grants atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		defer secret.Wipe(body)
		if r.URL.Path == "/token" {
			n := grants.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("owned-token-%d", n), "token_type": "Bearer", "expires_in": 1})
			return
		}
		expected := fmt.Sprintf("Bearer owned-token-%d", grants.Load())
		if r.Method != http.MethodPost || r.URL.Path != "/resource" || r.URL.Query().Get("x") != "one two" || len(r.URL.Query()) != 1 || r.Header.Get("Authorization") != expected || r.Header.Get("Cookie") != "" || r.Header.Get("X-Goog-Api-Key") != "" || r.Header.Get("X-Goog-Iam-Authorization-Token") != "" || r.Header.Get("X-Serverless-Authorization") != "" || !bytes.Equal(body, []byte("exact-api-body")) {
			http.Error(w, "authority or request changed", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, "owned-result")
	}))
	defer target.Close()
	var raw []byte
	err := material.key.Use(func(key []byte) error {
		var err error
		raw, err = json.Marshal(struct { // #nosec G117 -- owned provider-envelope fixture; private bytes are locked on parse and scratch is wiped (CWE-200)
			Type    string           `json:"type"`
			ID      string           `json:"private_key_id"`
			Subject string           `json:"client_email"`
			Key     secret.JSONBytes `json:"private_key"`
		}{"service_account", material.id, material.subject, key})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	intent := SessionIntent{OAuthSubject: material.subject, OAuthScopes: []string{"https://www.googleapis.com/auth/devstorage.read_only"}, OAuthTokenEndpoint: target.URL + "/token", UpstreamURL: target.URL, ExpiresAt: time.Now().Add(4 * time.Second)}
	done := make(chan error, 1)
	go func() { done <- serveGCP(ctx, server, raw, intent, nil, nil) }()
	reader := bufio.NewReader(client)
	for n := 1; n <= 2; n++ {
		if n == 2 {
			time.Sleep(1100 * time.Millisecond)
		}
		wire := "POST /resource?x=one+two&access_token=foreign&oauth_token=foreign&key=foreign&api_key=foreign HTTP/1.1\r\nHost: untrusted.example\r\nAuthorization: Bearer foreign\r\nCookie: session=foreign\r\nX-Goog-Api-Key: foreign\r\nX-Goog-Iam-Authorization-Token: foreign\r\nX-Serverless-Authorization: foreign\r\nContent-Length: 14\r\n\r\nexact-api-body"
		if _, err := io.WriteString(client, wire); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != 200 || !bytes.Equal(body, []byte("owned-result")) || grants.Load() != int32(n) {
			t.Fatal("credential-free request or native expiry refresh failed")
		}
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("relay did not stop after connection closure")
	}
}
