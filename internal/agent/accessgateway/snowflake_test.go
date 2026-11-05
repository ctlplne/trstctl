// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestSnowflakeJWTBoundsExpiryAndRejectsUnsupportedKeys(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(25 * time.Second)
	for _, algorithm := range []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256} {
		key, err := crypto.GenerateLockedKey(algorithm)
		if err != nil {
			t.Fatal(err)
		}
		pem, err := key.PrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := snowflakeJWT("served-lab", "scoped_user", pem, now, deadline)
		secret.Wipe(pem)
		if algorithm != crypto.RSA2048 {
			key.Destroy()
			if err == nil {
				secret.Wipe(raw)
				t.Fatal("Snowflake accepted a non-RSA key")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := crypto.PublicJWK(key.Public(), "")
		key.Destroy()
		if err != nil {
			t.Fatal(err)
		}
		payload, err := crypto.VerifyJWTBytes(raw, crypto.JWKS{Keys: []crypto.JWK{jwk}})
		secret.Wipe(raw)
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Exp int64
			Sub string
		}
		if json.Unmarshal(payload, &claims) != nil || claims.Exp != deadline.Unix() || claims.Sub != "SERVED-LAB.SCOPED_USER" {
			t.Fatal("JWT exceeded or changed session authority")
		}
		secret.Wipe(payload)
	}
	if raw, err := snowflakeJWT("account", "user", []byte("invalid key"), now, now); err == nil {
		secret.Wipe(raw)
		t.Fatal("expired Snowflake session created auth")
	}
}

func TestSnowflakeRoundTripReplacesAuthWithoutChangingBody(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pem, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	held, err := secret.NewFrom(pem)
	secret.Wipe(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Destroy()
	jwk, err := crypto.PublicJWK(key.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	exact := []byte(`{"statement":"SELECT 1","bindings":{"1":{"type":"TEXT","value":"owned-value"}}}`)
	var accepted atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		defer secret.Wipe(raw)
		payload, err := crypto.VerifyJWTBytes(raw, crypto.JWKS{Keys: []crypto.JWK{jwk}})
		secret.Wipe(payload)
		body, _ := io.ReadAll(r.Body)
		defer secret.Wipe(body)
		accepted.Store(err == nil && bytes.Equal(body, exact) && r.Header.Get("X-Snowflake-Authorization-Token-Type") == "KEYPAIR_JWT" && r.Header.Get("Cookie") == "" && r.Header.Get("Forwarded") == "" && r.Header.Get("Idempotency-Key") == "")
		if !accepted.Load() {
			http.Error(w, "auth or body changed", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"code":"090001"}`))
	}))
	defer target.Close()
	request := httptest.NewRequest(http.MethodPost, "http://client.example/api/v2/statements?requestId=owned", bytes.NewReader(exact))
	request.Header.Set("Authorization", "Bearer client-auth-canary")
	request.Header.Set("Cookie", "session=client-auth-canary")
	request.Header.Set("Forwarded", "host=untrusted")
	request.Header.Set("Idempotency-Key", "client-key")
	response, err := snowflakeRoundTrip(context.Background(), request, exact, httpUpstream{URL: target.URL}, "served-lab", "scoped_user", held, time.Now().Add(time.Minute), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !accepted.Load() {
		t.Fatal("target did not authenticate exactly the issued user")
	}
	if request.Header.Get("Authorization") != "Bearer client-auth-canary" {
		t.Fatal("forwarding mutated caller metadata")
	}
	if response, err := snowflakeRoundTrip(context.Background(), request, exact, httpUpstream{URL: "http://192.0.2.10"}, "a", "u", held, time.Now().Add(time.Minute), nil); err == nil {
		_ = response.Body.Close()
		t.Fatal("remote cleartext accepted")
	}
}

func FuzzSnowflakeCredentialEnvelope(f *testing.F) {
	for _, raw := range []string{`{"account":"lab","user":"scoped","private_key":"invalid-key"}`, `{"account":"lab","private_key":"invalid-key"}`, `{}`, `null`} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		credential, err := parseSnowflakeCredential(raw)
		defer secret.Wipe(credential.PrivateKey)
		if !bytes.Equal(raw, before) {
			t.Fatal("credential parser changed input")
		}
		if err == nil && (len(raw) > 64<<10 || len(credential.PrivateKey) == 0 || credential.Account == "" || credential.User == "") {
			t.Fatal("unbounded or incomplete credential accepted")
		}
	})
}

func TestSnowflakeResponseHeaderBoundAndInterim(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	pem, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	held, err := secret.NewFrom(pem)
	secret.Wipe(pem)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Destroy()
	interim := "HTTP/1.1 103 Early Hints\r\n\r\n"
	okReply := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	for _, tc := range []struct {
		name, wire string
		allowed    bool
	}{{"ordinary", okReply, true}, {"early_hints", interim + okReply, true}, {"oversized_headers", "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 65<<10) + "\r\nContent-Length: 0\r\n\r\n", false}, {"interim_flood", strings.Repeat(interim, 8) + okReply, false}, {"upgrade", "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: unknown\r\n\r\n", false}} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				peer, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = peer.Close() }()
				_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
				request, err := http.ReadRequest(bufio.NewReader(peer))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, request.Body)
				_ = request.Body.Close()
				_, _ = io.WriteString(peer, tc.wire)
			}()
			request := httptest.NewRequest(http.MethodGet, "http://client/api/v2/statements/owned", nil)
			response, err := snowflakeRoundTrip(context.Background(), request, nil, httpUpstream{URL: "http://" + listener.Addr().String()}, "served-lab", "scoped", held, time.Now().Add(5*time.Second), nil)
			if response != nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
			<-done
			if (err == nil) != tc.allowed {
				t.Fatalf("response accepted=%v, want %v: %v", err == nil, tc.allowed, err)
			}
		})
	}
}
