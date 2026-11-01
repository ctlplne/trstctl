// SPDX-License-Identifier: MPL-2.0

package trstctlsign

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type signCall struct {
	Authorization, IdempotencyKey string
	Body                          struct {
		KeyID        string `json:"key_id"`
		ArtifactType string `json:"artifact_type"`
		Digest       []byte `json:"digest"`
	}
}

func newSignServer(t *testing.T, statuses ...int) (*httptest.Server, func() []signCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []signCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/code-signing/sign" {
			http.NotFound(w, r)
			return
		}
		var call signCall
		call.Authorization = r.Header.Get("Authorization")
		call.IdempotencyKey = r.Header.Get("Idempotency-Key")
		_ = json.NewDecoder(r.Body).Decode(&call.Body)
		mu.Lock()
		calls = append(calls, call)
		n := len(calls)
		mu.Unlock()
		status := http.StatusOK
		if n <= len(statuses) {
			status = statuses[n-1]
		}
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"title":"refused","detail":"approval_required:codesign:abc request_id=r1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"algorithm":"ECDSA-P256","signature":"AQID","public_key_der":"BAU="}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []signCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]signCall(nil), calls...)
	}
}

func digest(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// A retry after a busy server reuses the request's idempotency key, so trstctl
// answers with the first signature rather than signing twice.
func TestSignDigestRetriesWithTheSameIdempotencyKey(t *testing.T) {
	srv, calls := newSignServer(t, http.StatusServiceUnavailable)
	client := &Client{BaseURL: srv.URL, Token: "tok-a", HTTP: srv.Client()}
	sig, err := client.SignDigest(context.Background(), "release", "oci-image", digest(7))
	if err != nil || sig.Algorithm != "ECDSA-P256" || !bytes.Equal(sig.Signature, []byte{1, 2, 3}) {
		t.Fatalf("SignDigest = %+v, %v", sig, err)
	}
	got := calls()
	if len(got) != 2 || got[0].IdempotencyKey == "" || got[0].IdempotencyKey != got[1].IdempotencyKey {
		t.Fatalf("calls = %+v, want one retry with the same idempotency key", got)
	}
	if got[1].Authorization != "Bearer tok-a" || got[1].Body.KeyID != "release" || got[1].Body.ArtifactType != "oci-image" || !bytes.Equal(got[1].Body.Digest, digest(7)) {
		t.Fatalf("request = %+v", got[1])
	}
}

// Running the tool again for the same digest reuses the key — the approval
// trstctl bound to it is consumed — while another credential or another
// digest gets its own.
func TestSignDigestKeyIsStablePerCredentialAndRequest(t *testing.T) {
	srv, calls := newSignServer(t)
	a := &Client{BaseURL: srv.URL, Token: "tok-a", HTTP: srv.Client()}
	b := &Client{BaseURL: srv.URL, Token: "tok-b", HTTP: srv.Client()}
	for _, step := range []struct {
		c *Client
		d []byte
	}{{a, digest(1)}, {a, digest(1)}, {b, digest(1)}, {a, digest(2)}} {
		if _, err := step.c.SignDigest(context.Background(), "release", "oci-image", step.d); err != nil {
			t.Fatal(err)
		}
	}
	got := calls()
	if got[0].IdempotencyKey != got[1].IdempotencyKey {
		t.Fatal("the same request from the same credential changed its idempotency key")
	}
	if got[2].IdempotencyKey == got[0].IdempotencyKey || got[3].IdempotencyKey == got[0].IdempotencyKey {
		t.Fatalf("keys collided across credentials or digests: %+v", got)
	}
	if _, err := a.SignDigest(context.Background(), "release", "oci-image", []byte("short")); err == nil {
		t.Fatal("a digest that is not SHA-256 was sent")
	}
}

// A refusal — a missing permission or an approval that is pending or denied —
// stops at once and carries trstctl's reason; it is not retried.
func TestSignDigestRefusalIsDeniedAndNotRetried(t *testing.T) {
	srv, calls := newSignServer(t, http.StatusForbidden, http.StatusForbidden, http.StatusForbidden)
	client := &Client{BaseURL: srv.URL, Token: "tok-a", HTTP: srv.Client()}
	_, err := client.SignDigest(context.Background(), "release", "oci-image", digest(3))
	var refused *APIError
	if !errors.As(err, &refused) || !refused.Denied() || refused.Status != http.StatusForbidden ||
		refused.Message != "approval_required:codesign:abc request_id=r1" {
		t.Fatalf("err = %v", err)
	}
	if n := len(calls()); n != 1 {
		t.Fatalf("a refusal was retried: %d calls", n)
	}
	if (&APIError{Status: http.StatusNotFound}).Denied() {
		t.Fatal("a missing key reads as a denial")
	}
}

func TestKeyCertificateReturnsTheChainLeafFirst(t *testing.T) {
	leaf, root := []byte("leaf-der"), []byte("root-der")
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/v1/code-signing/keys/release%2Fkey/certificate" || r.Header.Get("Authorization") != "Bearer tok" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"key_id": "release/key", "algorithm": "ECDSA-P256", "chain_pem": chain, "code_signing_eku": true})
	}))
	defer srv.Close()
	cert, err := (&Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}).KeyCertificate(context.Background(), "release/key")
	if err != nil {
		t.Fatal(err)
	}
	der := cert.ChainDER()
	if len(der) != 2 || !bytes.Equal(der[0], leaf) || !bytes.Equal(der[1], root) || !cert.CodeSigningEKU {
		t.Fatalf("chain = %q", der)
	}
}

func TestFromEnv(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("tok-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	badCA := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRSTCTL_URL", "")
	t.Setenv("TRSTCTL_TOKEN", "")
	t.Setenv("TRSTCTL_TOKEN_FILE", "")
	t.Setenv("TRSTCTL_CA_FILE", "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("no URL or token accepted")
	}
	t.Setenv("TRSTCTL_URL", "https://trstctl.example/")
	t.Setenv("TRSTCTL_TOKEN_FILE", tokenFile)
	c, err := FromEnv()
	if err != nil || c.Token != "tok-file" || c.BaseURL != "https://trstctl.example" {
		t.Fatalf("FromEnv = %+v, %v", c, err)
	}
	t.Setenv("TRSTCTL_CA_FILE", badCA)
	if _, err := FromEnv(); err == nil {
		t.Fatal("a CA file without a certificate was accepted")
	}
	t.Setenv("TRSTCTL_CA_FILE", "")
	t.Setenv("TRSTCTL_URL", "ftp://trstctl.example")
	if _, err := FromEnv(); err == nil {
		t.Fatal("a non-HTTP URL was accepted")
	}
}
