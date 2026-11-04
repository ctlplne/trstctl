// SPDX-License-Identifier: MPL-2.0

package trstctl

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A250: the Go SDK makes the same secrets, PKI and revocation calls as the
// Python and Java SDKs, with exact routes and wire shapes, a held
// Idempotency-Key across a retry that honors Retry-After, and secret values
// as bytes in both directions.
func TestSecretsPKIAndRevocationCalls(t *testing.T) {
	const value = "line\n\"quoted\" \\ é ☃ \U0001F512"
	var mu sync.Mutex
	stored := map[string]string{}
	version := map[string]int{}
	keys := map[string][]string{}
	var firstCreate time.Time
	var retriedAfter time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		key := r.Method + " " + r.URL.EscapedPath()
		keys[key] = append(keys[key], r.Header.Get("Idempotency-Key"))
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		reply := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/store":
			// The first attempt is turned away with Retry-After: 1.
			if len(keys[key]) == 1 {
				firstCreate = time.Now()
				w.Header().Set("Retry-After", "1")
				reply(http.StatusServiceUnavailable, map[string]any{"title": "busy"})
				return
			}
			retriedAfter = time.Since(firstCreate)
			name := body["name"].(string)
			stored[name], version[name] = body["value"].(string), 1
			reply(http.StatusCreated, map[string]any{"name": name, "version": 1})
		case r.Method == http.MethodGet && r.URL.EscapedPath() == "/api/v1/secrets/store/app/db%20password":
			reply(http.StatusOK, map[string]any{"name": "app/db password", "version": version["app/db password"], "value": stored["app/db password"]})
		case r.Method == http.MethodPut && r.URL.EscapedPath() == "/api/v1/secrets/store/app/db%20password":
			stored["app/db password"] = body["value"].(string)
			version["app/db password"]++
			reply(http.StatusOK, map[string]any{"name": "app/db password", "version": version["app/db password"]})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/pki":
			if body["common_name"] != "sdk.lab.test" || body["ttl_seconds"].(float64) != 300 {
				reply(http.StatusBadRequest, map[string]any{"title": "bad body"})
				return
			}
			reply(http.StatusCreated, map[string]any{"certificate_id": "c-1", "serial": "0a", "common_name": "sdk.lab.test",
				"certificate": "-----BEGIN CERTIFICATE-----", "private_key": "fixture-key-pem\n"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/certificates/bulk-revoke":
			ids, _ := body["certificate_ids"].([]any)
			if len(ids) != 1 || ids[0] != "c-1" || body["reason"] != "superseded" {
				reply(http.StatusBadRequest, map[string]any{"title": "bad body"})
				return
			}
			reply(http.StatusOK, map[string]any{"total_matched": 1, "total_revoked": 1, "total_skipped": 0, "total_failed": 0,
				"items": []any{map[string]any{"id": "c-1", "status": "revoked"}}})
		default:
			reply(http.StatusNotFound, map[string]any{"title": "no route " + key})
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "token", WithRetry(RetryPolicy{MaxAttempts: 3, BaseDelay: 10 * time.Millisecond, MaxDelay: 5 * time.Second}))
	ctx := t.Context()

	created, err := c.CreateSecret(ctx, "app/db password", []byte(value))
	if err != nil || created.Version != 1 {
		t.Fatalf("create = %+v, %v", created, err)
	}
	if retriedAfter < time.Second {
		t.Fatalf("the retry came %s after a Retry-After: 1", retriedAfter)
	}
	createKeys := keys["POST /api/v1/secrets/store"]
	if len(createKeys) != 2 || createKeys[0] == "" || createKeys[0] != createKeys[1] {
		t.Fatalf("the retry changed or dropped its Idempotency-Key: %q", createKeys)
	}
	got, err := c.GetSecret(ctx, "app/db password")
	if err != nil || !bytes.Equal(got.Value, []byte(value)) || got.Version != 1 {
		t.Fatalf("get = %+v (%q), %v", got, got.Value, err)
	}
	rotated, err := c.RotateSecretKeyed(ctx, "app/db password", []byte("v2"), "rotate-1")
	if err != nil || rotated.Version != 2 || keys["PUT /api/v1/secrets/store/app/db%20password"][0] != "rotate-1" {
		t.Fatalf("rotate = %+v, %v", rotated, err)
	}
	if err := c.DeleteSecret(ctx, "app/db password"); err != nil {
		t.Fatal(err)
	}
	pki, err := c.IssuePKISecret(ctx, "sdk.lab.test", 5*time.Minute)
	if err != nil || pki.CertificateID != "c-1" || string(pki.PrivateKey) != "fixture-key-pem\n" {
		t.Fatalf("pki = %+v, %v", pki, err)
	}
	revoked, err := c.RevokeCertificates(ctx, []string{pki.CertificateID}, "superseded")
	if err != nil || revoked.TotalRevoked != 1 || revoked.Items[0].Status != "revoked" {
		t.Fatalf("revoke = %+v, %v", revoked, err)
	}
	for route, sent := range keys {
		if strings.HasPrefix(route, "GET ") {
			continue
		}
		for _, k := range sent {
			if k == "" {
				t.Fatalf("%s carried no Idempotency-Key", route)
			}
		}
	}
	if _, err := c.RevokeCertificates(ctx, nil, "superseded"); err == nil {
		t.Fatal("revoking nothing was sent")
	}
}

func TestUnquoteSecretMatchesEncodingJSON(t *testing.T) {
	for _, s := range []string{"", "plain", "a\"b\\c/d", "\b\f\n\r\t", "é☃🔒", "\u0001\u001f", "x\U0001F600y"} {
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		got, err := unquoteSecret(raw)
		if err != nil || string(got) != s {
			t.Fatalf("unquote(%s) = %q, %v", raw, got, err)
		}
		encoded, err := secretText(s).MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var back string
		if err := json.Unmarshal(encoded, &back); err != nil || back != s {
			t.Fatalf("secretText(%q) = %s", s, encoded)
		}
	}
	for _, bad := range []string{`"\x"`, `"\u12"`, `noquote`, `"\`} {
		if _, err := unquoteSecret(json.RawMessage(bad)); err == nil {
			t.Fatalf("unquote(%s) accepted", bad)
		}
	}
}
