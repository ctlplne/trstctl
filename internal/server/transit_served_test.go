// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestServedTransitAPIEncryptDecryptRewrap(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "kms-operator", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})

	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/transit/keys", token, "kms-01-create-aead", map[string]string{
		"name": "payments", "kind": "aead",
	})
	if code != http.StatusCreated {
		t.Fatalf("create transit key = %d, want 201; body=%s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/transit/keys", token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list transit keys = %d, want 200; body=%s", code, body)
	}
	var listed struct {
		Items []struct {
			Name    string `json:"name"`
			Kind    string `json:"kind"`
			Version int    `json:"version"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode transit key list: %v; body=%s", err, body)
	}
	if len(listed.Items) != 1 || listed.Items[0].Name != "payments" || listed.Items[0].Kind != "aead" || listed.Items[0].Version != 1 {
		t.Fatalf("transit key list exposed wrong metadata: %+v", listed.Items)
	}

	plaintext := []byte("card-number-tokenization-test")
	aad := []byte("tenant=payments")
	defer secret.Wipe(plaintext)
	defer secret.Wipe(aad)

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/transit/encrypt", token, "kms-01-encrypt", map[string]any{
		"key": "payments", "plaintext": plaintext, "aad": aad,
	})
	if code != http.StatusOK {
		t.Fatalf("encrypt = %d, want 200; body=%s", code, body)
	}
	var encrypted struct {
		Ciphertext string `json:"ciphertext"`
		Version    int    `json:"version"`
	}
	if err := json.Unmarshal(body, &encrypted); err != nil || encrypted.Ciphertext == "" || encrypted.Version != 1 {
		t.Fatalf("decode encrypt response: version=%d ciphertext=%q err=%v body=%s", encrypted.Version, encrypted.Ciphertext, err, body)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/transit/keys/rotate", token, "kms-01-rotate-aead", map[string]string{
		"name": "payments",
	})
	if code != http.StatusOK {
		t.Fatalf("rotate transit key = %d, want 200; body=%s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/transit/keys", token, "", nil)
	if code != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) != 1 || listed.Items[0].Version != 2 {
		t.Fatalf("transit key list did not durably read back rotation: code=%d items=%+v body=%s", code, listed.Items, body)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/transit/rewrap", token, "kms-01-rewrap", map[string]any{
		"key": "payments", "ciphertext": encrypted.Ciphertext, "aad": aad,
	})
	if code != http.StatusOK {
		t.Fatalf("rewrap = %d, want 200; body=%s", code, body)
	}
	var rewrapped struct {
		Ciphertext string `json:"ciphertext"`
		Version    int    `json:"version"`
	}
	if err := json.Unmarshal(body, &rewrapped); err != nil || rewrapped.Ciphertext == "" || rewrapped.Version != 2 {
		t.Fatalf("decode rewrap response: version=%d ciphertext=%q err=%v body=%s", rewrapped.Version, rewrapped.Ciphertext, err, body)
	}
	if rewrapped.Ciphertext == encrypted.Ciphertext || !strings.HasPrefix(rewrapped.Ciphertext, "trv:2:") {
		t.Fatalf("rewrap did not upgrade ciphertext version: old=%q new=%q", encrypted.Ciphertext, rewrapped.Ciphertext)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/transit/decrypt", token, "", map[string]any{
		"key": "payments", "ciphertext": rewrapped.Ciphertext, "aad": aad,
	})
	if code != http.StatusOK {
		t.Fatalf("decrypt = %d, want 200; body=%s", code, body)
	}
	var decrypted struct {
		Plaintext []byte `json:"plaintext"`
	}
	if err := json.Unmarshal(body, &decrypted); err != nil {
		t.Fatalf("decode decrypt response: %v body=%s", err, body)
	}
	defer secret.Wipe(decrypted.Plaintext)
	if !bytes.Equal(decrypted.Plaintext, plaintext) {
		t.Fatalf("decrypt plaintext = %q, want %q", decrypted.Plaintext, plaintext)
	}

	for _, eventType := range []string{"transit.key.created", "transit.key.rotated", "transit.encrypt", "transit.rewrap"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing audit event %s", eventType)
		}
	}
}
