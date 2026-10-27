// SPDX-License-Identifier: BUSL-1.1

package azurekv_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/kms/azurekv"
)

// A200: wrapkey names the version and the algorithm, and an answer for
// another key version is refused; unwrapkey decodes base64url straight into
// bytes and refuses an algorithm it does not send.
func TestWrapDataKeyPinsTheVersionThatAnswered(t *testing.T) {
	var answerVersion atomic.Value
	answerVersion.Store("v1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Alg, Value string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Alg != azurekv.WrapRSAOAEP256 || r.URL.Query().Get("api-version") != "7.4" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		value, _ := base64.RawURLEncoding.DecodeString(in.Value)
		kid := "https://vault.example.test/keys/signer/" + answerVersion.Load().(string)
		switch {
		case strings.HasSuffix(r.URL.Path, "/wrapkey"):
			_ = json.NewEncoder(w).Encode(map[string]string{"kid": kid, "value": base64.RawURLEncoding.EncodeToString(append([]byte("w:"), value...))})
		case strings.HasSuffix(r.URL.Path, "/unwrapkey"):
			_ = json.NewEncoder(w).Encode(map[string]string{"kid": kid, "value": base64.RawURLEncoding.EncodeToString(value[2:])})
		}
	}))
	defer srv.Close()
	b := azurekv.New("https://vault.example.test", azurekv.Credentials{BearerToken: []byte("azure-token")},
		azurekv.WithEndpoint(srv.URL), azurekv.WithHTTPClient(srv.Client()))
	defer b.Destroy()
	ctx := context.Background()
	version, wrapped, err := b.WrapDataKey(ctx, "signer", "v1", azurekv.WrapRSAOAEP256, []byte("data-key"))
	if err != nil || version != "v1" || string(wrapped) != "w:data-key" {
		t.Fatalf("wrap = %q %q %v", version, wrapped, err)
	}
	plain, err := b.UnwrapDataKey(ctx, "signer", version, azurekv.WrapRSAOAEP256, wrapped)
	if err != nil || string(plain) != "data-key" {
		t.Fatalf("unwrap = %q %v", plain, err)
	}
	if _, err := b.UnwrapDataKey(ctx, "signer", version, "RSA1_5", wrapped); err == nil {
		t.Fatal("an algorithm outside the wrap set was sent")
	}
	answerVersion.Store("v2")
	if _, _, err := b.WrapDataKey(ctx, "signer", "v1", azurekv.WrapRSAOAEP256, []byte("data-key")); err == nil {
		t.Fatal("a wrap answered by another key version was accepted")
	}
}
