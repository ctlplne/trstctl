// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVaultStockCLIKeyBindsTokenMethodPathAndBody(t *testing.T) {
	key := func(token, method, path, body, explicit string) (string, int) {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("X-Vault-Token", token)
		}
		if explicit != "" {
			r.Header.Set("Idempotency-Key", explicit)
		}
		w := httptest.NewRecorder()
		got, ok := vaultStockCLIKey(w, r, []byte(body))
		if ok {
			return got, http.StatusOK
		}
		return got, w.Code
	}
	body := `{"data":{"password":"disposable"}}`
	first, status := key("trst_test_a", http.MethodPut, "/v1/secret/data/app", body, "")
	if status != http.StatusOK || !strings.HasPrefix(first, "vault-stock-v1-") || strings.Contains(first, "disposable") {
		t.Fatalf("stock key status=%d key=%q", status, first)
	}
	second, _ := key("trst_test_a", http.MethodPut, "/v1/secret/data/app", body, "")
	if second != first {
		t.Fatal("exact stock retry changed idempotency key")
	}
	for _, changed := range []struct{ token, method, path, body string }{
		{"trst_test_b", http.MethodPut, "/v1/secret/data/app", body},
		{"trst_test_a", http.MethodPost, "/v1/secret/data/app", body},
		{"trst_test_a", http.MethodPut, "/v1/secret/data/other", body},
		{"trst_test_a", http.MethodPut, "/v1/secret/data/app", `{"data":{"password":"changed"}}`},
	} {
		got, status := key(changed.token, changed.method, changed.path, changed.body, "")
		if status != http.StatusOK || got == first {
			t.Fatalf("distinct stock request key=%q status=%d", got, status)
		}
	}
	if got, status := key("", http.MethodPut, "/v1/secret/data/app", body, ""); got != "" || status != http.StatusBadRequest {
		t.Fatalf("no credential key=%q status=%d", got, status)
	}
	if got, status := key("", http.MethodPut, "/v1/secret/data/app", body, "explicit-key"); got != "explicit-key" || status != http.StatusOK {
		t.Fatalf("explicit key=%q status=%d", got, status)
	}
}
