// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"net/http"
	"testing"
)

// The raw SSH routes bound their JSON bodies; an over-limit body is refused with
// 413 through the API mutation guard, before any issuance or revocation.
func TestServedRawSSHRejectsOverLimitJSONBody(t *testing.T) {
	h := newOperatingServedHarness(t, sshServedProtocols())
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "ssh-operator", []string{"certs:issue", "certs:write"})
	for _, path := range []string{"/ssh/issue/user", "/ssh/revoke"} {
		req, err := http.NewRequest(http.MethodPost, h.ts.URL+path, bytes.NewReader(bytes.Repeat([]byte("x"), maxSSHJSONBody+1)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Idempotency-Key", "over-limit"+path)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("over-limit POST %s = %d, want 413", path, resp.StatusCode)
		}
	}
}
