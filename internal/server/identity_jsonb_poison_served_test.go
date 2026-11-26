// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedIdentityRejectsJSONBPoisonBeforeAppend(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "identities:read")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", token, "n0002-owner", map[string]any{
		"kind": "workload", "name": "jsonb-boundary-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: HTTP %d %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatal(err)
	}
	for name, attributes := range map[string]string{
		"surrogate": `{"x":"\ud800"}`,
		"exponent":  `{"n":1e999999}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := json.RawMessage(fmt.Sprintf(`{"kind":"x509_certificate","name":"%s.example.test","owner_id":"%s","attributes":%s}`,
				name, owner.ID, attributes))
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities", token, "n0002-"+name, request)
			if status != http.StatusBadRequest || !strings.Contains(string(body), "unsafe") {
				t.Fatalf("%s poison: HTTP %d %s, want pre-append 400", name, status, body)
			}
		})
	}
}
