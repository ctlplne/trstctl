// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// B6-2 lead: an identity that names a certificate profile with no active
// revision used to be accepted at creation and then answer a bare 404
// "resource not found" on its first deploy, where the resources the caller
// named (identity, target) all existed. The gap is now refused at creation
// with the profile's name.
func TestServedIdentityCreateRefusesAProfileWithNoActiveRevision(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "profile admission")
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "profiles:write")
	code, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", token, map[string]any{"kind": "workload", "name": "profile-check-owner"})
	if code != http.StatusCreated {
		t.Fatalf("create owner: %d %s", code, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
		t.Fatalf("decode owner: %v %s", err, body)
	}
	owner := created.ID
	identity := map[string]any{
		"kind": "x509_certificate", "name": "profile-check.example.test", "owner_id": owner,
		"attributes": map[string]any{"profile_name": "lab-b5-missing", "dns_names": []string{"profile-check.example.test"}},
	}
	code, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", token, identity)
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(body), "lab-b5-missing") || !strings.Contains(string(body), "no active revision") {
		t.Fatalf("identity naming a missing profile = %d %s, want 422 naming the profile", code, body)
	}

	// The same request succeeds once the profile has an active revision.
	code, body = secretsReq(t, h, http.MethodPost, "/api/v1/profiles", token, map[string]any{"name": "lab-b5-missing", "spec": map[string]any{
		"max_validity": "720h", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"example.test"}, "allowed_key_algorithms": []string{"ECDSA"},
	}})
	if code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", code, body)
	}
	if code, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", token, identity); code != http.StatusCreated {
		t.Fatalf("identity naming the now-active profile = %d %s, want 201", code, body)
	}
}
