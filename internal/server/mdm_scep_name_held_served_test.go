// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// LS-1: a tenant's MDM SCEP policies have distinct names, in any case. A
// second policy under a held name is a 409 and nothing is appended; it used to
// append the policy event and fail its projection on the (tenant, lower(name))
// index, leaving an event a rebuild stopped at. A log that already holds one
// rebuilds as live.
func TestServedMDMSCEPPolicyUnderAHeldNameIsAConflictLS1(t *testing.T) {
	t.Setenv("TRSTCTL_TEST_GRAPH_TOKEN", "graph-test-token")
	h := newOperatingServedHarness(t, config.Protocols{})
	seedMDMTestRelay(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "issuers:read", "issuers:write", string(authz.PrivateEgress))
	policy := func(name string) map[string]any {
		return map[string]any{"name": name, "provider": "intune", "scep_profile": "profile-ls1",
			"scep_endpoint": "/scep", "challenge_mode": "intune-jws", "enabled": true}
	}
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/mdm/scep/policies", tok, policy("Fleet laptops"))
	if status != http.StatusCreated {
		t.Fatalf("first policy: %d %s", status, body)
	}
	var first struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &first); err != nil || first.ID == "" {
		t.Fatalf("decode the first policy: %v %s", err, body)
	}
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/mdm/scep/policies", tok, policy("FLEET LAPTOPS"))
	if status != http.StatusConflict || !strings.Contains(string(body), `another MDM SCEP policy is named \"FLEET LAPTOPS\"`) ||
		!strings.Contains(string(body), `"code":"name_held"`) {
		t.Fatalf("a second policy under the first's name = %d %s, want a 409 naming it", status, body)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("the refused policy appended: %d -> %d %v", before, after, err)
	}
	// The first policy keeps its own name on update.
	if status, body := secretsReq(t, h, http.MethodPut, "/api/v1/mdm/scep/policies/"+first.ID, tok, policy("Fleet laptops")); status != http.StatusOK {
		t.Fatalf("the first policy re-saved under its own name: %d %s", status, body)
	}

	poisoned, err := json.Marshal(projections.MDMSCEPPolicyUpserted{ID: "17171717-1717-4717-8717-171717171717", Name: "fleet laptops",
		Provider: "intune", SCEPProfile: "profile-ls1", SCEPEndpoint: "/scep", ChallengeMode: "intune-jws", Enabled: true, RotationVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{Type: projections.EventMDMSCEPPolicyUpserted, TenantID: h.tenant, Data: poisoned}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("a log holding a pre-check duplicate does not rebuild: %v", err)
	}
	if _, err := h.store.GetMDMSCEPPolicy(t.Context(), h.tenant, "17171717-1717-4717-8717-171717171717"); err == nil {
		t.Fatal("the duplicate projected a policy")
	}
	if got, err := h.store.GetMDMSCEPPolicy(t.Context(), h.tenant, first.ID); err != nil || got.Name != "Fleet laptops" {
		t.Fatalf("the first policy after the rebuild: %+v %v", got, err)
	}
}
