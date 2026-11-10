// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// G1-L1: a dynamic-secret lease did not record who requested it, so the
// access graph showed it with holder_recorded=false and no holder, and an
// access review generated from the graph could not name whose access it was.
// The lease now records the subject whose request opened it: its read says so,
// the graph shows that person holding it, and the lease read model holds it.
func TestServedDynamicSecretLeaseRecordsItsRequesterG1L1(t *testing.T) {
	provider := &leaseRotationDouble{}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	registerServedTenant(t, h, "lease requester tenant")
	startServedExternalCADispatcher(t, h)
	ctx := t.Context()
	if _, err := h.srv.orch.UpsertTenantMember(ctx, h.tenant, store.TenantMember{
		Subject: "dana-ops", DisplayName: "Dana Ops", Roles: []string{"operator"}, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	dana := seedScopedTokenSubject(t, h.store, h.tenant, "dana-ops", "secrets:read", "secrets:write")
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "g1l1-auditor", "graph:read", "access:read", "secrets:read")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", dana, "g1l1-lease",
		map[string]any{"provider": "pg-double", "role": "reporting", "ttl_seconds": 600})
	var issued struct {
		ID          string `json:"id"`
		RequestedBy string `json:"requested_by"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &issued) != nil || issued.ID == "" {
		t.Fatalf("issue a lease: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+issued.ID, auditor, nil)
	var read struct {
		RequestedBy string `json:"requested_by"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &read) != nil || read.RequestedBy != "dana-ops" {
		t.Fatalf("the lease read names requester %q (HTTP %d %s), want dana-ops", read.RequestedBy, status, body)
	}
	if rec, err := h.store.GetDynamicSecretLease(ctx, h.tenant, issued.ID); err != nil || rec.RequestedBy != "dana-ops" {
		t.Fatalf("the lease read model names requester %q (%v), want dana-ops", rec.RequestedBy, err)
	}

	g := readG2Graph(t, h, auditor)
	lease, ok := g.node("lease:" + issued.ID)
	if !ok || lease.Attrs["holder_recorded"] != "true" || lease.Attrs["requested_by"] != "dana-ops" {
		t.Fatalf("graph lease node = %+v (found %v), want the recorded holder", lease, ok)
	}
	holds := false
	for _, e := range g.Edges {
		if e.To == "lease:"+issued.ID && e.Type == "HOLDS" {
			if n, ok := g.node(e.From); ok && n.Kind == "person" && n.Name == "Dana Ops" {
				holds = true
			}
		}
	}
	if !holds {
		t.Fatalf("no person holds the lease in the graph: %+v", g.Edges)
	}
}
