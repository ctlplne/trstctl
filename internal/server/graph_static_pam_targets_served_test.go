// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
)

// G1-L5 Done-when (served): a PAM target from static configuration is in the
// access graph, linked to the dynamic-secret backend it signs in through, as
// a registered target is: the graph holds res:pam:postgres:g1l5-orders,
// marked configured static with its provider, and a CONNECTS_TO edge from it
// to res:dynamic-secret:pam-pg-provider sourced from the static
// configuration; a reader without access:read sees neither.
func TestServedGraphLinksStaticPAMTargetsToTheirProviderG1L5(t *testing.T) {
	adminDSNRef := pamPostgresAdminFileRef(t, "postgres://g1l5:unused@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, 10*time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, DefaultTTL: 5 * time.Minute, MaxTTL: 10 * time.Minute, ExpiryInterval: time.Hour,
			Attestors: []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{
				TenantID: servedTestTenant, ID: "g1l5-orders", ProviderID: "pam-pg-provider", AllowedRoles: []string{"readonly"},
			}},
		}
	})
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "g1l5-graph-reader", "graph:read", "access:read")
	outsider := seedScopedTokenSubject(t, h.store, h.tenant, "g1l5-graph-only", "graph:read")
	graphOf := func(token string) (map[string]g1Node, []g1Edge) {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/graph", token, nil)
		var g struct {
			Nodes []g1Node `json:"nodes"`
			Edges []g1Edge `json:"edges"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &g) != nil {
			t.Fatalf("GET /api/v1/graph = %d %s", status, raw)
		}
		nodes := map[string]g1Node{}
		for _, n := range g.Nodes {
			nodes[n.ID] = n
		}
		return nodes, g.Edges
	}
	const target, backend = "res:pam:postgres:g1l5-orders", "res:dynamic-secret:pam-pg-provider"
	nodes, edges := graphOf(reader)
	node, ok := nodes[target]
	if !ok || node.Attrs["configured"] != "static" || node.Attrs["provider_id"] != "pam-pg-provider" || node.Attrs["resource_kind"] != "pam_target" {
		t.Fatalf("the static target's node = %+v (found %v)", node, ok)
	}
	if _, ok := nodes[backend]; !ok {
		t.Fatalf("the provider's backend is not in the graph")
	}
	linked := false
	for _, e := range edges {
		if e.From == target && e.To == backend && e.Type == "CONNECTS_TO" && e.Source == "PAM target provider reference (static configuration)" {
			linked = true
		}
	}
	if !linked {
		t.Fatalf("no CONNECTS_TO edge from %s to %s", target, backend)
	}
	if nodes, _ := graphOf(outsider); nodes[target].ID != "" {
		t.Fatal("a reader without access:read saw the static PAM target")
	}
	t.Log("G1L5_STATIC_PAM_TARGET_OK")
}
