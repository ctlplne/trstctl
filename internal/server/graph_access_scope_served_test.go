// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// G1-L2: the access side of the graph — tenant members (subjects and display
// names), their roles, and the API tokens, sessions and leases they hold — is
// access:read data. A custom role holding graph:read without access:read used
// to read all of it through the graph routes; it now gets the graph without the
// access side and is told so, while a reader with both still sees it.
func TestServedGraphLeavesOutTheAccessSideWithoutAccessReadG1L2(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	if _, err := h.srv.orch.UpsertTenantMember(ctx, h.tenant, store.TenantMember{
		Subject: "g1l2-member", DisplayName: "Gail Member", Roles: []string{"operator"}, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	graphOnly := seedScopedTokenSubject(t, h.store, h.tenant, "g1l2-graph-viewer", "graph:read")
	auditor := seedScopedTokenSubject(t, h.store, h.tenant, "g1l2-auditor", "graph:read", "access:read")

	read := func(token string) (map[string]bool, bool, string) {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/graph", token, nil)
		if status != http.StatusOK {
			t.Fatalf("GET /api/v1/graph = %d %s", status, raw)
		}
		var g struct {
			Nodes []struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"nodes"`
			AccessOmitted bool `json:"access_omitted"`
		}
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatal(err)
		}
		kinds := map[string]bool{}
		for _, n := range g.Nodes {
			kinds[n.Kind] = true
			if strings.HasPrefix(n.ID, "person:") || strings.HasPrefix(n.ID, "role:") || strings.HasPrefix(n.ID, "principal:") {
				kinds["access-id:"+strings.SplitN(n.ID, ":", 2)[0]] = true
			}
		}
		return kinds, g.AccessOmitted, string(raw)
	}

	full, omitted, raw := read(auditor)
	if omitted || !full["person"] || !full["access-id:person"] || !strings.Contains(raw, "Gail Member") || !strings.Contains(raw, "API token for g1l2-auditor") {
		t.Fatalf("graph for graph:read + access:read = omitted %v kinds %v; want the members and their tokens", omitted, full)
	}
	narrow, omitted, raw := read(graphOnly)
	for _, leaked := range []string{"Gail Member", "g1l2-member", "API token for", "g1l2-auditor"} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("graph for graph:read alone carries %q (access:read data)", leaked)
		}
	}
	if narrow["person"] || narrow["role"] || narrow["access-id:principal"] {
		t.Fatalf("graph for graph:read alone has access nodes: %v", narrow)
	}
	if !omitted {
		t.Fatal("graph for graph:read alone does not say the access side is left out")
	}
	// Every graph route reads the same graph: a member is not a node there.
	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/graph/reachable/person:g1l2-member", graphOnly, nil); status != http.StatusNotFound {
		t.Fatalf("reachability from a member for graph:read alone = %d %s; want 404", status, raw)
	}
	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/graph/reachable/person:g1l2-member", auditor, nil); status != http.StatusOK {
		t.Fatalf("reachability from a member with access:read = %d %s; want 200", status, raw)
	}
}
