package api

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestAISurfaceRoutesStayReadOnlyGraphScoped(t *testing.T) {
	a := New(nil, nil, nil)
	want := map[string]string{
		"GET /api/v1/ai/status":         "aiStatus",
		"POST /api/v1/ai/query":         "aiQuery",
		"POST /api/v1/ai/rca":           "aiRCA",
		"GET /api/v1/mcp/tools":         "listMCPTools",
		"POST /api/v1/mcp/tools/{tool}": "callMCPTool",
	}
	seen := map[string]bool{}
	for _, r := range a.routes() {
		key := r.method + " " + r.path
		if !strings.HasPrefix(r.path, "/api/v1/ai/") && !strings.HasPrefix(r.path, "/api/v1/mcp/") {
			continue
		}
		opID, ok := want[key]
		if !ok {
			t.Fatalf("unexpected served AI/MCP route %s (opID %s); add an explicit read-only review before exposing it", key, r.opID)
		}
		seen[key] = true
		if r.opID != opID {
			t.Errorf("%s opID = %q, want %q", key, r.opID, opID)
		}
		if r.mutation {
			t.Errorf("%s is marked as a mutation; AI/MCP must stay read-only", key)
		}
		if r.perm != authz.GraphRead {
			t.Errorf("%s permission = %q, want %q", key, r.perm, authz.GraphRead)
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("missing served AI/MCP route %s", key)
		}
	}
}

func TestAISurfaceEngineQueryRejectsTenantMismatch(t *testing.T) {
	q := engineQuery{principal: authz.Principal{TenantID: "tenant-a"}}
	_, err := q.Run(context.Background(), "tenant-b", "graph", "anything")
	if err == nil || !strings.Contains(err.Error(), "does not match the authenticated principal") {
		t.Fatalf("tenant mismatch error = %v, want fail-closed principal mismatch", err)
	}
}
