package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/mcpserver"
)

func TestAISurfaceRoutesStayGraphScopedWithGuardedMCPWrites(t *testing.T) {
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
			t.Fatalf("unexpected served AI/MCP route %s (opID %s); add an explicit route-scope review before exposing it", key, r.opID)
		}
		seen[key] = true
		if r.opID != opID {
			t.Errorf("%s opID = %q, want %q", key, r.opID, opID)
		}
		if r.mutation {
			t.Errorf("%s is marked as a route-level mutation; MCP write tools must stay behind the guarded tool branch", key)
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

func TestMCPRESTRouteToolsInheritRESTGuardAndIdempotency(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	h := New(nil, nil, nil,
		WithInsecureHeaderResolver(),
		WithAISurface(AISurfaceBackend{MCPIdentity: "spiffe://example.test/mcp", MCPWriteTools: true}),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", "mcp-agent")
	req.Header.Set("X-Roles", "mcp")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list MCP tools = %d: %s", rec.Code, rec.Body.String())
	}
	var listed mcpToolsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode MCP tool list: %v", err)
	}
	for _, want := range []string{"rest_list_certificates", "rest_get_graph", "rest_list_notifications", "rest_create_owner"} {
		if !containsString(listed.Tools, want) {
			t.Fatalf("MCP REST tool list missing %q: %v", want, listed.Tools)
		}
	}
	if listed.ReadOnly {
		t.Fatal("MCP tool list reports read_only=true even though guarded REST writes are enabled")
	}

	denied := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tools/rest_create_owner",
		strings.NewReader(`{"body":{"kind":"team","name":"platform","email":"platform@example.test"}}`))
	denied.Header.Set("X-Tenant-ID", tenantID)
	denied.Header.Set("X-Subject", "mcp-agent")
	denied.Header.Set("X-Roles", "mcp")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, denied)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "owners:write") {
		t.Fatalf("mcp role invoked rest_create_owner = %d body=%s, want 403 from served owners:write guard", rec.Code, rec.Body.String())
	}

	missingIdem := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tools/rest_create_owner",
		strings.NewReader(`{"body":{"kind":"team","name":"platform","email":"platform@example.test"}}`))
	missingIdem.Header.Set("X-Tenant-ID", tenantID)
	missingIdem.Header.Set("X-Subject", "admin")
	missingIdem.Header.Set("X-Roles", "admin")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, missingIdem)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Idempotency-Key") {
		t.Fatalf("admin rest_create_owner without idempotency = %d body=%s, want AN-5 mutation rejection", rec.Code, rec.Body.String())
	}
}

func TestMCPRESTToolCatalogMapsServedRoutesOneToOne(t *testing.T) {
	a := New(nil, nil, nil, WithAISurface(AISurfaceBackend{MCPWriteTools: true}))
	srv := a.mcpServerFor(authz.Principal{TenantID: "tenant-a", Subject: "agent"})
	covered := 0
	for _, rt := range a.routes() {
		if !mcpRESTToolCandidate(rt) {
			continue
		}
		covered++
		name := mcpserver.RESTToolName(rt.opID)
		tool, ok := srv.RESTTool(name)
		if !ok {
			t.Errorf("served route %s %s (%s) has no MCP REST tool %q", rt.method, rt.path, rt.opID, name)
			continue
		}
		if tool.Method != rt.method || tool.Path != rt.path || tool.OperationID != rt.opID || tool.Permission != string(rt.perm) || tool.Mutation != rt.mutation {
			t.Errorf("MCP REST tool %q = %+v, want served route %s %s permission=%q mutation=%t", name, tool, rt.method, rt.path, rt.perm, rt.mutation)
		}
	}
	if covered < 50 {
		t.Fatalf("MCP REST tool catalog covered only %d served routes; want broad REST coverage", covered)
	}
	if _, ok := srv.RESTTool("rest_call_mcp_tool"); ok {
		t.Fatal("MCP call route must not be exposed as a recursive REST-backed MCP tool")
	}
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
