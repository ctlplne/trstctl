package featureparity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/mcpserver"
)

func TestMCPRESTCoverageGuardFailsUncoveredSyntheticRoute(t *testing.T) {
	gaps, stale := CheckMCPRESTCoverage([]MCPRESTRoute{{
		OperationID: "newSyntheticRoute",
		Method:      http.MethodGet,
		Path:        "/api/v1/synthetic",
	}}, nil, nil)
	if len(stale) != 0 {
		t.Fatalf("unexpected stale allowlist entries: %+v", stale)
	}
	if len(gaps) != 1 || gaps[0].OperationID != "newSyntheticRoute" {
		t.Fatalf("uncovered synthetic route gaps = %+v, want one gap for newSyntheticRoute", gaps)
	}
}

func TestMCPRESTCoverageGuardAllowsDocumentedSyntheticException(t *testing.T) {
	routes := []MCPRESTRoute{{
		OperationID: "browserOnlyCallback",
		Method:      http.MethodGet,
		Path:        "/api/v1/browser/callback",
	}}
	allowlist := []MCPRESTAllowlistEntry{{
		OperationID:   "browserOnlyCallback",
		Method:        http.MethodGet,
		Path:          "/api/v1/browser/callback",
		Justification: "browser-only redirect endpoint; no AI client action path",
	}}
	gaps, stale := CheckMCPRESTCoverage(routes, nil, allowlist)
	if len(gaps) != 0 || len(stale) != 0 {
		t.Fatalf("allowlisted synthetic route gaps=%+v stale=%+v, want clean", gaps, stale)
	}
}

func TestMCPRESTCoverageGuardCoversServedRoutes(t *testing.T) {
	h := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithAISurface(api.AISurfaceBackend{MCPIdentity: "spiffe://example.test/mcp", MCPWriteTools: true}),
	)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Subject", "coverage-agent")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list MCP tools = %d body=%s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Tools []string `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode MCP tools: %v body=%s", err, rec.Body.String())
	}

	routes := make([]MCPRESTRoute, 0, len(h.Routes()))
	tools := make([]MCPRESTTool, 0, len(listed.Tools))
	for _, rt := range h.Routes() {
		routes = append(routes, MCPRESTRoute{
			OperationID: rt.OperationID,
			Method:      rt.Method,
			Path:        rt.Path,
		})
		if containsString(listed.Tools, mcpserver.RESTToolName(rt.OperationID)) {
			tools = append(tools, MCPRESTTool{OperationID: rt.OperationID})
		}
	}
	allowlist, err := LoadMCPRESTAllowlist()
	if err != nil {
		t.Fatalf("load MCP REST allowlist: %v", err)
	}
	gaps, stale := CheckMCPRESTCoverage(routes, tools, allowlist.Entries)
	if len(gaps) != 0 || len(stale) != 0 {
		t.Fatalf("MCP REST coverage guard gaps=%+v stale=%+v", gaps, stale)
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
