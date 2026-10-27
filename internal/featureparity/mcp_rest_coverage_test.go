// SPDX-License-Identifier: BUSL-1.1

package featureparity_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/featureparity"
	"trstctl.com/trstctl/internal/mcpserver"
)

func TestMCPRESTCoverageGuardFailsUncoveredSyntheticRoute(t *testing.T) {
	gaps, stale := featureparity.CheckMCPRESTCoverage([]featureparity.MCPRESTRoute{{
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
	routes := []featureparity.MCPRESTRoute{{
		OperationID: "browserOnlyCallback",
		Method:      http.MethodGet,
		Path:        "/api/v1/browser/callback",
	}}
	allowlist := []featureparity.MCPRESTAllowlistEntry{{
		OperationID:   "browserOnlyCallback",
		Method:        http.MethodGet,
		Path:          "/api/v1/browser/callback",
		Justification: "browser-only redirect endpoint; no AI client action path",
	}}
	gaps, stale := featureparity.CheckMCPRESTCoverage(routes, nil, allowlist)
	if len(gaps) != 0 || len(stale) != 0 {
		t.Fatalf("allowlisted synthetic route gaps=%+v stale=%+v, want clean", gaps, stale)
	}
}

// A route the served API itself excludes from MCP (an approval decision, or a
// privileged certificate mutation outside the lifecycle gate) needs neither a
// tool nor an allowlist entry, and an allowlist entry for it goes stale.
func TestMCPRESTCoverageGuardSkipsAnExcludedRoute(t *testing.T) {
	routes := []featureparity.MCPRESTRoute{{
		OperationID:  "approveSyntheticRequest",
		Method:       http.MethodPost,
		Path:         "/api/v1/synthetic/{id}/approvals",
		MCPExclusion: "approval decision: an agent never approves or denies a dual-control request",
	}}
	if gaps, stale := featureparity.CheckMCPRESTCoverage(routes, nil, nil); len(gaps) != 0 || len(stale) != 0 {
		t.Fatalf("excluded route gaps=%+v stale=%+v, want clean", gaps, stale)
	}
	allowlist := []featureparity.MCPRESTAllowlistEntry{{
		OperationID: "approveSyntheticRequest", Method: http.MethodPost, Path: "/api/v1/synthetic/{id}/approvals",
		Justification: "approval decision",
	}}
	if _, stale := featureparity.CheckMCPRESTCoverage(routes, nil, allowlist); len(stale) != 1 {
		t.Fatalf("an allowlist entry for an excluded route should be stale, got %+v", stale)
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

	routes := make([]featureparity.MCPRESTRoute, 0, len(h.Routes()))
	tools := make([]featureparity.MCPRESTTool, 0, len(listed.Tools))
	for _, rt := range h.Routes() {
		routes = append(routes, featureparity.MCPRESTRoute{
			OperationID:       rt.OperationID,
			Method:            rt.Method,
			Path:              rt.Path,
			SensitiveResponse: rt.SensitiveResponse,
			MCPExclusion:      rt.MCPExclusion,
		})
		if containsString(listed.Tools, mcpserver.RESTToolName(rt.OperationID)) {
			tools = append(tools, featureparity.MCPRESTTool{OperationID: rt.OperationID})
		}
	}
	allowlist, err := featureparity.LoadMCPRESTAllowlist()
	if err != nil {
		t.Fatalf("load MCP REST allowlist: %v", err)
	}
	gaps, stale := featureparity.CheckMCPRESTCoverage(routes, tools, allowlist.Entries)
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
