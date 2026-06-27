package featureparity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MCPRESTRoute is the served REST route identity the MCP coverage guard checks.
type MCPRESTRoute struct {
	OperationID string
	Method      string
	Path        string
}

// MCPRESTTool records that one MCP tool covers one served REST operation.
type MCPRESTTool struct {
	OperationID string
}

// MCPRESTAllowlist is the explicit list of served routes that intentionally do not
// have MCP tools. Each entry needs a reason so drift remains a reviewable decision,
// not a silent omission.
type MCPRESTAllowlist struct {
	Entries []MCPRESTAllowlistEntry `json:"entries"`
}

type MCPRESTAllowlistEntry struct {
	OperationID   string `json:"operation_id"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Justification string `json:"justification"`
}

type MCPRESTCoverageGap struct {
	OperationID string
	Method      string
	Path        string
}

// LoadMCPRESTAllowlist reads the repository-owned MCP-vs-REST exception list.
func LoadMCPRESTAllowlist() (MCPRESTAllowlist, error) {
	root, err := repoRoot()
	if err != nil {
		return MCPRESTAllowlist{}, err
	}
	b, err := os.ReadFile(filepath.Join(root, "internal", "featureparity", "mcp-rest-allowlist.json"))
	if err != nil {
		return MCPRESTAllowlist{}, fmt.Errorf("read MCP REST allowlist: %w", err)
	}
	var allowlist MCPRESTAllowlist
	if err := json.Unmarshal(b, &allowlist); err != nil {
		return MCPRESTAllowlist{}, fmt.Errorf("parse MCP REST allowlist: %w", err)
	}
	return allowlist, nil
}

// CheckMCPRESTCoverage returns served routes that have neither a registered MCP tool
// nor an explicit allowlist entry, plus allowlist entries that are stale or invalid.
func CheckMCPRESTCoverage(routes []MCPRESTRoute, tools []MCPRESTTool, allowlist []MCPRESTAllowlistEntry) ([]MCPRESTCoverageGap, []MCPRESTAllowlistEntry) {
	covered := map[string]bool{}
	for _, tool := range tools {
		opID := strings.TrimSpace(tool.OperationID)
		if opID != "" {
			covered[opID] = true
		}
	}

	usedAllowlist := map[int]bool{}
	var gaps []MCPRESTCoverageGap
	for _, route := range routes {
		route = normalizeMCPRESTRoute(route)
		if route.OperationID == "" || route.Method == "" || route.Path == "" {
			gaps = append(gaps, MCPRESTCoverageGap(route))
			continue
		}
		if covered[route.OperationID] {
			continue
		}
		allowed := false
		for i, entry := range allowlist {
			if mcpRESTAllowlistMatches(entry, route) && strings.TrimSpace(entry.Justification) != "" {
				usedAllowlist[i] = true
				allowed = true
				break
			}
		}
		if !allowed {
			gaps = append(gaps, MCPRESTCoverageGap(route))
		}
	}

	var stale []MCPRESTAllowlistEntry
	for i, entry := range allowlist {
		if strings.TrimSpace(entry.Justification) == "" || !usedAllowlist[i] {
			stale = append(stale, entry)
		}
	}
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].OperationID == gaps[j].OperationID {
			return gaps[i].Method+" "+gaps[i].Path < gaps[j].Method+" "+gaps[j].Path
		}
		return gaps[i].OperationID < gaps[j].OperationID
	})
	sort.Slice(stale, func(i, j int) bool {
		if stale[i].OperationID == stale[j].OperationID {
			return stale[i].Method+" "+stale[i].Path < stale[j].Method+" "+stale[j].Path
		}
		return stale[i].OperationID < stale[j].OperationID
	})
	return gaps, stale
}

func normalizeMCPRESTRoute(route MCPRESTRoute) MCPRESTRoute {
	route.OperationID = strings.TrimSpace(route.OperationID)
	route.Method = strings.ToUpper(strings.TrimSpace(route.Method))
	route.Path = strings.TrimSpace(route.Path)
	return route
}

func mcpRESTAllowlistMatches(entry MCPRESTAllowlistEntry, route MCPRESTRoute) bool {
	if strings.TrimSpace(entry.OperationID) != "" && strings.TrimSpace(entry.OperationID) == route.OperationID {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(entry.Method), route.Method) && strings.TrimSpace(entry.Path) == route.Path
}
