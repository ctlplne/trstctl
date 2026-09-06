// SPDX-License-Identifier: MPL-2.0

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/buildinfo"
)

// mcp serve — the Model Context Protocol stdio transport for trstctl.
//
// The control plane serves its AI tool surface as authenticated REST routes
// (GET /api/v1/mcp/tools, POST /api/v1/mcp/tools/{tool}). Those routes are
// tenant-scoped, RBAC-gated, rate-limited and audited, but they are not the MCP
// wire protocol, so a standard MCP client (an IDE, an agent framework) could
// not connect to them. This command is the bridge: it speaks JSON-RPC 2.0 over
// newline-delimited stdio exactly as the MCP stdio transport specifies, and
// forwards tool discovery and tool calls to the served routes with the caller's
// own token. It adds no capability of its own: what the token may not do over
// REST, it may not do here either.
//
// Design-partner finding DP2-006 (cold run 20260906t143500z): the docs called
// the REST routes "an MCP server", and a standard client could not talk to them.

const mcpProtocolVersion = "2025-03-26"

var mcpSupportedProtocolVersions = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true}

// mcpServeUsage documents the command the way the other custom verbs do.
func mcpServeUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: trstctl-cli [--server URL] [--token TOKEN] [--ca-file PATH] mcp serve")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Serve the trstctl MCP tools to a standard Model Context Protocol client over the")
	_, _ = fmt.Fprintln(w, "stdio transport (JSON-RPC 2.0, one message per line). The client spawns this command;")
	_, _ = fmt.Fprintln(w, "the token travels in the environment (TRSTCTL_TOKEN), never on the command line.")
	_, _ = fmt.Fprintln(w, "Methods: initialize, ping, tools/list, tools/call (read tools; write tools only when")
	_, _ = fmt.Fprintln(w, "the server exposes them and the token holds certs:issue). Every call is forwarded to")
	_, _ = fmt.Fprintln(w, "/api/v1/mcp/tools with your token, so the server's tenant scope, RBAC, rate limit and")
	_, _ = fmt.Fprintln(w, "audit apply unchanged.")
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// mcpStdioServer holds one client session. Every outbound HTTP call reuses the
// CLI's own client, so TLS verification against --ca-file is identical.
type mcpStdioServer struct {
	ctx    context.Context
	client *http.Client
	server string
	token  string
	tenant string
	out    io.Writer
	errOut io.Writer
	mu     sync.Mutex
}

func runMCPServe(ctx context.Context, args []string, env Env, stdin io.Reader, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	if commandHelpRequested(args) {
		mcpServeUsage(stdout)
		return 0
	}
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "error: mcp serve takes no arguments")
		mcpServeUsage(stderr)
		return 2
	}
	if strings.TrimSpace(server) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --server (or TRSTCTL_SERVER) is required")
		return 2
	}
	if strings.TrimSpace(token) == "" {
		_, _ = fmt.Fprintln(stderr, "error: TRSTCTL_TOKEN (or --token) is required; the MCP client must pass it in the environment")
		return 2
	}
	client, err := httpClientForEnv(env, caFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	s := &mcpStdioServer{ctx: ctx, client: client, server: server, token: token, tenant: tenant, out: stdout, errOut: stderr}
	return s.serve(stdin)
}

// serve reads one JSON-RPC message per line until stdin closes. Notifications
// (no id) get no answer; everything else gets exactly one line back.
func (s *mcpStdioServer) serve(stdin io.Reader) int {
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req jsonRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.reply(jsonRPCResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &jsonRPCError{Code: -32700, Message: "parse error"}})
			continue
		}
		result, rpcErr := s.dispatch(req)
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue // notification: no response by definition
		}
		if rpcErr != nil {
			s.reply(jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: rpcErr})
			continue
		}
		s.reply(jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		_, _ = fmt.Fprintf(s.errOut, "mcp serve: stdin: %v\n", err)
		return 1
	}
	return 0
}

func (s *mcpStdioServer) reply(resp jsonRPCResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = s.out.Write(append(data, '\n'))
}

func (s *mcpStdioServer) dispatch(req jsonRPCRequest) (any, *jsonRPCError) {
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params)
		version := mcpProtocolVersion
		if mcpSupportedProtocolVersions[params.ProtocolVersion] {
			version = params.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "trstctl-cli", "version": buildinfo.Version()},
			"instructions": "Tools are the tenant-scoped trstctl operations the presented token may call. Read tools answer from served " +
				"inventory and evidence; write tools appear only when the control plane exposes them and still require certs:issue.",
		}, nil
	case "notifications/initialized", "notifications/cancelled", "notifications/roots/list_changed":
		return nil, nil
	case "ping":
		return map[string]any{}, nil
	case "resources/list":
		return map[string]any{"resources": []any{}}, nil
	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil
	case "tools/list":
		return s.listTools()
	case "tools/call":
		return s.callTool(req.Params)
	default:
		return nil, &jsonRPCError{Code: -32601, Message: "method not found: " + req.Method}
	}
}

type mcpToolsListing struct {
	Identity string   `json:"identity"`
	ReadOnly bool     `json:"read_only"`
	Tools    []string `json:"tools"`
}

// mcpToolInputSchema is the request contract of POST /api/v1/mcp/tools/{tool}:
// every field is optional and the server validates what a given tool needs.
var mcpToolInputSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"subject":     map[string]any{"type": "string", "description": "identity, certificate, owner or resource the tool should answer about"},
		"path_params": map[string]any{"type": "object", "description": "path parameters for REST-backed tools", "additionalProperties": map[string]any{"type": "string"}},
		"query":       map[string]any{"type": "object", "description": "query parameters for REST-backed tools", "additionalProperties": map[string]any{"type": "string"}},
		"body":        map[string]any{"type": "object", "description": "request body for REST-backed tools"},
		"reason":      map[string]any{"type": "string", "description": "operator reason recorded with guarded write tools"},
	},
	"additionalProperties": true,
}

func (s *mcpStdioServer) listTools() (any, *jsonRPCError) {
	status, body, err := do(s.ctx, s.client, s.server, http.MethodGet, "/api/v1/mcp/tools", nil, nil, s.token, s.tenant, "")
	if err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "control plane unreachable: " + err.Error()}
	}
	if status != http.StatusOK {
		return nil, &jsonRPCError{Code: -32603, Message: fmt.Sprintf("control plane answered HTTP %d: %s", status, problemSummary(body))}
	}
	var listing mcpToolsListing
	if err := json.Unmarshal(body, &listing); err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "control plane returned an unexpected tool listing"}
	}
	tools := make([]map[string]any, 0, len(listing.Tools))
	for _, name := range listing.Tools {
		desc := "trstctl tool " + name + " (tenant-scoped; answered by the control plane with this token's permissions)"
		if listing.ReadOnly {
			desc += "; read-only"
		}
		tools = append(tools, map[string]any{"name": name, "description": desc, "inputSchema": mcpToolInputSchema})
	}
	return map[string]any{"tools": tools}, nil
}

func (s *mcpStdioServer) callTool(params json.RawMessage) (any, *jsonRPCError) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil || strings.TrimSpace(call.Name) == "" {
		return nil, &jsonRPCError{Code: -32602, Message: "tools/call needs params.name"}
	}
	if strings.ContainsAny(call.Name, "/?#") {
		return nil, &jsonRPCError{Code: -32602, Message: "tool name may not contain path or query characters"}
	}
	body := []byte("{}")
	if len(call.Arguments) > 0 && string(call.Arguments) != "null" {
		body = call.Arguments
	}
	status, resp, err := do(s.ctx, s.client, s.server, http.MethodPost, "/api/v1/mcp/tools/"+url.PathEscape(call.Name), nil, body, s.token, s.tenant, generateIdempotencyKey())
	if err != nil {
		return nil, &jsonRPCError{Code: -32603, Message: "control plane unreachable: " + err.Error()}
	}
	text := strings.TrimSpace(string(resp))
	if status < 200 || status >= 300 {
		// A refused call is a tool result the model can read, not a transport
		// fault: MCP reserves JSON-RPC errors for protocol problems.
		return map[string]any{"content": []map[string]any{{"type": "text", "text": fmt.Sprintf("HTTP %d: %s", status, problemSummary(resp))}}, "isError": true}, nil
	}
	if text == "" {
		text = fmt.Sprintf("HTTP %d with an empty body", status)
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": false}, nil
}

// problemSummary keeps a refusal readable without echoing arbitrary bodies.
func problemSummary(body []byte) string {
	var p struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &p) == nil && (p.Title != "" || p.Detail != "") {
		return strings.TrimSpace(strings.TrimSpace(p.Title + ": " + p.Detail))
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}
