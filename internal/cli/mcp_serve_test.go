// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A standard MCP client speaks JSON-RPC over stdio: initialize, the initialized
// notification (no answer), tools/list, tools/call, ping. The bridge must answer
// each request with exactly one line, forward calls with the caller's token, and
// turn a refused call into a readable tool result rather than a protocol error
// (DP2-006).
func TestMCPServeSpeaksTheStdioTransportOverTheServedToolRoutes(t *testing.T) {
	var seenAuth, seenIdem string
	var calledBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/mcp/tools":
			_, _ = io.WriteString(w, `{"identity":"lab-mcp","read_only":true,"tools":["inventory_summary","owner_lookup"]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/mcp/tools/owner_lookup":
			seenIdem = r.Header.Get("Idempotency-Key")
			calledBody, _ = io.ReadAll(r.Body)
			_, _ = io.WriteString(w, `{"tool":"owner_lookup","citations":["owners/1"],"text":"owner name=Partner Lab Web Team"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/mcp/tools/rotate_certificate":
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"title":"Forbidden","detail":"forbidden: requires certs:issue","status":403}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"owner_lookup","arguments":{"subject":"Partner Lab Web Team"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"rotate_certificate","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":6,"method":"resources/read"}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"../owners"}}`,
	}, "\n") + "\n"
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"--server", ts.URL, "--token", "trst_test_token", "mcp", "serve"}, Env{}, strings.NewReader(in), &out, &errOut)
	if code != 0 {
		t.Fatalf("mcp serve exit %d, stderr %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 7 {
		t.Fatalf("expected 7 responses (the notification gets none), got %d:\n%s", len(lines), out.String())
	}
	var resp []map[string]any
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("response is not one JSON line: %q", l)
		}
		resp = append(resp, m)
	}
	init := resp[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" || init["serverInfo"].(map[string]any)["name"] != "trstctl-cli" {
		t.Fatalf("initialize result = %v", init)
	}
	tools := resp[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 || tools[0].(map[string]any)["name"] != "inventory_summary" || tools[0].(map[string]any)["inputSchema"] == nil {
		t.Fatalf("tools/list = %v", tools)
	}
	call := resp[2]["result"].(map[string]any)
	if call["isError"] != false || !strings.Contains(call["content"].([]any)[0].(map[string]any)["text"].(string), "Partner Lab Web Team") {
		t.Fatalf("tools/call = %v", call)
	}
	if seenAuth != "Bearer trst_test_token" || seenIdem == "" || !strings.Contains(string(calledBody), `"subject":"Partner Lab Web Team"`) {
		t.Fatalf("forwarded call: auth=%q idem=%q body=%s", seenAuth, seenIdem, calledBody)
	}
	refused := resp[3]["result"].(map[string]any)
	if refused["isError"] != true || !strings.Contains(refused["content"].([]any)[0].(map[string]any)["text"].(string), "HTTP 403: Forbidden: forbidden: requires certs:issue") {
		t.Fatalf("a refused write must be a readable tool error, got %v", refused)
	}
	if _, ok := resp[4]["result"].(map[string]any); !ok {
		t.Fatalf("ping = %v", resp[4])
	}
	if e, ok := resp[5]["error"].(map[string]any); !ok || e["code"].(float64) != -32601 {
		t.Fatalf("unknown method must be -32601, got %v", resp[5])
	}
	if e, ok := resp[6]["error"].(map[string]any); !ok || e["code"].(float64) != -32602 {
		t.Fatalf("a tool name with path characters must be refused before any request, got %v", resp[6])
	}
	if strings.Contains(out.String(), "trst_test_token") {
		t.Fatal("the token leaked into the transport")
	}
}

func TestMCPServeRefusesToStartWithoutAServerOrToken(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"mcp", "serve"}, Env{}, strings.NewReader(""), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "--server") {
		t.Fatalf("no server: exit %d stderr %s", code, errOut.String())
	}
	errOut.Reset()
	if code := Run(context.Background(), []string{"--server", "https://cp.example", "mcp", "serve"}, Env{}, strings.NewReader(""), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "TRSTCTL_TOKEN") {
		t.Fatalf("no token: exit %d stderr %s", code, errOut.String())
	}
	out.Reset()
	if code := Run(context.Background(), []string{"mcp", "serve", "--help"}, Env{}, strings.NewReader(""), &out, &errOut); code != 0 || !strings.Contains(out.String(), "stdio transport") {
		t.Fatalf("help: exit %d out %s", code, out.String())
	}
}
