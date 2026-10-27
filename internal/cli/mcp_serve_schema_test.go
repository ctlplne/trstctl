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

// The control plane publishes the result schema with its tool list. The bridge
// hands it to the MCP client as each tool's outputSchema, carries the tool's own
// description, and returns each result as structured content alongside its text.
func TestMCPServeAdvertisesTheResultSchemaAndReturnsStructuredContent(t *testing.T) {
	schema := `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","required":["schema","tool"]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/mcp/tools":
			_, _ = io.WriteString(w, `{"identity":"lab-mcp","read_only":true,"tools":["distrust_exposure"],`+
				`"descriptions":{"distrust_exposure":"the certificates and host trust stores a distrust-list entry affects"},"result_schema":`+schema+`}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/mcp/tools/distrust_exposure":
			_, _ = io.WriteString(w, `{"schema":"trstctl.mcp.tool-result/v1","tool":"distrust_exposure","text":"affects 1 certificates","findings":[{"finding_id":"f1"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"distrust_exposure","arguments":{"subject":"emSign ECC Root CA - G3"}}}`,
	}, "\n") + "\n"
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"--server", ts.URL, "--token", "trst_test_token", "mcp", "serve"}, Env{}, strings.NewReader(in), &out, &errOut); code != 0 {
		t.Fatalf("mcp serve exit %d, stderr %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 answers, got %s", out.String())
	}
	var listed struct {
		Result struct {
			Tools []struct {
				Name         string          `json:"name"`
				Description  string          `json:"description"`
				OutputSchema json.RawMessage `json:"outputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &listed); err != nil || len(listed.Result.Tools) != 1 {
		t.Fatalf("tools/list = %s (%v)", lines[0], err)
	}
	tool := listed.Result.Tools[0]
	if !strings.Contains(tool.Description, "a distrust-list entry affects") || string(tool.OutputSchema) != schema {
		t.Fatalf("tool = %+v (outputSchema %s)", tool, tool.OutputSchema)
	}
	var called struct {
		Result struct {
			IsError           bool           `json:"isError"`
			StructuredContent map[string]any `json:"structuredContent"`
			Content           []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &called); err != nil || called.Result.IsError {
		t.Fatalf("tools/call = %s (%v)", lines[1], err)
	}
	if called.Result.StructuredContent["schema"] != "trstctl.mcp.tool-result/v1" || len(called.Result.Content) != 1 ||
		!strings.Contains(called.Result.Content[0].Text, `"finding_id":"f1"`) {
		t.Fatalf("a result must come back as structured content and its JSON text: %s", lines[1])
	}
}
