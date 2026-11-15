// SPDX-License-Identifier: BUSL-1.1

// Package mcpprobe_test proves P7's MCP network probe against stock MCP SDK servers:
package mcpprobe_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"trstctl.com/trstctl/internal/discovery/mcpprobe"
)

func stockServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "issues", Version: "2.3.0"}, nil)
	s.AddTool(&mcp.Tool{Name: "read_issue", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		})
	return s
}

// recording counts what reaches the server and notes any credential sent.
type recording struct {
	mu          sync.Mutex
	methods     []string
	credentials int
}

func (rec *recording) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.methods = append(rec.methods, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			rec.credentials++
		}
		rec.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// TestTheProbeFindsStockMCPServersAndTheirAuthorizationP7 (A20, A22): the probe
// finds a stock MCP SDK server on its Streamable HTTP endpoint (stateful, so the
// probe ends the session it opened), and a stock server behind the SDK's own
// bearer-token middleware is recorded as requiring OAuth with its protected
// resource metadata; neither receives a credential, and a server outside the
// approved ranges is never contacted.
func TestTheProbeFindsStockMCPServersAndTheirAuthorizationP7(t *testing.T) {
	approved := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	open := &recording{}
	mux := http.NewServeMux()
	mux.Handle("/mcp", open.wrap(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return stockServer() }, nil)))
	openTS := httptest.NewServer(mux)
	defer openTS.Close()

	p := &mcpprobe.Prober{Approved: approved}
	obs, found, err := p.Probe(context.Background(), openTS.URL)
	if err != nil || !found || obs.Auth != mcpprobe.AuthNone || obs.ServerName != "issues" || obs.ServerVersion != "2.3.0" || obs.ProtocolVersion == "" {
		t.Fatalf("open stock server = %+v found=%v err=%v", obs, found, err)
	}
	open.mu.Lock()
	if fmt.Sprint(open.methods) != "[POST /mcp DELETE /mcp]" || open.credentials != 0 {
		t.Fatalf("open server saw %v with %d credentials", open.methods, open.credentials)
	}
	open.mu.Unlock()

	protected := &recording{}
	var protectedURL string // the server's own address, known once it listens
	never := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return nil, errors.New("the probe never presents a token")
	}
	stock := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return stockServer() }, nil)
	pmux := http.NewServeMux()
	pmux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"resource":%q,"authorization_servers":["https://login.example.test/tenant"],"scopes_supported":["issues:read"]}`, protectedURL+"/mcp")
	})
	pmux.Handle("/mcp", protected.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.RequireBearerToken(never, &auth.RequireBearerTokenOptions{
			ResourceMetadataURL: protectedURL + "/.well-known/oauth-protected-resource/mcp",
		})(stock).ServeHTTP(w, r)
	})))
	protectedTS := httptest.NewServer(pmux)
	defer protectedTS.Close()
	protectedURL = protectedTS.URL

	obs, found, err = p.Probe(context.Background(), protectedTS.URL)
	if err != nil || !found || obs.Auth != mcpprobe.AuthOAuth || obs.Resource != protectedTS.URL+"/mcp" ||
		len(obs.AuthorizationServers) != 1 || obs.ServerName != "" {
		t.Fatalf("protected stock server = %+v found=%v err=%v", obs, found, err)
	}
	protected.mu.Lock()
	if protected.credentials != 0 {
		t.Fatalf("the protected server received %d credentials", protected.credentials)
	}
	protected.mu.Unlock()

	outside := &mcpprobe.Prober{Approved: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	before := len(open.methods)
	if _, found, err := outside.Probe(context.Background(), openTS.URL); found || !errors.Is(err, mcpprobe.ErrNotApproved) {
		t.Fatalf("outside the approved ranges = found=%v err=%v", found, err)
	}
	if len(open.methods) != before {
		t.Fatal("a server outside the approved ranges was contacted")
	}
}
