// SPDX-License-Identifier: BUSL-1.1

// Command toolserver is the reference MCP tool server: a relying service built on
// the official MCP Go SDK that serves two tools to agents and honors a call only
// when the agent's trstctl identity and delegated credential authorize it.
//
//	toolserver pin   --config server.json   # read and pin the tenant's issuing CA and roots
//	toolserver serve --config server.json   # serve MCP over HTTPS
//
// With "authorization": "agent-delegation" (the default) it admits agents by
// their mutual-TLS identity and delegated credential. With "authorization":
// "oauth" it is an OAuth resource server for the customer's authorization server
// (MCP authorization): protected resource metadata, and bearer tokens issued for
// this server only (oauth.go).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"trstctl.com/trstctl/test/interop/agentframeworks/relying"
)

// verifiedAgentHeader carries the agent ID the connection's verified certificate
// names from the TLS layer to the tool handlers. Any client-sent value is dropped.
const verifiedAgentHeader = "X-Relying-Verified-Agent"

type config struct {
	Listen           string         `json:"listen"`
	TLSCertFile      string         `json:"tls_cert_file"`
	TLSKeyFile       string         `json:"tls_key_file"`
	AgentCAFile      string         `json:"agent_ca_file"`
	AgentIDPrefix    string         `json:"agent_id_prefix"`
	TenantID         string         `json:"tenant_id"`
	PinsFile         string         `json:"pins_file"`
	TrstctlURL       string         `json:"trstctl_url"`
	TrstctlCAFile    string         `json:"trstctl_ca_file"`
	TrstctlTokenFile string         `json:"trstctl_token_file"`
	Policy           relying.Policy `json:"policy"`
	StatusTTLSeconds int            `json:"status_ttl_seconds"`
	AuditFile        string         `json:"audit_file"`
	Authorization    string         `json:"authorization"`
	OAuth            oauthConfig    `json:"oauth"`
}

// pins is what `pin` records and `serve` trusts.
type pins struct {
	TenantID            string   `json:"tenant_id"`
	IssuingCADER        []byte   `json:"issuing_ca_der"`
	IssuingCASPKISHA256 string   `json:"issuing_ca_spki_sha256"`
	RootAnchorDERs      [][]byte `json:"root_anchor_ders"`
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: toolserver pin|serve --config <file>"))
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	_ = fs.Parse(os.Args[2:])
	cfg, err := loadConfig(*path)
	if err != nil {
		fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch os.Args[1] {
	case "pin":
		err = pin(ctx, cfg)
	case "serve":
		err = serve(ctx, cfg)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func loadConfig(path string) (config, error) {
	var cfg config
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- the operator names the configuration file (CWE-22)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("configuration: %w", err)
	}
	return cfg, nil
}

func trstctlClient(cfg config) (*relying.Client, error) {
	token, err := os.ReadFile(cfg.TrstctlTokenFile) // #nosec G304 -- operator-named token file (CWE-22)
	if err != nil {
		return nil, err
	}
	var caPEM []byte
	if cfg.TrstctlCAFile != "" {
		if caPEM, err = os.ReadFile(cfg.TrstctlCAFile); err != nil { // #nosec G304 -- operator-named CA file (CWE-22)
			return nil, err
		}
	}
	return relying.NewClient(cfg.TrstctlURL, string(token), caPEM)
}

// pin reads the tenant's issuing CA and root anchors and records them. An operator
// compares issuing_ca_spki_sha256 with the value trstctl shows before trusting it.
func pin(ctx context.Context, cfg config) error {
	client, err := trstctlClient(cfg)
	if err != nil {
		return err
	}
	ca, err := client.IssuingCA(ctx)
	if err != nil {
		return err
	}
	if ca.TenantID != cfg.TenantID {
		return fmt.Errorf("the issuing CA is for tenant %s, not %s", ca.TenantID, cfg.TenantID)
	}
	anchors, err := client.RootAnchors(ctx)
	if err != nil {
		return err
	}
	out := pins{TenantID: ca.TenantID, IssuingCADER: ca.CertificateDER, IssuingCASPKISHA256: ca.SPKISHA256}
	for _, anchor := range anchors {
		if anchor.Provisioned {
			out.RootAnchorDERs = append(out.RootAnchorDERs, anchor.PublicDER)
		}
	}
	if len(out.RootAnchorDERs) == 0 {
		return errors.New("the tenant has no provisioned root anchor")
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.PinsFile, raw, 0o600); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"issuing_ca_spki_sha256": out.IssuingCASPKISHA256, "root_anchors": len(out.RootAnchorDERs),
	})
}

type searchIn struct {
	Query string `json:"query" jsonschema:"what to search for"`
}

type searchOut struct {
	Results []string `json:"results"`
}

type deleteIn struct {
	Selector string `json:"selector" jsonschema:"which records to delete"`
}

type deleteOut struct {
	Deleted int `json:"deleted"`
}

func serve(ctx context.Context, cfg config) error {
	audit, err := os.OpenFile(cfg.AuditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- operator-named audit log (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = audit.Close() }()
	var handler http.Handler
	var tlsConfig *tls.Config
	switch cfg.Authorization {
	case "", "agent-delegation":
		if handler, err = delegationHandler(cfg, audit); err == nil {
			tlsConfig, err = serverTLS(cfg)
		}
	case "oauth":
		if handler, err = oauthHandler(cfg, audit); err == nil {
			tlsConfig, err = serverOnlyTLS(cfg)
		}
	default:
		err = fmt.Errorf("unknown authorization %q", cfg.Authorization)
	}
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	fmt.Printf("listening https://%s/mcp\n", ln.Addr())
	if err := httpServer.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// delegationHandler serves the tools to agents admitted by their mutual-TLS
// identity, each call decided by the delegation gate.
func delegationHandler(cfg config, audit io.Writer) (http.Handler, error) {
	raw, err := os.ReadFile(cfg.PinsFile)
	if err != nil {
		return nil, fmt.Errorf("read pins (run toolserver pin first): %w", err)
	}
	var pinned pins
	if err := json.Unmarshal(raw, &pinned); err != nil {
		return nil, err
	}
	client, err := trstctlClient(cfg)
	if err != nil {
		return nil, err
	}
	gate, err := relying.NewGate(relying.Config{
		TenantID: cfg.TenantID, IssuingCADER: pinned.IssuingCADER, RootAnchorDERs: pinned.RootAnchorDERs,
		Policy: cfg.Policy, Trstctl: client, StatusTTL: time.Duration(cfg.StatusTTLSeconds) * time.Second, Audit: audit,
	})
	if err != nil {
		return nil, err
	}
	server := newToolServer(func(tool string) func(context.Context, *mcp.CallToolRequest) error {
		return func(ctx context.Context, req *mcp.CallToolRequest) error {
			header := requestHeader(req)
			presentation := relying.PresentationFromHeaders(header.Get(verifiedAgentHeader), header.Get)
			if decision := gate.Authorize(ctx, presentation, tool); !decision.Allowed {
				return fmt.Errorf("refused by the relying service: %s", decision.Reason)
			}
			return nil
		}
	})
	return withAgentIdentity(cfg.AgentIDPrefix, mcpHTTPHandler(server)), nil
}

// newToolServer registers the two tools, each behind the given check.
func newToolServer(check func(tool string) func(context.Context, *mcp.CallToolRequest) error) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "trstctl-reference-tools", Version: "1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "search", Description: "Search the record index (a read)."},
		guarded(check("search"), func(in searchIn) searchOut {
			return searchOut{Results: []string{"result for " + in.Query}}
		}))
	mcp.AddTool(server, &mcp.Tool{Name: "delete_records", Description: "Delete matching records (a delete)."},
		guarded(check("delete_records"), func(deleteIn) deleteOut {
			return deleteOut{Deleted: 1}
		}))
	return server
}

func mcpHTTPHandler(server *mcp.Server) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true})
}

func requestHeader(req *mcp.CallToolRequest) http.Header {
	if req != nil && req.Extra != nil && req.Extra.Header != nil {
		return req.Extra.Header
	}
	return http.Header{}
}

// guarded runs a tool only when its check passes; a refusal reaches the agent as
// a tool error naming the reason.
func guarded[In, Out any](check func(context.Context, *mcp.CallToolRequest) error, run func(In) Out) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		var zero Out
		if err := check(ctx, req); err != nil {
			return nil, zero, err
		}
		return nil, run(in), nil
	}
}

// serverOnlyTLS authenticates the tool server; callers authenticate with tokens.
func serverOnlyTLS(cfg config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, nil
}

func serverTLS(cfg config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, err
	}
	agentCAs, err := os.ReadFile(cfg.AgentCAFile) // #nosec G304 -- operator-named CA bundle (CWE-22)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(agentCAs) {
		return nil, errors.New("the agent CA file holds no certificate")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// withAgentIdentity admits only connections whose verified client certificate
// names an agent, and hands that agent ID to the tool handlers.
func withAgentIdentity(prefix string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del(verifiedAgentHeader)
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			http.Error(w, "an agent identity certificate is required", http.StatusUnauthorized)
			return
		}
		agent := ""
		for _, uri := range r.TLS.VerifiedChains[0][0].URIs {
			if id := uri.String(); strings.HasPrefix(id, prefix) && len(id) > len(prefix) {
				agent = strings.TrimPrefix(id, prefix)
			}
		}
		if agent == "" {
			http.Error(w, "the agent identity certificate names no agent", http.StatusForbidden)
			return
		}
		r.Header.Set(verifiedAgentHeader, agent)
		next.ServeHTTP(w, r)
	})
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "toolserver:", err)
	os.Exit(1)
}
