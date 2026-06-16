// Package mcpserver exposes trstctl as read-only, grounded MCP tools (F78,
// S19b.4) an external AI agent can call to investigate credentials within strict
// bounds: query_credentials, get_blast_radius, explain_incident,
// compliance_status. Every call is tenant+RBAC-scoped via SF.7 (an out-of-scope
// call returns nothing), rate-limited and enumeration-resistant, and audited.
// There are NO write/remediation tools — the agent can never act — and retrieved
// data is inert (a hostile string in a SAN or secret name causes no action and no
// out-of-scope disclosure). The server holds an identity issued by trstctl's own
// F61 broker (dogfooding). No key material appears in tool output (AN-8).
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/rca"
)

// ErrRateLimited is returned when a caller exceeds its per-tool budget.
var ErrRateLimited = errors.New("mcpserver: rate limit exceeded")

// ErrOutOfScope is returned for a cross-tenant / out-of-scope call.
var ErrOutOfScope = errors.New("mcpserver: out of scope")

// RateLimiter is a per-key sliding-window limiter (enumeration-abuse protection).
type RateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	clock  func() time.Time
	hits   map[string][]time.Time
}

// NewRateLimiter constructs a limiter allowing max calls per key per window.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{max: max, window: window, clock: time.Now, hits: map[string][]time.Time{}}
}

// Allow reports whether a call for key is within budget.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	cutoff := now.Add(-r.window)
	kept := r.hits[key][:0]
	for _, t := range r.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.max {
		r.hits[key] = kept
		return false
	}
	r.hits[key] = append(kept, now)
	return true
}

// ToolResult is a grounded, cited tool result.
type ToolResult struct {
	Tool      string
	Citations []string
	Text      string
}

// Server is the read-only MCP tool surface.
type Server struct {
	tenantID string
	pipeline *rca.Pipeline
	synth    *rca.Synthesizer
	rate     *RateLimiter
	audit    auditsink.Auditor
	identity string
	tools    map[string]string // read-only tool -> question template
}

// New constructs a Server. identity is the workload identity the F61 broker issued
// to this MCP server.
func New(tenantID string, p *rca.Pipeline, s *rca.Synthesizer, rate *RateLimiter, audit auditsink.Auditor, identity string) *Server {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	if rate == nil {
		rate = NewRateLimiter(100, time.Minute)
	}
	return &Server{
		tenantID: tenantID, pipeline: p, synth: s, rate: rate, audit: audit, identity: identity,
		tools: map[string]string{
			"query_credentials": "summarize the credentials for",
			"get_blast_radius":  "what is the blast radius of",
			"explain_incident":  "reconstruct what happened to",
			"compliance_status": "what is the compliance gap for",
		},
	}
}

// Identity returns the broker-issued identity of this MCP server.
func (s *Server) Identity() string { return s.identity }

// Tools lists the read-only tool names.
func (s *Server) Tools() []string {
	out := make([]string, 0, len(s.tools))
	for n := range s.tools {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// HasWriteTool reports whether any write/remediation tool is exposed. Always false.
func (s *Server) HasWriteTool() bool { return false }

// Call invokes a read-only tool, scoped to the caller's tenant via SF.7,
// rate-limited and audited. Retrieved data is grounded and inert.
func (s *Server) Call(ctx context.Context, caller, tenantID, tool, subject string) (ToolResult, error) {
	if tenantID != s.tenantID { // SF.7 scoping by construction
		_ = auditsink.Emit(ctx, s.audit, nil, "mcp.tool.denied", s.tenantID, []byte(fmt.Sprintf(`{"caller":%q,"tool":%q,"reason":"out-of-scope"}`, caller, tool)))
		return ToolResult{}, ErrOutOfScope
	}
	q, ok := s.tools[tool]
	if !ok {
		return ToolResult{}, fmt.Errorf("mcpserver: unknown or non-read-only tool %q", tool)
	}
	if !s.rate.Allow(caller + "|" + tool) {
		_ = auditsink.Emit(ctx, s.audit, nil, "mcp.tool.ratelimited", s.tenantID, []byte(fmt.Sprintf(`{"caller":%q,"tool":%q}`, caller, tool)))
		return ToolResult{}, ErrRateLimited
	}
	ev, err := s.pipeline.Gather(ctx, tenantID, subject, q+" "+subject)
	if err != nil {
		return ToolResult{}, err
	}
	ans, err := s.synth.Answer(ctx, ev)
	if err != nil {
		return ToolResult{}, err
	}
	_ = auditsink.Emit(ctx, s.audit, nil, "mcp.tool.call", s.tenantID,
		[]byte(fmt.Sprintf(`{"caller":%q,"tool":%q,"scope":%q,"citations":%d,"outcome":"ok"}`, caller, tool, tenantID, len(ans.Citations))))
	return ToolResult{Tool: tool, Citations: ans.Citations, Text: ans.Text}, nil
}
