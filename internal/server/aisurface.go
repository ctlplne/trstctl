package server

import (
	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/query"
)

// This file wires the SERVED AI / RCA / NL-query / MCP surface (SURFACE-003; F75/F76/
// F77/F78). Until now internal/aimodel, internal/rca, internal/mcpserver, and
// internal/query were a library island with no served importer: the advertised AI
// features ran in no binary, and (unlike connectors/discovery) the gap was undisclosed
// (a higher-severity over-claim). This is the composition that mounts them on the
// running control plane.
//
// It assembles the api.AISurfaceBackend from the control plane's already-built
// dependencies:
//   - the tenant-then-RBAC-scoped query.Engine (SF.7) over the RLS-isolated store and
//     the AN-2 event log, on its OWN bounded "query" pool (AN-7) so a heavy AI/NL query
//     sheds fast and cannot starve the API;
//   - the AN-2 event log (as an auditor) so every AI/RCA/MCP call is audited;
//   - the OPTIONAL, opt-in model adapter (F76): air-gapped by default (no model), and
//     when a model IS configured every prompt crosses the boundary redactor + the
//     residual-entropy refuse-gate before any egress (AN-8 / SURFACE-004).
//
// The surface is OFF unless Deps.EnableAISurface is set (fail closed). When on it is
// READ-ONLY (no write/remediation tools), tenant-scoped under RLS (the tenant is the
// authenticated principal's, never a request field — AN-1), auth-gated, and
// rate-limited.

// buildAISurfaceBackend assembles the api.AISurfaceBackend from the assembled server's
// dependencies. The query engine reads under RLS for the caller's tenant only and is
// denied per surface by RBAC before any read; it runs on the dedicated "query"
// bulkhead pool when present (the same pool the heavy graph/risk reads use), falling
// back to inline when a custom bulkhead set omits it. The model adapter is the opt-in
// F76 adapter the server was given (nil = air-gapped, AI reasoning off; grounding +
// citations still work).
func (s *Server) buildAISurfaceBackend(d Deps) api.AISurfaceBackend {
	var pool *bulkhead.Pool
	if s.bulk != nil {
		pool = s.bulk.Pool(bulkhead.SubsystemQuery)
	}
	engine := query.New(d.Store, d.Log, pool, query.DefaultConfig())
	return api.AISurfaceBackend{
		Query:       engine,
		Audit:       audit.NewAuditor(s.log),
		Model:       d.AIModel, // nil → air-gapped (no model); opt-in only (AN-8 posture)
		MCPIdentity: d.AIMCPIdentity,
		RateMax:     d.AIRateMax,
		RateWindow:  d.AIRateWindow,
	}
}

// apiAISurfaceServed reports whether the running binary mounts the served AI/RCA/MCP
// surface (SURFACE-003) — the wiring assertion (it delegates to the API's
// AISurfaceServed). A startup log and the acceptance test consult it.
func (s *Server) apiAISurfaceServed() bool { return s.api != nil && s.api.AISurfaceServed() }

// aiModelFromConfig is the seam where a configured model provider (F76) would be
// constructed. Per the product posture the AI model adapter is AIR-GAPPED / OPT-IN by
// default: the served surface ships with NO model (Deps.AIModel nil), so grounding +
// citations work but nothing phones home. An operator that opts into a local
// (Ollama/vLLM) or cloud model wires the provider here; whatever the choice, the
// adapter's boundary redactor + residual-entropy refuse-gate (aimodel.Adapter) sit
// between any prompt and the model (AN-8). It returns nil today (no model) by design.
func aiModelFromConfig() *aimodel.Adapter { return aimodel.New(nil, nil) }
