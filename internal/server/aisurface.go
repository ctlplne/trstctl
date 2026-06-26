package server

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
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
// The surface is OFF unless Deps.EnableAISurface is set (fail closed). When on, MCP
// investigation stays read-only unless Deps.EnableMCPWriteTools is also set. All calls
// are tenant-scoped under RLS (the tenant is the authenticated principal's, never a
// request field — AN-1), auth-gated, and rate-limited.

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
		Query:         engine,
		Audit:         audit.NewAuditor(s.log),
		Model:         d.AIModel, // nil → air-gapped (no model); opt-in only (AN-8 posture)
		ModelStatus:   d.AIModelStatus,
		MCPIdentity:   d.AIMCPIdentity,
		MCPWriteTools: d.EnableMCPWriteTools,
		RateMax:       d.AIRateMax,
		RateWindow:    d.AIRateWindow,
	}
}

// apiAISurfaceServed reports whether the running binary mounts the served AI/RCA/MCP
// surface (SURFACE-003) — the wiring assertion (it delegates to the API's
// AISurfaceServed). A startup log and the acceptance test consult it.
func (s *Server) apiAISurfaceServed() bool { return s.api != nil && s.api.AISurfaceServed() }

// aiModelFromConfig builds the optional F76 model adapter from validated config. The
// default mode is off: no adapter is returned, grounding/citations still work, and no
// prompt leaves the process. Local mode targets an operator-owned Ollama/vLLM endpoint.
// Cloud mode is only reachable after config validation sees allow_egress=true. In all
// non-off modes, aimodel.Adapter remains the hard redaction/refusal boundary.
func aiModelFromConfig(cfg config.AIModel, guard *egress.Guard) (*aimodel.Adapter, api.AIModelStatus, error) {
	mode := cfg.ModeValue()
	// PRIVACY-005: the PII egress policy is default-private (redact) unless the
	// operator consents (AllowPII) or chooses a strict block posture. It applies to
	// any non-off model, but it matters most for cloud egress to a third party.
	pii := aimodel.PIIPolicy{AllowPII: cfg.AllowPII, Block: cfg.BlockPII}
	status := api.AIModelStatus{Mode: mode, Egress: "none", PIIEgress: piiEgressLabel(pii)}
	if cfg.Endpoint != "" {
		if u, err := url.Parse(cfg.Endpoint); err == nil {
			status.EndpointHost = u.Host
		} else {
			return nil, status, err
		}
	}
	switch mode {
	case config.AIModelOff:
		return nil, status, nil
	case config.AIModelLocal:
		runtime := strings.ToLower(strings.TrimSpace(cfg.Runtime))
		format := aimodel.FormatOpenAIChat
		if runtime == config.AIModelRuntimeOllama {
			format = aimodel.FormatOllama
		}
		client := aimodel.NewHTTPCompleter(cfg.Endpoint, cfg.Name, format, aiModelHTTPClient(guard))
		status.Runtime = runtime
		status.ModelName = cfg.Name
		status.Egress = "local-endpoint"
		return aimodel.NewWithPII(aimodel.LocalModel{Runtime: runtime, Client: client}, nil, pii), status, nil
	case config.AIModelCloud:
		provider := strings.TrimSpace(cfg.Provider)
		client := aimodel.NewHTTPCompleter(cfg.Endpoint, cfg.Name, aimodel.FormatOpenAIChat, aiModelHTTPClient(guard))
		status.Provider = provider
		status.ModelName = cfg.Name
		status.Egress = "cloud-allowed"
		return aimodel.NewWithPII(aimodel.CloudModel{Provider: provider, Client: client}, nil, pii), status, nil
	default:
		return nil, status, nil
	}
}

func aiModelHTTPClient(guard *egress.Guard) *http.Client {
	if guard == nil || !guard.Enabled() {
		return nil
	}
	return guard.Client(30 * time.Second)
}

// piiEgressLabel renders the operator-visible PRIVACY-005 personal-data egress
// posture for status (non-secret): "allow" (consented), "block" (refuse on PII), or
// "redact" (default-private). It mirrors aimodel.Adapter.PIIEgressMode for the
// off-mode case where no adapter is constructed.
func piiEgressLabel(p aimodel.PIIPolicy) string {
	switch {
	case p.AllowPII:
		return "allow"
	case p.Block:
		return "block"
	default:
		return "redact"
	}
}
