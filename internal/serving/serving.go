// Package serving is the Phase-2 composition root (S15.0): it mounts every new
// Phase-2 serving surface (EST/SCEP/CMP, the SPIFFE Workload API, the AI-agent
// broker) into one control plane, starts them in dependency order with health
// gating, wires the policy engine into the request path so a deployed policy
// actually blocks a real request, and drains them in reverse order on shutdown.
// This is integration only — no new capability.
package serving

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"trustctl.io/trustctl/internal/policy"
)

// Surface is one mounted serving surface (a protocol server or API).
type Surface struct {
	Name     string
	Prefix   string // URL prefix, e.g. "/.well-known/est"
	Handler  http.Handler
	Order    int                             // startup order (lower starts first)
	Ready    func(ctx context.Context) error // readiness probe (health gating)
	Shutdown func(ctx context.Context) error // graceful drain
}

// Registry composes serving surfaces with an ordered, health-gated lifecycle.
type Registry struct {
	mu       sync.Mutex
	surfaces []Surface
	started  []Surface
}

// NewRegistry constructs an empty Registry.
func NewRegistry() *Registry { return &Registry{} }

// Mount registers a surface. Duplicate names or prefixes are rejected.
func (r *Registry) Mount(s Surface) error {
	if s.Name == "" || s.Prefix == "" || s.Handler == nil {
		return fmt.Errorf("serving: surface needs a name, prefix, and handler")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.surfaces {
		if e.Name == s.Name || e.Prefix == s.Prefix {
			return fmt.Errorf("serving: duplicate surface name/prefix %q/%q", s.Name, s.Prefix)
		}
	}
	r.surfaces = append(r.surfaces, s)
	return nil
}

// Handler returns the composed mux: each request is dispatched to the surface
// with the longest matching prefix.
func (r *Registry) Handler() http.Handler {
	r.mu.Lock()
	surfaces := append([]Surface(nil), r.surfaces...)
	r.mu.Unlock()
	sort.Slice(surfaces, func(i, j int) bool { return len(surfaces[i].Prefix) > len(surfaces[j].Prefix) })
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, s := range surfaces {
			if strings.HasPrefix(req.URL.Path, s.Prefix) {
				s.Handler.ServeHTTP(w, req)
				return
			}
		}
		http.NotFound(w, req)
	})
}

// Start starts surfaces in Order, gating on each readiness probe. If a surface is
// not ready, it fails closed and drains already-started surfaces in reverse order.
func (r *Registry) Start(ctx context.Context) error {
	r.mu.Lock()
	ordered := append([]Surface(nil), r.surfaces...)
	r.mu.Unlock()
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Order < ordered[j].Order })
	for _, s := range ordered {
		if s.Ready != nil {
			if err := s.Ready(ctx); err != nil {
				_ = r.Shutdown(ctx)
				return fmt.Errorf("serving: surface %q failed readiness, rolled back: %w", s.Name, err)
			}
		}
		r.mu.Lock()
		r.started = append(r.started, s)
		r.mu.Unlock()
	}
	return nil
}

// Started returns the names of currently-started surfaces, in start order.
func (r *Registry) Started() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.started))
	for i, s := range r.started {
		out[i] = s.Name
	}
	return out
}

// Shutdown drains started surfaces in reverse start order.
func (r *Registry) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	started := r.started
	r.started = nil
	r.mu.Unlock()
	var firstErr error
	for i := len(started) - 1; i >= 0; i-- {
		if sd := started[i].Shutdown; sd != nil {
			if err := sd(ctx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// PolicyGate is the request-path policy decision seam (S10.1). policy.Engine
// satisfies it.
type PolicyGate interface {
	Evaluate(ctx context.Context, in policy.Input) (policy.Decision, error)
}

// Compile-time proof the S10.1 engine is a valid request-path gate.
var _ PolicyGate = (*policy.Engine)(nil)

// GateMutating wraps h so mutating requests (POST/PUT/DELETE/PATCH) are evaluated
// by the policy engine before reaching the handler; a denied request returns 403
// and never reaches h. Reads pass through. This is how a deployed policy blocks a
// real request end-to-end.
func GateMutating(gate PolicyGate, action policy.Action, tenantID string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			dec, err := gate.Evaluate(req.Context(), policy.Input{Action: action, TenantID: tenantID})
			if err != nil {
				http.Error(w, "policy evaluation failed", http.StatusForbidden)
				return
			}
			if !dec.Allow {
				http.Error(w, "policy denied: "+dec.Reason, http.StatusForbidden)
				return
			}
		}
		h.ServeHTTP(w, req)
	})
}
