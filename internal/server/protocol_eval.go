// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

const protocolEvalProfileActivatedEvent = "protocol.eval_profile.activated"

var evalProtocolNames = []string{"acme", "est", "scep", "cmp", "ssh", "tsa", "spiffe"}

// protocolActivationGate keeps an eval profile dark until the authenticated
// first-run action records activation. Explicit production protocol toggles do
// not use this gate. A closed ready channel also lets the SPIFFE UDS worker wait
// without polling.
type protocolActivationGate struct {
	active atomic.Bool
	once   sync.Once
	ready  chan struct{}
}

func newProtocolActivationGate(active bool) *protocolActivationGate {
	g := &protocolActivationGate{ready: make(chan struct{})}
	if active {
		g.Activate()
	}
	return g
}

func (g *protocolActivationGate) Active() bool { return g != nil && g.active.Load() }

func (g *protocolActivationGate) Activate() {
	if g == nil {
		return
	}
	g.once.Do(func() {
		g.active.Store(true)
		close(g.ready)
	})
}

func (g *protocolActivationGate) Wait(ctx context.Context) bool {
	if g == nil || g.Active() {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-g.ready:
		return true
	}
}

// evalProtocolProfileControl owns the event-sourced activation state shared by
// the REST wizard action, HTTP protocol gate, and SPIFFE UDS worker.
type evalProtocolProfileControl struct {
	mu        sync.Mutex
	tenantID  string
	protocols []string
	log       *events.Log
	gate      *protocolActivationGate
}

func newEvalProtocolProfileControl(ctx context.Context, protocols config.Protocols, served *servedProtocols, log *events.Log) (*evalProtocolProfileControl, error) {
	if protocols.Profile != config.ProtocolProfileEval {
		return nil, nil
	}
	if log == nil {
		return nil, errors.New("server: eval protocol profile requires the event log for durable activation")
	}
	if served == nil || !slices.Equal(served.names, evalProtocolNames) {
		return nil, fmt.Errorf("server: eval protocol profile assembled %v, want every shipped protocol %v", servedProtocolNames(served), evalProtocolNames)
	}
	active := false
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == protocolEvalProfileActivatedEvent && event.TenantID == protocols.EvalTenantID {
			active = true
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("server: replay eval protocol activation: %w", err)
	}
	gate := newProtocolActivationGate(active)
	served.activation = gate
	return &evalProtocolProfileControl{
		tenantID:  protocols.EvalTenantID,
		protocols: append([]string(nil), served.names...),
		log:       log,
		gate:      gate,
	}, nil
}

func servedProtocolNames(served *servedProtocols) []string {
	if served == nil {
		return nil
	}
	return served.names
}

func (c *evalProtocolProfileControl) Status(_ context.Context, tenantID string) (api.ProtocolProfileStatus, error) {
	if c == nil {
		return api.ProtocolProfileStatus{}, api.ErrProtocolProfileUnavailable
	}
	if tenantID != c.tenantID {
		return api.ProtocolProfileStatus{}, api.ErrProtocolProfileTenantMismatch
	}
	return c.status(), nil
}

func (c *evalProtocolProfileControl) Activate(ctx context.Context, tenantID, _ string) (api.ProtocolProfileStatus, error) {
	if c == nil {
		return api.ProtocolProfileStatus{}, api.ErrProtocolProfileUnavailable
	}
	if tenantID != c.tenantID {
		return api.ProtocolProfileStatus{}, api.ErrProtocolProfileTenantMismatch
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gate.Active() {
		return c.status(), nil
	}
	payload, err := json.Marshal(struct {
		Profile   string   `json:"profile"`
		Protocols []string `json:"protocols"`
	}{Profile: config.ProtocolProfileEval, Protocols: c.protocols})
	if err != nil {
		return api.ProtocolProfileStatus{}, err
	}
	if _, err := c.log.Append(ctx, events.Event{
		Type: protocolEvalProfileActivatedEvent, TenantID: c.tenantID, SchemaVersion: 1, Data: payload,
	}); err != nil {
		return api.ProtocolProfileStatus{}, fmt.Errorf("append eval protocol activation: %w", err)
	}
	c.gate.Activate()
	return c.status(), nil
}

func (c *evalProtocolProfileControl) status() api.ProtocolProfileStatus {
	return api.ProtocolProfileStatus{
		Profile: config.ProtocolProfileEval, Active: c.gate.Active(), Protocols: append([]string(nil), c.protocols...),
	}
}

func protocolActivationHandler(gate *protocolActivationGate, next http.Handler) http.Handler {
	if gate == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !gate.Active() {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"type":"about:blank","title":"eval protocol profile is not active","status":503}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
