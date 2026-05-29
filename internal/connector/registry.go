package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// DeployPayload is the JSON body of a "connector.deploy" outbox message: which
// connector deploys what, where. Key material is []byte (AN-8).
type DeployPayload struct {
	Connector   string `json:"connector"`
	Target      string `json:"target"`
	CertPEM     []byte `json:"cert_pem"`
	KeyPEM      []byte `json:"key_pem"`
	Fingerprint string `json:"fingerprint"`
}

// EncodeDeploy builds the outbox payload that deploys dep through the named
// connector. The orchestrator enqueues it on the outbox in the same transaction
// as the lifecycle state change (AN-6).
func EncodeDeploy(connectorName string, dep Deployment) ([]byte, error) {
	return json.Marshal(DeployPayload{
		Connector:   connectorName,
		Target:      dep.Target,
		CertPEM:     dep.CertPEM,
		KeyPEM:      dep.KeyPEM,
		Fingerprint: dep.Fingerprint,
	})
}

// Registry routes deploy payloads to registered connectors, running each under
// its declared capabilities. opsFor supplies the Ops a connector deploys
// through (real network/filesystem/exec in production; an in-memory double in
// tests).
type Registry struct {
	mu         sync.RWMutex
	connectors map[string]Connector
	opsFor     func(connectorName string) Ops
}

// NewRegistry returns a Registry that obtains a connector's Ops via opsFor.
func NewRegistry(opsFor func(connectorName string) Ops) *Registry {
	return &Registry{connectors: map[string]Connector{}, opsFor: opsFor}
}

// Register adds a connector under its Name.
func (r *Registry) Register(c Connector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectors[c.Name()] = c
}

// Handle decodes a deploy payload and runs the named connector. It is the body
// of the outbox handler (AN-6): wire it as
// outbox.HandlerFunc(func(ctx, m) error { return reg.Handle(ctx, m.Payload) }).
// It is idempotent insofar as the connector's Deploy is.
func (r *Registry) Handle(ctx context.Context, payload []byte) error {
	var p DeployPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("connector: decode deploy payload: %w", err)
	}
	r.mu.RLock()
	c := r.connectors[p.Connector]
	r.mu.RUnlock()
	if c == nil {
		return fmt.Errorf("connector: no connector registered as %q", p.Connector)
	}
	_, err := Run(ctx, c, r.opsFor(p.Connector), Deployment{
		Target: p.Target, CertPEM: p.CertPEM, KeyPEM: p.KeyPEM, Fingerprint: p.Fingerprint,
	})
	return err
}
