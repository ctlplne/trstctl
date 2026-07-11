// SPDX-License-Identifier: MPL-2.0

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
	IdentityID     string          `json:"identity_id,omitempty"`
	TargetID       string          `json:"target_id,omitempty"`
	TargetRevision string          `json:"target_revision,omitempty"`
	Connector      string          `json:"connector"`
	Target         string          `json:"target"`
	TargetConfig   json.RawMessage `json:"target_config,omitempty"`
	CertPEM        []byte          `json:"cert_pem"`
	KeyPEM         []byte          `json:"key_pem"`
	Fingerprint    string          `json:"fingerprint"`

	// TenantID is authoritative dispatch context supplied from the outbox
	// envelope. It is never accepted from durable JSON (AN-1).
	TenantID string `json:"-"`
}

// EncodeDeploy builds the outbox payload that deploys dep through the named
// connector. The orchestrator enqueues it on the outbox in the same transaction
// as the lifecycle state change (AN-6).
func EncodeDeploy(connectorName string, dep Deployment) ([]byte, error) {
	return EncodeIdentityDeploy(connectorName, "", dep)
}

// EncodeIdentityDeploy builds an outbox payload tied to an identity lifecycle
// deployment. The identity_id is routing evidence only; connector implementations
// still receive only the Deployment.
func EncodeIdentityDeploy(connectorName, identityID string, dep Deployment) ([]byte, error) {
	return json.Marshal(DeployPayload{
		IdentityID:  identityID,
		Connector:   connectorName,
		Target:      dep.Target,
		CertPEM:     dep.CertPEM,
		KeyPEM:      dep.KeyPEM,
		Fingerprint: dep.Fingerprint,
	})
}

// EncodeTargetIdentityDeploy pins the immutable event revision of the tenant's
// deployment target into the sealed outbox intent. Config contains metadata and
// secret:// references only; the dispatcher resolves secret bytes just in time.
func EncodeTargetIdentityDeploy(connectorName, identityID, targetID, revisionID string, targetConfig json.RawMessage, dep Deployment) ([]byte, error) {
	return json.Marshal(DeployPayload{
		IdentityID: identityID, TargetID: targetID, TargetRevision: revisionID,
		Connector: connectorName, Target: dep.Target,
		TargetConfig: append(json.RawMessage(nil), targetConfig...),
		CertPEM:      dep.CertPEM, KeyPEM: dep.KeyPEM, Fingerprint: dep.Fingerprint,
	})
}

// Registry routes deploy payloads to registered connectors, running each under
// its declared capabilities. opsFor supplies the Ops a connector deploys
// through (real network/filesystem/exec in production; an in-memory double in
// tests).
type Registry struct {
	mu           sync.RWMutex
	connectors   map[string]Connector
	opsFor       func(connectorName string) Ops
	factories    map[string]Factory
	replaySafety map[string]ReplaySafety
}

// ReplaySafety describes the receiver guarantee a connector offers across the
// outbox crash window between a successful remote mutation and the local
// delivery acknowledgement. Unknown and third-party connectors are deliberately
// AtMostOnce: claiming them before I/O is safer than guessing that a repeated
// POST/import is harmless.
type ReplaySafety uint8

const (
	ReplaySafetyAtMostOnce ReplaySafety = iota
	ReplaySafetyReconciled
)

func validReplaySafety(safety ReplaySafety) bool {
	return safety == ReplaySafetyAtMostOnce || safety == ReplaySafetyReconciled
}

// Factory constructs one target-scoped connector and its privileged Ops for a
// single delivery attempt. The returned cleanup function must destroy every
// credential lease and connector-owned secret. Production uses factories so
// two tenants never share a singleton containing another target's paths, URL,
// or credentials.
type Factory func(context.Context, DeployPayload) (Connector, Ops, func(), error)

// NewRegistry returns a Registry that obtains a connector's Ops via opsFor.
func NewRegistry(opsFor ...func(connectorName string) Ops) *Registry {
	var provider func(string) Ops
	if len(opsFor) > 0 {
		provider = opsFor[0]
	}
	return &Registry{
		connectors:   map[string]Connector{},
		factories:    map[string]Factory{},
		replaySafety: map[string]ReplaySafety{},
		opsFor:       provider,
	}
}

// Register adds a connector under its Name using the conservative at-most-once
// policy. A connector is replay-safe only through the explicit registration
// method below; implementing Connector alone is not proof of a receiver-native
// idempotency token or deterministic reconciliation.
func (r *Registry) Register(c Connector) {
	r.RegisterWithReplaySafety(c, ReplaySafetyAtMostOnce)
}

// RegisterWithReplaySafety adds a connector together with its audited receiver
// replay contract. Production composition uses this for shipped connectors;
// signed/third-party connectors stay at-most-once unless a future interface adds
// an enforceable replay proof.
func (r *Registry) RegisterWithReplaySafety(c Connector, safety ReplaySafety) {
	if r == nil || c == nil || !validReplaySafety(safety) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectors[c.Name()] = c
	r.replaySafety[c.Name()] = safety
}

// RegisterFactory adds a production target-scoped constructor. It returns an
// error instead of silently replacing an existing implementation because a
// duplicate name would make startup order decide which external system receives
// private key material.
func (r *Registry) RegisterFactory(name string, factory Factory) error {
	return r.RegisterFactoryWithReplaySafety(name, factory, ReplaySafetyAtMostOnce)
}

// RegisterFactoryWithReplaySafety is RegisterFactory with an explicit audited
// receiver replay contract. The default RegisterFactory remains conservative.
func (r *Registry) RegisterFactoryWithReplaySafety(name string, factory Factory, safety ReplaySafety) error {
	if r == nil || name == "" || factory == nil {
		return fmt.Errorf("connector: factory requires registry, name, and constructor")
	}
	if !validReplaySafety(safety) {
		return fmt.Errorf("connector: factory %q has an invalid replay-safety classification", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factories[name] != nil || r.connectors[name] != nil {
		return fmt.Errorf("connector: duplicate registration for %q", name)
	}
	r.factories[name] = factory
	r.replaySafety[name] = safety
	return nil
}

// Has reports whether a connector is registered under name.
func (r *Registry) Has(name string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.connectors[name] != nil || r.factories[name] != nil
}

// ReplaySafetyFor returns the audited replay contract for a registered
// connector. Missing metadata fails closed to AtMostOnce.
func (r *Registry) ReplaySafetyFor(name string) ReplaySafety {
	if r == nil {
		return ReplaySafetyAtMostOnce
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if safety, ok := r.replaySafety[name]; ok && validReplaySafety(safety) {
		return safety
	}
	return ReplaySafetyAtMostOnce
}

// Deploy routes an already decoded payload to the named connector.
func (r *Registry) Deploy(ctx context.Context, p DeployPayload) error {
	if r == nil {
		return fmt.Errorf("connector: registry is not configured")
	}
	r.mu.RLock()
	c := r.connectors[p.Connector]
	factory := r.factories[p.Connector]
	opsFor := r.opsFor
	r.mu.RUnlock()
	if c == nil && factory == nil {
		return fmt.Errorf("connector: no connector registered as %q", p.Connector)
	}
	var (
		ops     Ops
		cleanup func()
		err     error
	)
	if factory != nil {
		c, ops, cleanup, err = factory(ctx, p)
		if err != nil {
			return fmt.Errorf("connector: build target %q: %w", p.Connector, err)
		}
		if cleanup != nil {
			defer cleanup()
		}
	} else if opsFor != nil {
		ops = opsFor(p.Connector)
	}
	if c == nil {
		return fmt.Errorf("connector: factory returned no connector for %q", p.Connector)
	}
	if ops == nil {
		return fmt.Errorf("connector: no ops configured for %q", p.Connector)
	}
	_, err = Run(ctx, c, ops, Deployment{
		Target: p.Target, CertPEM: p.CertPEM, KeyPEM: p.KeyPEM, Fingerprint: p.Fingerprint,
	})
	return err
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
	return r.Deploy(ctx, p)
}
