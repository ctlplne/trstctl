// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
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
	tlsPosture   map[string]bool
	vantage      map[string]TargetVantage
}

// ReplaySafety describes the receiver guarantee a connector offers across the
// outbox crash window between a successful remote mutation and the local
// delivery acknowledgment. Unknown and third-party connectors are deliberately
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
		tlsPosture:   map[string]bool{},
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

// CapabilitiesFor returns the sandbox capabilities a registered connector
// declares, sorted, so an operator can see what a delivery is permitted to do
// before authorizing one (B-6). A factory-registered connector builds its
// grant per attempt and has none to report here; an unknown name returns nil.
// This never constructs a connector: reporting must not run connector code.
func (r *Registry) CapabilitiesFor(name string) []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	c := r.connectors[name]
	if c == nil {
		return nil
	}
	caps := c.Capabilities().Capabilities()
	out := make([]string, 0, len(caps))
	for _, capability := range caps {
		out = append(out, string(capability))
	}
	sort.Strings(out)
	return out
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

// MarkTLSPostureCapable explicitly advertises that the named shipped connector
// implements the read/mutate/read-back TLS posture contract. Registration is
// deliberately separate from the structural type assertion: production
// composition must make an auditable, closed claim rather than accidentally
// serving a partial method set.
func (r *Registry) MarkTLSPostureCapable(name string) error {
	if r == nil || name == "" {
		return fmt.Errorf("connector: TLS posture capability requires registry and connector name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.connectors[name] == nil && r.factories[name] == nil {
		return fmt.Errorf("connector: cannot mark unregistered connector %q TLS-posture capable", name)
	}
	r.tlsPosture[name] = true
	return nil
}

// SupportsTLSPosture reports the explicit production registration claim.
func (r *Registry) SupportsTLSPosture(name string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tlsPosture[name] && (r.connectors[name] != nil || r.factories[name] != nil)
}

// ApplyTLSPosture drives a target-scoped native connector through read, mutate,
// and read-back. A failed or mismatched update restores the exact prior policy
// and verifies that rollback before returning an error.
func (r *Registry) ApplyTLSPosture(ctx context.Context, p TLSPostureMutation) (TLSPostureReceipt, error) {
	return r.applyTLSPosture(ctx, p, false)
}

// RestoreTLSPosture uses the same read/mutate/read-back and verified rollback
// machinery, but permits a structurally valid legacy desired state because an
// operator rollback must restore the exact observed pre-migration posture.
func (r *Registry) RestoreTLSPosture(ctx context.Context, p TLSPostureMutation) (TLSPostureReceipt, error) {
	return r.applyTLSPosture(ctx, p, true)
}

// ReadTLSPosture obtains the receiver state through the same immutable target
// revision, factory, capability grant, and bounded native read used by Apply.
// A licensed worker durably records this value before the first mutation.
func (r *Registry) ReadTLSPosture(ctx context.Context, p TLSPostureMutation) (TLSPosture, error) {
	if err := validateTLSPostureMutationContext(p); err != nil {
		return TLSPosture{}, err
	}
	postureConnector, sb, cleanup, err := r.resolveTLSPostureTarget(ctx, p)
	if err != nil {
		return TLSPosture{}, err
	}
	defer cleanup()
	observed, err := postureConnector.ReadTLSPosture(ctx, sb, p.Target)
	if err != nil {
		return TLSPosture{}, fmt.Errorf("connector: read current TLS posture: %w", err)
	}
	if err := ValidateObservedTLSPosture(observed); err != nil {
		return TLSPosture{}, fmt.Errorf("connector: current TLS posture is malformed: %w", err)
	}
	return cloneTLSPosture(observed), nil
}

func (r *Registry) applyTLSPosture(ctx context.Context, p TLSPostureMutation, allowLegacyDesired bool) (TLSPostureReceipt, error) {
	receipt := TLSPostureReceipt{
		RunID: p.RunID, FindingID: p.FindingID, FindingKind: p.FindingKind,
		TargetID: p.TargetID, TargetRevision: p.TargetRevision, Connector: p.Connector,
	}
	if err := validateTLSPostureMutationContext(p); err != nil {
		return receipt, err
	}
	validateDesired := ValidateTLSPosture
	if allowLegacyDesired {
		validateDesired = ValidateObservedTLSPosture
	}
	if err := validateDesired(p.Desired); err != nil {
		return receipt, err
	}
	if p.ExpectedPrevious != nil {
		if err := ValidateObservedTLSPosture(*p.ExpectedPrevious); err != nil {
			return receipt, fmt.Errorf("connector: expected previous TLS posture is malformed: %w", err)
		}
	}
	postureConnector, sb, cleanup, err := r.resolveTLSPostureTarget(ctx, p)
	if err != nil {
		return receipt, err
	}
	defer cleanup()
	previous, err := postureConnector.ReadTLSPosture(ctx, sb, p.Target)
	if err != nil {
		return receipt, fmt.Errorf("connector: read current TLS posture: %w", err)
	}
	if err := ValidateObservedTLSPosture(previous); err != nil {
		return receipt, fmt.Errorf("connector: current TLS posture is malformed: %w", err)
	}
	if p.ExpectedPrevious != nil {
		expected := cloneTLSPosture(*p.ExpectedPrevious)
		receipt.Previous = expected
		if EqualTLSPosture(previous, p.Desired) {
			receipt.Observed = cloneTLSPosture(previous)
			return receipt, nil
		}
		if !EqualTLSPosture(previous, expected) {
			return receipt, fmt.Errorf("connector: current TLS posture changed after durable preparation")
		}
	} else {
		receipt.Previous = cloneTLSPosture(previous)
		if EqualTLSPosture(previous, p.Desired) {
			receipt.Observed = cloneTLSPosture(previous)
			return receipt, nil
		}
	}
	rollback := func(cause error) (TLSPostureReceipt, error) {
		if rbErr := postureConnector.ApplyTLSPosture(ctx, sb, p.Target, previous); rbErr != nil {
			return receipt, fmt.Errorf("connector: TLS posture update failed and rollback failed: update=%v rollback=%w", cause, rbErr)
		}
		restored, rbErr := postureConnector.ReadTLSPosture(ctx, sb, p.Target)
		if rbErr != nil || !EqualTLSPosture(restored, previous) {
			return receipt, fmt.Errorf("connector: TLS posture update failed and rollback read-back did not match: update=%v rollback=%v", cause, rbErr)
		}
		return receipt, fmt.Errorf("connector: TLS posture update failed; rollback verified: %w", cause)
	}
	if err := postureConnector.ApplyTLSPosture(ctx, sb, p.Target, p.Desired); err != nil {
		return rollback(err)
	}
	observed, err := postureConnector.ReadTLSPosture(ctx, sb, p.Target)
	if err != nil {
		return rollback(fmt.Errorf("read-back: %w", err))
	}
	if err := ValidateObservedTLSPosture(observed); err != nil {
		return rollback(fmt.Errorf("malformed read-back: %w", err))
	}
	if !EqualTLSPosture(observed, p.Desired) {
		return rollback(fmt.Errorf("read-back differs from desired posture"))
	}
	receipt.Observed = cloneTLSPosture(observed)
	receipt.Applied = true
	return receipt, nil
}

func validateTLSPostureMutationContext(p TLSPostureMutation) error {
	if p.RunID == "" || p.FindingID == "" || p.TargetID == "" || p.TargetRevision == "" || p.Connector == "" || p.Target == "" || p.TenantID == "" {
		return fmt.Errorf("connector: TLS posture mutation requires run, finding, target, revision, connector, target name, and authoritative tenant")
	}
	return nil
}

func (r *Registry) resolveTLSPostureTarget(ctx context.Context, p TLSPostureMutation) (TLSPostureConnector, Sandbox, func(), error) {
	if r == nil {
		return nil, nil, nil, fmt.Errorf("connector: registry is not configured")
	}
	r.mu.RLock()
	c := r.connectors[p.Connector]
	factory := r.factories[p.Connector]
	opsFor := r.opsFor
	capable := r.tlsPosture[p.Connector]
	r.mu.RUnlock()
	if !capable || (c == nil && factory == nil) {
		return nil, nil, nil, fmt.Errorf("connector: %q does not support TLS posture mutation", p.Connector)
	}
	var (
		ops     Ops
		cleanup func()
		err     error
	)
	if factory != nil {
		c, ops, cleanup, err = factory(ctx, DeployPayload{
			TargetID: p.TargetID, TargetRevision: p.TargetRevision, Connector: p.Connector,
			Target: p.Target, TargetConfig: append(json.RawMessage(nil), p.TargetConfig...), TenantID: p.TenantID,
		})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("connector: build TLS posture target %q: %w", p.Connector, err)
		}
	} else if opsFor != nil {
		ops = opsFor(p.Connector)
	}
	postureConnector, ok := c.(TLSPostureConnector)
	if !ok || postureConnector == nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, nil, fmt.Errorf("connector: %q advertised TLS posture without implementing the contract", p.Connector)
	}
	if ops == nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, nil, fmt.Errorf("connector: no ops configured for %q", p.Connector)
	}
	sb := &sandbox{ctx: ctx, grant: c.Capabilities(), ops: ops}
	if cleanup == nil {
		cleanup = func() {}
	}
	return postureConnector, sb, cleanup, nil
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

// Preview constructs the same immutable, tenant-scoped target connector a
// deployment would use, including one-attempt secret leases, but dispatches only
// its explicit effect-free Preview contract. It rejects credential-bearing
// payloads because a target test never needs certificate or private-key bytes.
func (r *Registry) Preview(ctx context.Context, p DeployPayload) (Preview, error) {
	if r == nil {
		return Preview{}, fmt.Errorf("connector: registry is not configured")
	}
	if p.TenantID == "" || p.TargetID == "" || p.TargetRevision == "" || p.Connector == "" || p.Target == "" {
		return Preview{}, fmt.Errorf("connector: preview requires tenant, target, revision, connector, and target name")
	}
	if len(p.CertPEM) != 0 || len(p.KeyPEM) != 0 || p.Fingerprint != "" {
		return Preview{}, fmt.Errorf("connector: preview payload must not contain certificate or private-key material")
	}
	r.mu.RLock()
	c := r.connectors[p.Connector]
	factory := r.factories[p.Connector]
	opsFor := r.opsFor
	r.mu.RUnlock()
	if c == nil && factory == nil {
		return Preview{}, fmt.Errorf("connector: no connector registered as %q", p.Connector)
	}
	var (
		ops     Ops
		cleanup func()
		err     error
	)
	if factory != nil {
		c, ops, cleanup, err = factory(ctx, p)
		if err != nil {
			return Preview{}, fmt.Errorf("connector: build preview target %q: %w", p.Connector, err)
		}
		if cleanup != nil {
			defer cleanup()
		}
	} else if opsFor != nil {
		ops = opsFor(p.Connector)
	}
	if c == nil {
		return Preview{}, fmt.Errorf("connector: factory returned no connector for %q", p.Connector)
	}
	if ops == nil {
		return Preview{}, fmt.Errorf("connector: no ops configured for %q", p.Connector)
	}
	return RunPreview(ctx, c, ops, p.Target)
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

// TargetVantage declares where a connector's deploy work must EXECUTE (epic A3).
// It is a property of what the target physically is, decided at registration by
// the shipped census in the control plane's composition root — never derived
// from transport details and never taken from a tenant's request.
//
// The distinction matters because it decides which agent role may claim the
// work (A2): a host agent acts on the machine it runs on, a network relay acts
// on things that cannot run an agent at all.
type TargetVantage string

const (
	// VantageControlPlane: the work executes inside the control plane process.
	// This is the fail-closed default for anything undeclared, and the permanent
	// home of targets that are neither a host nor an in-segment appliance (cloud
	// certificate stores reached over public APIs). Control-plane execution for
	// host/appliance targets is the deprecated interim (doctrine D5) — the
	// declaration is what lets the claim path move the work out.
	VantageControlPlane TargetVantage = "control_plane"
	// VantageHostAgent: the connector mutates the machine it runs on — files,
	// local exec, a co-resident service reload. The right executor is an agent
	// ON that machine, holding the host role.
	VantageHostAgent TargetVantage = "host_agent"
	// VantageNetworkRelay: the target is an appliance or device that cannot host
	// an agent (an F5, a NetScaler, a firewall) and is driven over its API from
	// inside its network segment. The right executor is a relay holding the
	// network role.
	VantageNetworkRelay TargetVantage = "network_relay"
)

// validTargetVantage reports whether v is a declared vantage value.
func validTargetVantage(v TargetVantage) bool {
	switch v {
	case VantageControlPlane, VantageHostAgent, VantageNetworkRelay:
		return true
	default:
		return false
	}
}

// DeclareTargetVantage records where a registered connector's work executes.
// Like MarkTLSPostureCapable, it is a separate, auditable registration step
// rather than a method on the Connector interface: the census is a closed claim
// made by the composition root, not something connector code asserts about
// itself. Declaring an unknown vantage or an unregistered connector errors so a
// typo cannot silently leave a connector control-plane-bound.
func (r *Registry) DeclareTargetVantage(name string, vantage TargetVantage) error {
	if r == nil || name == "" {
		return fmt.Errorf("connector: target vantage requires registry and connector name")
	}
	if !validTargetVantage(vantage) {
		return fmt.Errorf("connector: %q declares unknown target vantage %q", name, vantage)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factories[name] == nil && r.connectors[name] == nil {
		return fmt.Errorf("connector: cannot declare vantage for unregistered connector %q", name)
	}
	if r.vantage == nil {
		r.vantage = map[string]TargetVantage{}
	}
	r.vantage[name] = vantage
	return nil
}

// TargetVantageFor returns where the named connector's work executes. Undeclared
// or unknown names fail closed to VantageControlPlane: work nobody has audited
// for agent execution stays where it always ran, rather than becoming claimable
// by an agent that cannot perform it — mirroring how an undeclared job kind is
// refused at claim time.
func (r *Registry) TargetVantageFor(name string) TargetVantage {
	if r == nil {
		return VantageControlPlane
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if v, ok := r.vantage[name]; ok && validTargetVantage(v) {
		return v
	}
	return VantageControlPlane
}
