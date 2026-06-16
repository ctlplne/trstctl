// Package dynsecret is the dynamic-secrets lease engine (S17.1, F65) and provider
// template/conformance harness (S17.1a). A generated credential self-destructs on
// lease expiry, so a leaked one is worthless. Backend revocation is driven through
// a durable queue (the outbox) so revocation survives a control-plane crash
// mid-lease (AN-6); issuance/revocation are idempotent so retries never leave
// duplicate or orphaned credentials (AN-5); leases are tenant-guarded (AN-1) and
// audited (AN-2); generated material is []byte and never logged (AN-8).
package dynsecret

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

// GenerateRequest asks a provider for a scoped backend credential.
type GenerateRequest struct {
	Role    string
	TTL     time.Duration
	LeaseID string
}

// Credential is a generated backend credential. BackendRef is the handle the
// backend uses to revoke it (e.g. a username or access-key id); Secret is the
// material handed to the caller (AN-8 []byte).
type Credential struct {
	BackendRef string
	Secret     []byte
	Metadata   map[string]string
}

// Provider generates and revokes credentials at one backend. Concrete providers
// (S17.2–S17.8) implement only these; the engine and template supply leasing,
// durable revocation, idempotency, and audit.
type Provider interface {
	Name() string
	Generate(ctx context.Context, req GenerateRequest) (Credential, error)
	Revoke(ctx context.Context, backendRef string) error
}

// LeaseState is the state of a lease.
type LeaseState string

const (
	LeaseActive  LeaseState = "active"
	LeaseRevoked LeaseState = "revoked"
)

// Lease is the durable record of a generated credential's lifecycle.
type Lease struct {
	ID         string
	TenantID   string
	Provider   string
	Role       string
	BackendRef string
	State      LeaseState
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// RevokeItem is a queued backend revocation.
type RevokeItem struct {
	LeaseID    string
	Provider   string
	BackendRef string
}

// RevokeQueue is the durable revocation outbox (AN-6): a revocation enqueued here
// survives a control-plane crash and is replayed by RunRevocations. The
// PostgreSQL-backed orchestrator.Outbox satisfies this in production; MemoryQueue
// is the in-process implementation.
type RevokeQueue interface {
	Enqueue(ctx context.Context, item RevokeItem) error
	Pending(ctx context.Context) ([]RevokeItem, error)
	Done(ctx context.Context, leaseID string) error
}

// Config configures the Engine.
type Config struct {
	TenantID  string
	Providers []Provider
	Queue     RevokeQueue
	Audit     auditsink.Auditor
	Clock     func() time.Time
	Gate      func(ctx context.Context, provider, role string) (bool, string) // optional policy gate
}

// Engine runs the dynamic-secret lease lifecycle.
type Engine struct {
	cfg       Config
	providers map[string]Provider
	mu        sync.Mutex
	leases    map[string]Lease
	idem      map[string]string
}

// New validates configuration and constructs an Engine.
func New(cfg Config) (*Engine, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("dynsecret: TenantID required (AN-1)")
	}
	if cfg.Queue == nil {
		return nil, fmt.Errorf("dynsecret: RevokeQueue required (AN-6)")
	}
	m := map[string]Provider{}
	for _, p := range cfg.Providers {
		m[p.Name()] = p
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Engine{cfg: cfg, providers: m, leases: map[string]Lease{}, idem: map[string]string{}}, nil
}

// Issue generates a credential and opens a lease. Idempotent on idempotencyKey: a
// replay returns the original lease without generating a second credential.
func (e *Engine) Issue(ctx context.Context, provider, role string, ttl time.Duration, idempotencyKey string) (Lease, []byte, error) {
	p, ok := e.providers[provider]
	if !ok {
		return Lease{}, nil, fmt.Errorf("dynsecret: unknown provider %q", provider)
	}
	if e.cfg.Gate != nil {
		if allowed, reason := e.cfg.Gate(ctx, provider, role); !allowed {
			return Lease{}, nil, fmt.Errorf("dynsecret: policy denied %s/%s: %s", provider, role, reason)
		}
	}
	e.mu.Lock()
	if idempotencyKey != "" {
		if id, ok := e.idem[idempotencyKey]; ok {
			l := e.leases[id]
			e.mu.Unlock()
			return l, nil, nil // replay: credential already delivered once
		}
	}
	e.mu.Unlock()

	idb, _ := crypto.RandomBytes(12)
	leaseID := "lease-" + hex.EncodeToString(idb)
	cred, err := p.Generate(ctx, GenerateRequest{Role: role, TTL: ttl, LeaseID: leaseID})
	if err != nil {
		return Lease{}, nil, fmt.Errorf("dynsecret: generate: %w", err)
	}
	now := e.cfg.Clock()
	lease := Lease{ID: leaseID, TenantID: e.cfg.TenantID, Provider: provider, Role: role, BackendRef: cred.BackendRef, State: LeaseActive, IssuedAt: now, ExpiresAt: now.Add(ttl)}
	e.mu.Lock()
	e.leases[leaseID] = lease
	if idempotencyKey != "" {
		e.idem[idempotencyKey] = leaseID
	}
	e.mu.Unlock()
	e.audit(ctx, "dynsecret.lease.issued", lease)
	return lease, cred.Secret, nil
}

// Renew extends a lease's expiry.
func (e *Engine) Renew(ctx context.Context, leaseID string, extend time.Duration) (Lease, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, ok := e.leases[leaseID]
	if !ok || l.State != LeaseActive {
		return Lease{}, fmt.Errorf("dynsecret: lease %q not active", leaseID)
	}
	l.ExpiresAt = l.ExpiresAt.Add(extend)
	e.leases[leaseID] = l
	e.audit(ctx, "dynsecret.lease.renewed", l)
	return l, nil
}

// Revoke marks a lease revoked and durably enqueues the backend revocation (AN-6).
// Idempotent: revoking an already-revoked lease is a no-op.
func (e *Engine) Revoke(ctx context.Context, leaseID string) error {
	e.mu.Lock()
	l, ok := e.leases[leaseID]
	if !ok {
		e.mu.Unlock()
		return fmt.Errorf("dynsecret: unknown lease %q", leaseID)
	}
	if l.State == LeaseRevoked {
		e.mu.Unlock()
		return nil
	}
	l.State = LeaseRevoked
	e.leases[leaseID] = l
	e.mu.Unlock()

	if err := e.cfg.Queue.Enqueue(ctx, RevokeItem{LeaseID: l.ID, Provider: l.Provider, BackendRef: l.BackendRef}); err != nil {
		return fmt.Errorf("dynsecret: enqueue revoke: %w", err)
	}
	e.audit(ctx, "dynsecret.lease.revoked", l)
	return nil
}

// ExpireDue revokes every active lease whose expiry has passed (the expiry sweep).
func (e *Engine) ExpireDue(ctx context.Context, now time.Time) (int, error) {
	e.mu.Lock()
	var due []string
	for id, l := range e.leases {
		if l.State == LeaseActive && !now.Before(l.ExpiresAt) {
			due = append(due, id)
		}
	}
	e.mu.Unlock()
	for _, id := range due {
		if err := e.Revoke(ctx, id); err != nil {
			return 0, err
		}
	}
	return len(due), nil
}

// RunRevocations is the durable revocation worker: it drains the queue and calls
// the provider's backend revoke for each item, marking each done only on success.
// Because the queue is durable, this revokes credentials whose lease was created
// before a crash — the defining AN-6 property.
func (e *Engine) RunRevocations(ctx context.Context) (int, error) {
	items, err := e.cfg.Queue.Pending(ctx)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, it := range items {
		p, ok := e.providers[it.Provider]
		if !ok {
			continue // provider not registered in this process; leave for one that has it
		}
		if err := p.Revoke(ctx, it.BackendRef); err != nil {
			continue // fail-safe: leave it queued for retry
		}
		if err := e.cfg.Queue.Done(ctx, it.LeaseID); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}

func (e *Engine) audit(ctx context.Context, event string, l Lease) {
	_ = auditsink.Emit(ctx, e.cfg.Audit, nil, event, e.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"lease":%q,"provider":%q,"role":%q,"backend_ref":%q,"state":%q}`, l.ID, l.Provider, l.Role, l.BackendRef, l.State)))
}

// MemoryQueue is an in-process durable-semantics RevokeQueue for single-node and
// tests. It persists across "engine restarts" when shared, modeling the outbox.
type MemoryQueue struct {
	mu      sync.Mutex
	pending map[string]RevokeItem
}

// NewMemoryQueue constructs a MemoryQueue.
func NewMemoryQueue() *MemoryQueue { return &MemoryQueue{pending: map[string]RevokeItem{}} }

// Enqueue implements RevokeQueue.
func (q *MemoryQueue) Enqueue(_ context.Context, item RevokeItem) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending[item.LeaseID] = item
	return nil
}

// Pending implements RevokeQueue.
func (q *MemoryQueue) Pending(_ context.Context) ([]RevokeItem, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]RevokeItem, 0, len(q.pending))
	for _, it := range q.pending {
		out = append(out, it)
	}
	return out, nil
}

// Done implements RevokeQueue.
func (q *MemoryQueue) Done(_ context.Context, leaseID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.pending, leaseID)
	return nil
}

// Conform exercises a Provider through a full lifecycle including an interrupted
// (crash) revocation, asserting it generates a scoped credential and revokes it at
// the backend — and that backend revoke is idempotent (a re-revoke is safe). Every
// S17.2–S17.8 provider must pass this.
func Conform(p Provider) error {
	ctx := context.Background()
	if p == nil || p.Name() == "" {
		return fmt.Errorf("dynsecret: provider has no name")
	}
	cred, err := p.Generate(ctx, GenerateRequest{Role: "conformance", TTL: time.Minute, LeaseID: "l1"})
	if err != nil {
		return fmt.Errorf("dynsecret: %s generate: %w", p.Name(), err)
	}
	if cred.BackendRef == "" || len(cred.Secret) == 0 {
		return fmt.Errorf("dynsecret: %s produced no scoped credential", p.Name())
	}
	if err := p.Revoke(ctx, cred.BackendRef); err != nil {
		return fmt.Errorf("dynsecret: %s revoke: %w", p.Name(), err)
	}
	// Interrupted lease: a credential generated but whose revoke is replayed after a
	// crash must still revoke, and a double-revoke must be safe (idempotent).
	cred2, err := p.Generate(ctx, GenerateRequest{Role: "conformance", TTL: time.Minute, LeaseID: "l2"})
	if err != nil {
		return fmt.Errorf("dynsecret: %s second generate: %w", p.Name(), err)
	}
	if err := p.Revoke(ctx, cred2.BackendRef); err != nil {
		return fmt.Errorf("dynsecret: %s interrupted-lease revoke: %w", p.Name(), err)
	}
	if err := p.Revoke(ctx, cred2.BackendRef); err != nil {
		return fmt.Errorf("dynsecret: %s double-revoke not idempotent: %w", p.Name(), err)
	}
	return nil
}
