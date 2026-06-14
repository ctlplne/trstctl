// Package nhi manages non-human identity lifecycle (S16.2, F59): the machine
// identities and service accounts themselves — create, scope, rotate, disable,
// expire — as a governed surface, not just their credentials. Identities are
// tenant-scoped (AN-1), every transition is audited (AN-2), and lifecycle state is
// represented in the credential graph (F21).
package nhi

import (
	"context"
	"fmt"
	"sync"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/graph"
)

// State is the lifecycle state of an identity.
type State string

const (
	StateActive   State = "active"
	StateDisabled State = "disabled"
	StateRetired  State = "retired" // terminal
)

// Identity is a governed non-human identity.
type Identity struct {
	ID        string
	TenantID  string
	Owner     string
	State     State
	Scopes    []string
	Rotations int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Config configures a Manager.
type Config struct {
	TenantID string
	Graph    *graph.Graph
	Audit    auditsink.Auditor
	Clock    func() time.Time
}

// Manager runs identity lifecycle workflows.
type Manager struct {
	cfg Config
	mu  sync.Mutex
	ids map[string]Identity
}

// New validates configuration and constructs a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("nhi: TenantID required (AN-1)")
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Manager{cfg: cfg, ids: map[string]Identity{}}, nil
}

func nodeID(id string) string { return "nhi:" + id }

// Create registers a new active identity and maps it into the graph.
func (m *Manager) Create(ctx context.Context, id, owner string, scopes []string) (Identity, error) {
	if id == "" || owner == "" {
		return Identity{}, fmt.Errorf("nhi: id and owner required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ids[id]; ok {
		return Identity{}, fmt.Errorf("nhi: identity %q already exists", id)
	}
	now := m.cfg.Clock()
	idt := Identity{ID: id, TenantID: m.cfg.TenantID, Owner: owner, State: StateActive, Scopes: scopes, CreatedAt: now, UpdatedAt: now}
	m.ids[id] = idt
	m.sync(idt)
	m.audit(ctx, "nhi.created", id, string(StateActive))
	return idt, nil
}

// Scope updates an identity's scopes (must be active).
func (m *Manager) Scope(ctx context.Context, id string, scopes []string) error {
	return m.mutate(ctx, id, "nhi.scoped", func(idt *Identity) error {
		if idt.State != StateActive {
			return fmt.Errorf("nhi: %q is not active", id)
		}
		idt.Scopes = scopes
		return nil
	})
}

// Rotate records a credential rotation for the identity (must be active).
func (m *Manager) Rotate(ctx context.Context, id string) error {
	return m.mutate(ctx, id, "nhi.rotated", func(idt *Identity) error {
		if idt.State != StateActive {
			return fmt.Errorf("nhi: %q is not active", id)
		}
		idt.Rotations++
		return nil
	})
}

// Disable suspends an identity.
func (m *Manager) Disable(ctx context.Context, id string) error {
	return m.mutate(ctx, id, "nhi.disabled", func(idt *Identity) error {
		if idt.State == StateRetired {
			return fmt.Errorf("nhi: %q is retired", id)
		}
		idt.State = StateDisabled
		return nil
	})
}

// Expire retires an identity (terminal).
func (m *Manager) Expire(ctx context.Context, id string) error {
	return m.mutate(ctx, id, "nhi.expired", func(idt *Identity) error {
		idt.State = StateRetired
		return nil
	})
}

// Get returns an identity.
func (m *Manager) Get(id string) (Identity, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idt, ok := m.ids[id]
	return idt, ok
}

func (m *Manager) mutate(ctx context.Context, id, event string, fn func(*Identity) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	idt, ok := m.ids[id]
	if !ok {
		return fmt.Errorf("nhi: unknown identity %q", id)
	}
	if err := fn(&idt); err != nil {
		return err
	}
	idt.UpdatedAt = m.cfg.Clock()
	m.ids[id] = idt
	m.sync(idt)
	m.audit(ctx, event, id, string(idt.State))
	return nil
}

func (m *Manager) sync(idt Identity) {
	if m.cfg.Graph == nil {
		return
	}
	m.cfg.Graph.AddNode(graph.Node{
		ID: nodeID(idt.ID), Kind: graph.KindWorkload, Name: idt.ID,
		Attrs: map[string]string{"tenant_id": idt.TenantID, "owner": idt.Owner, "state": string(idt.State)},
	})
}

func (m *Manager) audit(ctx context.Context, event, id, state string) {
	_ = m.cfg.Audit.Audit(ctx, event, m.cfg.TenantID, []byte(fmt.Sprintf(`{"id":%q,"state":%q}`, id, state)))
}
