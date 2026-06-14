// Package approval implements JIT issuance with approval flows (S12.3, F33):
// approval is a first-class issuance state (requested → awaiting-approval →
// approve/deny → issue) with dual control, time-bounded grants, and
// policy-scoped approvers. It is deliberately generic over what is being issued
// (a Resource string + an Issuer seam) so the same primitive is later reused for
// secret-change approvals (F60) and the developer self-service portal.
//
// The request→approve→issue chain is audited with both actors (AN-2). Approval is
// idempotent (AN-5): re-approving by the same approver, or acting on a terminal
// request, is a no-op that returns the current state.
package approval

import (
	"context"
	"fmt"
	"sync"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
)

// State is the issuance-approval state.
type State string

const (
	StateAwaitingApproval State = "awaiting_approval"
	StateApproved         State = "approved"
	StateDenied           State = "denied"
	StateIssued           State = "issued"
	StateExpired          State = "expired"
)

// Approval is one approver's decision.
type Approval struct {
	Approver string    `json:"approver"`
	Decision string    `json:"decision"` // "approve" | "deny"
	At       time.Time `json:"at"`
}

// Request is the first-class approval state for an issuance.
type Request struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	Resource          string     `json:"resource"`
	Requester         string     `json:"requester"`
	RequiredApprovals int        `json:"required_approvals"`
	Approvals         []Approval `json:"approvals"`
	State             State      `json:"state"`
	CredentialID      string     `json:"credential_id,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
}

// Store persists requests (tenant-scoped, AN-1).
type Store interface {
	Save(ctx context.Context, req Request) error
	Get(ctx context.Context, tenantID, id string) (Request, bool, error)
}

// ApproverPolicy reports whether an approver may approve a request (policy-scoped
// approvers).
type ApproverPolicy interface {
	CanApprove(ctx context.Context, tenantID, requestID, approver string) (allowed bool, reason string)
}

// Notifier delivers an approval request to a channel (Slack/Teams).
type Notifier interface {
	NotifyApprovalRequest(ctx context.Context, req Request) error
}

// Issuer mints the credential once a request is approved.
type Issuer interface {
	Issue(ctx context.Context, tenantID, requestID, resource string) (credentialID string, err error)
}

// Config configures a Manager.
type Config struct {
	TenantID                 string
	Store                    Store
	Policy                   ApproverPolicy
	Notifier                 Notifier
	Issuer                   Issuer
	Audit                    auditsink.Auditor
	DefaultTTL               time.Duration
	DefaultRequiredApprovals int
	Clock                    func() time.Time
}

// Manager runs the approval state machine.
type Manager struct {
	cfg Config
}

// New validates configuration and constructs a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("approval: TenantID required (AN-1)")
	}
	if cfg.Store == nil || cfg.Issuer == nil {
		return nil, fmt.Errorf("approval: Store and Issuer required")
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = time.Hour
	}
	if cfg.DefaultRequiredApprovals <= 0 {
		cfg.DefaultRequiredApprovals = 2 // dual control
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Manager{cfg: cfg}, nil
}

// RequestSpec describes a new approval request.
type RequestSpec struct {
	ID                string
	Resource          string
	Requester         string
	RequiredApprovals int           // 0 → default (dual control)
	TTL               time.Duration // 0 → default
}

// RequestIssuance creates an approval request in awaiting-approval state and
// notifies approvers. Nothing is issued yet.
func (m *Manager) RequestIssuance(ctx context.Context, spec RequestSpec) (Request, error) {
	if spec.ID == "" || spec.Requester == "" || spec.Resource == "" {
		return Request{}, fmt.Errorf("approval: ID, Requester and Resource are required")
	}
	now := m.cfg.Clock()
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = m.cfg.DefaultTTL
	}
	req := Request{
		ID: spec.ID, TenantID: m.cfg.TenantID, Resource: spec.Resource, Requester: spec.Requester,
		RequiredApprovals: spec.RequiredApprovals, State: StateAwaitingApproval,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if req.RequiredApprovals <= 0 {
		req.RequiredApprovals = m.cfg.DefaultRequiredApprovals
	}
	if err := m.cfg.Store.Save(ctx, req); err != nil {
		return Request{}, err
	}
	if m.cfg.Notifier != nil {
		_ = m.cfg.Notifier.NotifyApprovalRequest(ctx, req)
	}
	m.audit(ctx, "approval.requested", fmt.Sprintf(`{"id":%q,"requester":%q,"resource":%q,"required":%d}`,
		req.ID, req.Requester, req.Resource, req.RequiredApprovals))
	return req, nil
}

// Approve records an approval. On reaching the required count it issues (dual
// control, policy-scoped, time-bounded). It is idempotent and fails closed.
func (m *Manager) Approve(ctx context.Context, tenantID, reqID, approver string) (Request, error) {
	req, ok, err := m.cfg.Store.Get(ctx, tenantID, reqID)
	if err != nil {
		return Request{}, err
	}
	if !ok {
		return Request{}, fmt.Errorf("approval: unknown request %q", reqID)
	}
	if req.State == StateIssued || req.State == StateDenied {
		return req, nil // terminal: idempotent no-op
	}
	now := m.cfg.Clock()
	if req.State == StateExpired || now.After(req.ExpiresAt) {
		if req.State != StateExpired {
			req.State = StateExpired
			_ = m.cfg.Store.Save(ctx, req)
			m.audit(ctx, "approval.expired", fmt.Sprintf(`{"id":%q}`, req.ID))
		}
		return req, fmt.Errorf("approval: request %q expired (time-bounded grant)", reqID)
	}
	if approver == req.Requester {
		m.audit(ctx, "approval.refused", fmt.Sprintf(`{"id":%q,"approver":%q,"reason":"self-approval"}`, req.ID, approver))
		return req, fmt.Errorf("approval: requester cannot approve own request (dual control)")
	}
	if m.cfg.Policy != nil {
		if allowed, reason := m.cfg.Policy.CanApprove(ctx, tenantID, reqID, approver); !allowed {
			m.audit(ctx, "approval.refused", fmt.Sprintf(`{"id":%q,"approver":%q,"reason":%q}`, req.ID, approver, reason))
			return req, fmt.Errorf("approval: %s not permitted to approve %q: %s", approver, reqID, reason)
		}
	}
	for _, a := range req.Approvals {
		if a.Approver == approver && a.Decision == "approve" {
			return req, nil // idempotent: already approved by this approver
		}
	}
	req.Approvals = append(req.Approvals, Approval{Approver: approver, Decision: "approve", At: now})
	m.audit(ctx, "approval.approved", fmt.Sprintf(`{"id":%q,"approver":%q,"requester":%q}`, req.ID, approver, req.Requester))

	if approveCount(req) >= req.RequiredApprovals {
		req.State = StateApproved
		credID, ierr := m.cfg.Issuer.Issue(ctx, tenantID, reqID, req.Resource)
		if ierr != nil {
			_ = m.cfg.Store.Save(ctx, req)
			return req, fmt.Errorf("approval: issue: %w", ierr)
		}
		req.State = StateIssued
		req.CredentialID = credID
		m.audit(ctx, "approval.issued", fmt.Sprintf(`{"id":%q,"credential_id":%q}`, req.ID, credID))
	}
	if err := m.cfg.Store.Save(ctx, req); err != nil {
		return Request{}, err
	}
	return req, nil
}

// Deny denies a request (a single deny is terminal).
func (m *Manager) Deny(ctx context.Context, tenantID, reqID, approver, reason string) (Request, error) {
	req, ok, err := m.cfg.Store.Get(ctx, tenantID, reqID)
	if err != nil {
		return Request{}, err
	}
	if !ok {
		return Request{}, fmt.Errorf("approval: unknown request %q", reqID)
	}
	if req.State == StateIssued {
		return req, fmt.Errorf("approval: request %q already issued", reqID)
	}
	if req.State == StateDenied {
		return req, nil
	}
	req.Approvals = append(req.Approvals, Approval{Approver: approver, Decision: "deny", At: m.cfg.Clock()})
	req.State = StateDenied
	if err := m.cfg.Store.Save(ctx, req); err != nil {
		return Request{}, err
	}
	m.audit(ctx, "approval.denied", fmt.Sprintf(`{"id":%q,"approver":%q,"reason":%q}`, req.ID, approver, reason))
	return req, nil
}

// Get returns a request.
func (m *Manager) Get(ctx context.Context, tenantID, reqID string) (Request, error) {
	req, ok, err := m.cfg.Store.Get(ctx, tenantID, reqID)
	if err != nil {
		return Request{}, err
	}
	if !ok {
		return Request{}, fmt.Errorf("approval: unknown request %q", reqID)
	}
	return req, nil
}

func approveCount(req Request) int {
	n := 0
	for _, a := range req.Approvals {
		if a.Decision == "approve" {
			n++
		}
	}
	return n
}

func (m *Manager) audit(ctx context.Context, event, data string) {
	_ = m.cfg.Audit.Audit(ctx, event, m.cfg.TenantID, []byte(data))
}

// MemoryStore is an in-memory Store for single-node deployments and tests.
type MemoryStore struct {
	mu sync.Mutex
	m  map[string]Request
}

// NewMemoryStore constructs a MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{m: map[string]Request{}} }

// Save implements Store.
func (s *MemoryStore) Save(_ context.Context, req Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[req.TenantID+"|"+req.ID] = req
	return nil
}

// Get implements Store.
func (s *MemoryStore) Get(_ context.Context, tenantID, id string) (Request, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.m[tenantID+"|"+id]
	return req, ok, nil
}
