// Package hierarchy lets trstctl operate as its own certificate authority (F48,
// sprint S4.15), not only as a broker: it creates and manages root and
// intermediate CA hierarchies, runs m-of-n key-generation ceremonies, issues
// end-entity certificates enforcing each CA's name/path-length/EKU constraints,
// cross-signs, and rotates CA certificates.
//
// CA signing routes through the internal/crypto/ca boundary (AN-3); the CA's
// signing key is held there as the reference path and is custodied by the
// signer/HSM (AN-4) in production. CA hierarchy and ceremony state are persisted
// tenant-scoped (AN-1) and every operation emits an event on the log (AN-2).
package hierarchy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// ErrQuorumNotMet is returned when a CA-key operation is attempted before its
// key ceremony has reached the required m-of-n approvals.
var ErrQuorumNotMet = errors.New("hierarchy: key ceremony has not reached quorum")

// ErrCANotLoaded is returned when an operation references a CA whose signing key
// is not held by this manager instance (created in another process/session).
var ErrCANotLoaded = errors.New("hierarchy: CA signing key is not loaded")

const (
	rootRotateTTL = 10 * 365 * 24 * time.Hour
	caRotateTTL   = 5 * 365 * 24 * time.Hour
)

// CASpec describes a CA to create or rotate.
type CASpec struct {
	CommonName          string
	PermittedDNSDomains []string
	MaxPathLen          int
	EKUs                []string
	TTL                 time.Duration
}

// Manager orchestrates the CA hierarchy. It holds live CA signing keys in memory
// (the reference path); the signer/HSM (AN-4) custodies them in production.
type Manager struct {
	store *store.Store
	log   *events.Log

	mu  sync.Mutex
	cas map[string]*cryptoca.CA // CA id -> live CA
}

// NewManager wires a hierarchy Manager over the store and event log.
func NewManager(s *store.Store, log *events.Log) *Manager {
	return &Manager{store: s, log: log, cas: map[string]*cryptoca.CA{}}
}

// StartCeremony begins an m-of-n key ceremony requiring threshold approvals. The
// opener — the authenticated principal starting the ceremony — is bound from the
// request context's actor (events.ActorFromContext) when present, so a later
// approval can enforce opener != approver separation of duties (PKIGOV-006). When
// no actor is in context (a background/system start), the opener is left
// unattributed and no opener!=approver constraint is imposed.
//
// Note: the served REST/gRPC wiring of the key ceremony — which sets the actor
// from the resolved principal — is the EXC-WIRE-03 epic; until then the SoD model
// is enforced at this library boundary and exercised by tests. The custodian
// binding to an authorized roster is part of that same served gate.
func (m *Manager) StartCeremony(ctx context.Context, tenantID, purpose string, threshold int) (string, error) {
	if threshold < 1 {
		return "", fmt.Errorf("hierarchy: ceremony threshold must be at least 1")
	}
	opener := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		opener = a.Subject
	}
	return m.store.CreateKeyCeremony(ctx, tenantID, purpose, opener, threshold)
}

// Approve records a custodian's approval of a ceremony and returns the resulting
// approval count. The custodian is bound from the request context's actor
// (events.ActorFromContext) when present — so a served approval is attributed to
// the authenticated principal, not a caller-chosen string — falling back to the
// explicit custodian argument for the library/test path. The store enforces
// PKIGOV-006: a named (non-empty) custodian, and opener != approver. A self-
// approval by the opener is rejected with store.ErrSelfApproval.
//
// PKIGOV-010: the individual approval act is also emitted as a ca.ceremony.approved
// event on the AN-2 log (custodian, ceremony, count, time), so the four-eyes trail
// is part of the signed, hash-chained, offline-verifiable audit-evidence bundle —
// not only a row in the ca_key_ceremonies read table. The event is emitted only
// after the store records the approval; if the store rejects it (self-approval,
// anonymous custodian), no event is written. A best-effort emit failure does not
// roll back the recorded approval but is returned so the caller sees it.
func (m *Manager) Approve(ctx context.Context, tenantID, ceremonyID, custodian string) (int, error) {
	if a, ok := events.ActorFromContext(ctx); ok && a.Subject != "" {
		custodian = a.Subject
	}
	count, err := m.store.ApproveKeyCeremony(ctx, tenantID, ceremonyID, custodian)
	if err != nil {
		return count, err
	}
	if emitErr := m.emit(ctx, tenantID, "ca.ceremony.approved", map[string]any{
		"ceremony_id": ceremonyID,
		"custodian":   custodian,
		"approvals":   count,
	}); emitErr != nil {
		return count, fmt.Errorf("hierarchy: record ceremony approval event: %w", emitErr)
	}
	return count, nil
}

// CreateRoot creates a self-signed root CA, gated by ceremonyID reaching quorum.
func (m *Manager) CreateRoot(ctx context.Context, tenantID, ceremonyID string, spec CASpec) (store.CAAuthority, error) {
	if err := m.requireQuorum(ctx, tenantID, ceremonyID); err != nil {
		return store.CAAuthority{}, err
	}
	root, err := cryptoca.NewRoot(toCryptoSpec(spec))
	if err != nil {
		return store.CAAuthority{}, fmt.Errorf("hierarchy: create root: %w", err)
	}
	rec, err := m.store.InsertCAAuthority(ctx, record(tenantID, root, "root", nil, nil, spec.EKUs))
	if err != nil {
		return store.CAAuthority{}, err
	}
	m.put(rec.ID, root)
	if err := m.store.CompleteKeyCeremony(ctx, tenantID, ceremonyID); err != nil {
		return store.CAAuthority{}, err
	}
	if err := m.emit(ctx, tenantID, "ca.root.created", map[string]any{"ca_id": rec.ID, "common_name": rec.CommonName, "ceremony_id": ceremonyID}); err != nil {
		return store.CAAuthority{}, err
	}
	return rec, nil
}

// CreateIntermediate signs an intermediate under parentCAID, gated by ceremonyID
// reaching quorum. It enforces the parent's path-length constraint.
func (m *Manager) CreateIntermediate(ctx context.Context, tenantID, ceremonyID, parentCAID string, spec CASpec) (store.CAAuthority, error) {
	if err := m.requireQuorum(ctx, tenantID, ceremonyID); err != nil {
		return store.CAAuthority{}, err
	}
	parent, err := m.get(parentCAID)
	if err != nil {
		return store.CAAuthority{}, err
	}
	inter, err := parent.CreateIntermediate(toCryptoSpec(spec))
	if err != nil {
		return store.CAAuthority{}, fmt.Errorf("hierarchy: create intermediate: %w", err)
	}
	pid := parentCAID
	rec, err := m.store.InsertCAAuthority(ctx, record(tenantID, inter, "intermediate", &pid, nil, spec.EKUs))
	if err != nil {
		return store.CAAuthority{}, err
	}
	m.put(rec.ID, inter)
	if err := m.store.CompleteKeyCeremony(ctx, tenantID, ceremonyID); err != nil {
		return store.CAAuthority{}, err
	}
	if err := m.emit(ctx, tenantID, "ca.intermediate.created", map[string]any{"ca_id": rec.ID, "parent_id": parentCAID, "ceremony_id": ceremonyID}); err != nil {
		return store.CAAuthority{}, err
	}
	return rec, nil
}

// IssueEndEntity issues an end-entity certificate from caID, enforcing the CA's
// name and EKU constraints; a violating request is rejected.
func (m *Manager) IssueEndEntity(ctx context.Context, tenantID, caID string, csr []byte, ttl time.Duration) ([]byte, error) {
	ca, err := m.get(caID)
	if err != nil {
		return nil, err
	}
	issued, err := ca.IssueLeaf(csr, ttl)
	if err != nil {
		return nil, fmt.Errorf("hierarchy: issue: %w", err)
	}
	if err := m.emit(ctx, tenantID, "ca.endentity.issued", map[string]any{"ca_id": caID, "serial": issued.Serial}); err != nil {
		return nil, err
	}
	return issued.CertificatePEM, nil
}

// Rotate re-keys a CA: it mints a fresh CA certificate with the same identity and
// policy, persists it linked to its predecessor, and supersedes the old one — all
// atomically — gated by ceremonyID reaching quorum.
func (m *Manager) Rotate(ctx context.Context, tenantID, caID, ceremonyID string) (store.CAAuthority, error) {
	if err := m.requireQuorum(ctx, tenantID, ceremonyID); err != nil {
		return store.CAAuthority{}, err
	}
	old, err := m.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return store.CAAuthority{}, err
	}
	spec := CASpec{CommonName: old.CommonName, PermittedDNSDomains: old.PermittedDNSNames, MaxPathLen: old.MaxPathLen, EKUs: old.EKUs}

	var fresh *cryptoca.CA
	switch old.Kind {
	case "root":
		spec.TTL = rootRotateTTL
		fresh, err = cryptoca.NewRoot(toCryptoSpec(spec))
	case "intermediate":
		if old.ParentID == nil {
			return store.CAAuthority{}, fmt.Errorf("hierarchy: intermediate %s has no parent to re-sign under", caID)
		}
		var parent *cryptoca.CA
		if parent, err = m.get(*old.ParentID); err == nil {
			spec.TTL = caRotateTTL
			fresh, err = parent.CreateIntermediate(toCryptoSpec(spec))
		}
	default:
		return store.CAAuthority{}, fmt.Errorf("hierarchy: cannot rotate CA of kind %q", old.Kind)
	}
	if err != nil {
		return store.CAAuthority{}, fmt.Errorf("hierarchy: rotate: %w", err)
	}

	replaces := caID
	rec := record(tenantID, fresh, old.Kind, old.ParentID, &replaces, old.EKUs)
	if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		inserted, err := m.store.InsertCAAuthorityTx(ctx, tx, rec)
		if err != nil {
			return err
		}
		rec = inserted
		return m.store.SupersedeCAAuthorityTx(ctx, tx, tenantID, caID)
	}); err != nil {
		return store.CAAuthority{}, err
	}
	m.put(rec.ID, fresh)
	if err := m.store.CompleteKeyCeremony(ctx, tenantID, ceremonyID); err != nil {
		return store.CAAuthority{}, err
	}
	if err := m.emit(ctx, tenantID, "ca.rotated", map[string]any{"ca_id": rec.ID, "replaces_id": caID, "ceremony_id": ceremonyID}); err != nil {
		return store.CAAuthority{}, err
	}
	return rec, nil
}

// CrossSign issues a cross-certificate for another CA's certificate (DER), signed
// by caID. Cross-signing extends trust — it mints a CA certificate under your
// signing CA — so it is gated by an m-of-n key ceremony exactly like CreateRoot /
// CreateIntermediate / Rotate (PKIGOV-003): it is refused with ErrQuorumNotMet
// until ceremonyID reaches its threshold, then the ceremony is marked complete and
// an approver-attributed ca.cross_signed event records the ceremony id. This stops
// a single operator (or a compromised in-process caller) from unilaterally
// extending trust where a CA auditor expects custodian quorum.
func (m *Manager) CrossSign(ctx context.Context, tenantID, ceremonyID, caID string, otherCertDER []byte) ([]byte, error) {
	if err := m.requireQuorum(ctx, tenantID, ceremonyID); err != nil {
		return nil, err
	}
	ca, err := m.get(caID)
	if err != nil {
		return nil, err
	}
	cross, err := ca.CrossSign(otherCertDER)
	if err != nil {
		return nil, fmt.Errorf("hierarchy: cross-sign: %w", err)
	}
	if err := m.store.CompleteKeyCeremony(ctx, tenantID, ceremonyID); err != nil {
		return nil, err
	}
	if err := m.emit(ctx, tenantID, "ca.cross_signed", map[string]any{"ca_id": caID, "ceremony_id": ceremonyID}); err != nil {
		return nil, err
	}
	return cross, nil
}

func (m *Manager) requireQuorum(ctx context.Context, tenantID, ceremonyID string) error {
	c, err := m.store.GetKeyCeremony(ctx, tenantID, ceremonyID)
	if err != nil {
		return err
	}
	if c.Approvals < c.Threshold {
		return fmt.Errorf("%w (%d of %d approvals)", ErrQuorumNotMet, c.Approvals, c.Threshold)
	}
	return nil
}

func (m *Manager) put(id string, ca *cryptoca.CA) {
	m.mu.Lock()
	m.cas[id] = ca
	m.mu.Unlock()
}

func (m *Manager) get(id string) (*cryptoca.CA, error) {
	m.mu.Lock()
	ca, ok := m.cas[id]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrCANotLoaded, id)
	}
	return ca, nil
}

func (m *Manager) emit(ctx context.Context, tenantID, eventType string, data map[string]any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = m.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
	return err
}

func toCryptoSpec(s CASpec) cryptoca.CASpec {
	return cryptoca.CASpec{
		CommonName: s.CommonName, PermittedDNSDomains: s.PermittedDNSDomains,
		MaxPathLen: s.MaxPathLen, EKUs: s.EKUs, TTL: s.TTL,
	}
}

// record builds the store row for a created/rotated CA from its boundary handle.
func record(tenantID string, c *cryptoca.CA, kind string, parentID, replacesID *string, ekus []string) store.CAAuthority {
	na := c.NotAfter()
	return store.CAAuthority{
		TenantID: tenantID, ParentID: parentID, CommonName: c.CommonName(), Kind: kind, Status: "active",
		CertificatePEM: string(c.ChainPEM()), Serial: c.Serial(), NotAfter: &na,
		MaxPathLen: c.MaxPathLen(), PermittedDNSNames: c.PermittedDNSDomains(), EKUs: ekus,
		ReplacesID: replacesID,
	}
}
