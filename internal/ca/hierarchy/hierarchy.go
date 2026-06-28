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
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
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

func PurposeRoot(spec CASpec) string {
	return "root:" + purposeSpecDigest(spec)
}

func PurposeIntermediate(parentCAID string, spec CASpec) string {
	return "intermediate:" + parentCAID + ":" + purposeSpecDigest(spec)
}

func PurposeRotate(caID string) string { return "rotation:" + caID }
func PurposeCrossSign(caID string, otherCertDER []byte) string {
	return "cross-sign:" + caID + ":" + boundarycrypto.SHA256Hex(otherCertDER)
}

func purposeSpecDigest(spec CASpec) string {
	permittedDNSDomains := append([]string(nil), spec.PermittedDNSDomains...)
	sort.Strings(permittedDNSDomains)
	ekus := append([]string(nil), spec.EKUs...)
	sort.Strings(ekus)
	payload, err := json.Marshal(struct {
		CommonName          string        `json:"common_name"`
		PermittedDNSDomains []string      `json:"permitted_dns_domains"`
		MaxPathLen          int           `json:"max_path_len"`
		EKUs                []string      `json:"ekus"`
		TTL                 time.Duration `json:"ttl"`
	}{
		CommonName:          spec.CommonName,
		PermittedDNSDomains: permittedDNSDomains,
		MaxPathLen:          spec.MaxPathLen,
		EKUs:                ekus,
		TTL:                 spec.TTL,
	})
	if err != nil {
		panic(fmt.Sprintf("hierarchy: canonical CA ceremony purpose: %v", err))
	}
	return boundarycrypto.SHA256Hex(payload)
}

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
	caOps caOperations

	mu  sync.Mutex
	cas map[string]*cryptoca.CA // CA id -> live CA
}

type caOperations struct {
	newRoot            func(cryptoca.CASpec) (*cryptoca.CA, error)
	createIntermediate func(*cryptoca.CA, cryptoca.CASpec) (*cryptoca.CA, error)
	crossSign          func(*cryptoca.CA, []byte) ([]byte, error)
}

func defaultCAOperations() caOperations {
	return caOperations{
		newRoot: cryptoca.NewRoot,
		createIntermediate: func(parent *cryptoca.CA, spec cryptoca.CASpec) (*cryptoca.CA, error) {
			return parent.CreateIntermediate(spec)
		},
		crossSign: func(ca *cryptoca.CA, certDER []byte) ([]byte, error) { return ca.CrossSign(certDER) },
	}
}

// NewManager wires a hierarchy Manager over the store and event log.
func NewManager(s *store.Store, log *events.Log) *Manager {
	return &Manager{store: s, log: log, caOps: defaultCAOperations(), cas: map[string]*cryptoca.CA{}}
}

// StartCeremony begins an m-of-n key ceremony requiring threshold approvals. The
// opener — the authenticated principal starting the ceremony — is bound from the
// request context's actor (events.ActorFromContext) when present, so a later
// approval can enforce opener != approver separation of duties (PKIGOV-006). When
// no actor is in context (a background/system start), the opener is left
// unattributed and no opener!=approver constraint is imposed.
//
// The ceremony row is projected from ca.ceremony.started after the event append
// succeeds, so replay can rebuild the same governance gate from the log.
func (m *Manager) StartCeremony(ctx context.Context, tenantID, purpose string, threshold int) (string, error) {
	if threshold < 1 {
		return "", fmt.Errorf("hierarchy: ceremony threshold must be at least 1")
	}
	opener := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		opener = a.Subject
	}
	id := uuid.NewString()
	ev, err := m.appendEvent(ctx, tenantID, projections.EventCACeremonyStarted, projections.CACeremonyStarted{
		CeremonyID: id,
		Purpose:    purpose,
		Threshold:  threshold,
		Opener:     opener,
	})
	if err != nil {
		return "", err
	}
	if err := projections.New(m.store).Apply(ctx, ev); err != nil {
		return "", err
	}
	return id, nil
}

// Approve records a custodian's approval of a ceremony and returns the resulting
// approval count. The custodian is bound from the request context's actor
// (events.ActorFromContext) when present — so a served approval is attributed to
// the authenticated principal, not a caller-chosen string — falling back to the
// explicit custodian argument for the library/test path. The store enforces
// PKIGOV-006: a named (non-empty) custodian, and opener != approver. A self-
// approval by the opener is rejected with store.ErrSelfApproval.
//
// PKIGOV-010 / PKIGOV-003: the individual approval act is emitted as a
// ca.ceremony.approved event on the AN-2 log (custodian, ceremony, count, time), so
// the four-eyes trail is part of the signed, hash-chained, offline-verifiable
// audit-evidence bundle — not only a row in the ca_key_ceremonies read table. The
// approval row is projected only after the event append succeeds, binding the
// row to the event id/sequence as quorum evidence. A repeated custodian approval
// returns the existing evidence-backed count instead of appending a new event.
func (m *Manager) Approve(ctx context.Context, tenantID, ceremonyID, custodian string) (int, error) {
	if a, ok := events.ActorFromContext(ctx); ok && a.Subject != "" {
		custodian = a.Subject
	}
	if custodian == "" {
		return 0, store.ErrAnonymousApproval
	}
	current, err := m.store.GetKeyCeremony(ctx, tenantID, ceremonyID)
	if err != nil {
		return 0, err
	}
	if current.Status != "pending" {
		return current.Approvals, store.ErrKeyCeremonyNotPending
	}
	if current.Opener != "" && current.Opener == custodian {
		return current.Approvals, store.ErrSelfApproval
	}
	evidenced, err := m.store.KeyCeremonyApprovalEvidenced(ctx, tenantID, ceremonyID, custodian)
	if err != nil {
		return current.Approvals, err
	}
	if evidenced {
		return current.Approvals, nil
	}
	ev, emitErr := m.appendEvent(ctx, tenantID, projections.EventCACeremonyApproved, projections.CACeremonyApproved{
		CeremonyID: ceremonyID,
		Custodian:  custodian,
		Approvals:  current.Approvals + 1,
	})
	if emitErr != nil {
		return current.Approvals, fmt.Errorf("hierarchy: record ceremony approval event: %w", emitErr)
	}
	if err := projections.New(m.store).Apply(ctx, ev); err != nil {
		return current.Approvals, fmt.Errorf("hierarchy: project ceremony approval event: %w", err)
	}
	updated, err := m.store.GetKeyCeremony(ctx, tenantID, ceremonyID)
	if err != nil {
		return current.Approvals, err
	}
	return updated.Approvals, nil
}

// CreateRoot creates a self-signed root CA, gated by ceremonyID reaching quorum.
func (m *Manager) CreateRoot(ctx context.Context, tenantID, ceremonyID string, spec CASpec) (store.CAAuthority, error) {
	var root *cryptoca.CA
	var rec store.CAAuthority
	if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := m.consumeCeremonyTx(ctx, tx, tenantID, ceremonyID, PurposeRoot(spec)); err != nil {
			return err
		}
		var err error
		root, err = m.caOps.newRoot(toCryptoSpec(spec))
		if err != nil {
			return fmt.Errorf("hierarchy: create root: %w", err)
		}
		inserted, err := m.store.InsertCAAuthorityTx(ctx, tx, record(tenantID, root, "root", nil, nil, spec.EKUs))
		if err != nil {
			return err
		}
		rec = inserted
		return nil
	}); err != nil {
		if root != nil {
			root.Destroy()
		}
		return store.CAAuthority{}, err
	}
	m.put(rec.ID, root)
	if err := m.emit(ctx, tenantID, "ca.root.created", map[string]any{"ca_id": rec.ID, "common_name": rec.CommonName, "ceremony_id": ceremonyID}); err != nil {
		return store.CAAuthority{}, err
	}
	return rec, nil
}

// CreateIntermediate signs an intermediate under parentCAID, gated by ceremonyID
// reaching quorum. It enforces the parent's path-length constraint.
func (m *Manager) CreateIntermediate(ctx context.Context, tenantID, ceremonyID, parentCAID string, spec CASpec) (store.CAAuthority, error) {
	parent, err := m.get(parentCAID)
	if err != nil {
		return store.CAAuthority{}, err
	}
	var inter *cryptoca.CA
	pid := parentCAID
	var rec store.CAAuthority
	if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := m.consumeCeremonyTx(ctx, tx, tenantID, ceremonyID, PurposeIntermediate(parentCAID, spec)); err != nil {
			return err
		}
		var err error
		inter, err = m.caOps.createIntermediate(parent, toCryptoSpec(spec))
		if err != nil {
			return fmt.Errorf("hierarchy: create intermediate: %w", err)
		}
		inserted, err := m.store.InsertCAAuthorityTx(ctx, tx, record(tenantID, inter, "intermediate", &pid, nil, spec.EKUs))
		if err != nil {
			return err
		}
		rec = inserted
		return nil
	}); err != nil {
		if inter != nil {
			inter.Destroy()
		}
		return store.CAAuthority{}, err
	}
	m.put(rec.ID, inter)
	if err := m.emit(ctx, tenantID, "ca.intermediate.created", map[string]any{"ca_id": rec.ID, "parent_id": parentCAID, "ceremony_id": ceremonyID}); err != nil {
		return store.CAAuthority{}, err
	}
	return rec, nil
}

// IssueEndEntity issues an end-entity certificate from caID under the served
// certificate-profile shape, enforcing the CA's name and EKU constraints; a
// violating request is rejected. The required prof carries the RFC 5280 /
// CA-Browser-Forum fields the served issuance applies — CRL distribution points,
// AIA (OCSP + CA issuers), certificatePolicies, the validity ceiling, the EKU
// allow-list, and DNS name constraints — so a hierarchy-issued leaf is the SAME
// shape as a broker-issued one (PKIGOV-002): it carries revocation pointers, AIA,
// policies, SKI, AKI, and a bounded validity rather than the bare legacy leaf. The
// signing routes through the crypto boundary's single leaf signer (AN-3); the CA's
// own lane is additionally folded in so the leaf can never exceed the CA's
// constraints. The zero profile is accepted (the in-process reference shape) for
// callers with no served revocation infrastructure.
func (m *Manager) IssueEndEntity(ctx context.Context, tenantID, caID string, csr []byte, ttl time.Duration, prof boundarycrypto.LeafProfile) ([]byte, error) {
	ca, err := m.get(caID)
	if err != nil {
		return nil, err
	}
	issued, err := ca.IssueLeafWithProfile(csr, ttl, prof)
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
	old, err := m.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return store.CAAuthority{}, err
	}
	spec := CASpec{CommonName: old.CommonName, PermittedDNSDomains: old.PermittedDNSNames, MaxPathLen: old.MaxPathLen, EKUs: old.EKUs}

	var fresh *cryptoca.CA
	if old.Kind != "root" && old.Kind != "intermediate" {
		return store.CAAuthority{}, fmt.Errorf("hierarchy: cannot rotate CA of kind %q", old.Kind)
	}

	replaces := caID
	var rec store.CAAuthority
	if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := m.consumeCeremonyTx(ctx, tx, tenantID, ceremonyID, PurposeRotate(caID)); err != nil {
			return err
		}
		switch old.Kind {
		case "root":
			spec.TTL = rootRotateTTL
			fresh, err = m.caOps.newRoot(toCryptoSpec(spec))
		case "intermediate":
			if old.ParentID == nil {
				return fmt.Errorf("hierarchy: intermediate %s has no parent to re-sign under", caID)
			}
			var parent *cryptoca.CA
			if parent, err = m.get(*old.ParentID); err == nil {
				spec.TTL = caRotateTTL
				fresh, err = m.caOps.createIntermediate(parent, toCryptoSpec(spec))
			}
		}
		if err != nil {
			return fmt.Errorf("hierarchy: rotate: %w", err)
		}
		rec = record(tenantID, fresh, old.Kind, old.ParentID, &replaces, old.EKUs)
		inserted, err := m.store.InsertCAAuthorityTx(ctx, tx, rec)
		if err != nil {
			return err
		}
		rec = inserted
		return m.store.SupersedeCAAuthorityTx(ctx, tx, tenantID, caID)
	}); err != nil {
		if fresh != nil {
			fresh.Destroy()
		}
		return store.CAAuthority{}, err
	}
	m.put(rec.ID, fresh)
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
	ca, err := m.get(caID)
	if err != nil {
		return nil, err
	}
	var cross []byte
	if err := m.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := m.consumeCeremonyTx(ctx, tx, tenantID, ceremonyID, PurposeCrossSign(caID, otherCertDER)); err != nil {
			return err
		}
		var err error
		cross, err = m.caOps.crossSign(ca, otherCertDER)
		if err != nil {
			return fmt.Errorf("hierarchy: cross-sign: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := m.emit(ctx, tenantID, "ca.cross_signed", map[string]any{"ca_id": caID, "ceremony_id": ceremonyID}); err != nil {
		return nil, err
	}
	return cross, nil
}

func (m *Manager) consumeCeremonyTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID, expectedPurpose string) error {
	c, err := m.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, ceremonyID, expectedPurpose)
	if errors.Is(err, store.ErrKeyCeremonyQuorumNotMet) {
		return fmt.Errorf("%w (%d of %d approvals)", ErrQuorumNotMet, c.Approvals, c.Threshold)
	}
	return err
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
	_, err := m.appendEvent(ctx, tenantID, eventType, data)
	return err
}

func (m *Manager) appendEvent(ctx context.Context, tenantID, eventType string, data any) (events.Event, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return events.Event{}, err
	}
	return m.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
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
