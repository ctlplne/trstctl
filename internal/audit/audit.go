// Package audit exposes query, search, filter, and signed-export surfaces over
// the event-sourced audit log (F9). The AN-2 event log remains the source of
// truth: this package reads it via Replay and derives views; it never writes a
// separate audit store. Every query is tenant-scoped (AN-1). Evidence bundles are
// signed through the crypto boundary (internal/crypto/jose) so an auditor can
// verify their integrity offline.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
)

// Record is one audit entry: a projection of an event for an auditor. Actor is
// the authenticated caller who performed the mutation (the "who"/"under what
// authorization"); Hash is the record's position in the tamper-evident chain
// (R2.1), each linked to its predecessor so any alteration is detectable.
type Record struct {
	Sequence uint64          `json:"sequence"`
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	TenantID string          `json:"tenant_id"`
	Time     time.Time       `json:"time"`
	Actor    *events.Actor   `json:"actor,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	Hash     string          `json:"hash,omitempty"`
}

// ErrMissingTenant is returned by Search/Export/VerifyChain when the query has an
// empty TenantID (TENANT-003). The audit log spans every tenant, and the
// tenant-scoping filter only applies when TenantID is set — so an empty TenantID
// would return the full cross-tenant log. We reject it instead, failing closed,
// to match the storage layer's fail-closed RLS norm: a missing tenant scope is an
// error, never "show everything".
var ErrMissingTenant = errors.New("audit: query requires a tenant id (AN-1)")

// Query selects a slice of the audit log. TenantID is required for tenant
// isolation; the zero value of the other fields means "unbounded".
type Query struct {
	TenantID     string    `json:"tenant_id"`
	Types        []string  `json:"types,omitempty"`          // exact event-type filter
	Since        time.Time `json:"since,omitempty"`          // inclusive lower time bound
	Until        time.Time `json:"until,omitempty"`          // inclusive upper time bound
	AsOfSequence uint64    `json:"as_of_sequence,omitempty"` // point-in-time: only events with Sequence <= this
	Contains     string    `json:"contains,omitempty"`       // substring match on type or data
	Limit        int       `json:"limit,omitempty"`          // cap on records returned (0 = all)
}

// Checkpoint is a sealed retention boundary (R4.4): every audit record up to
// BoundarySeq has been archived to cold storage as a signed, offline-verifiable
// bundle and pruned from the hot event log. BoundaryHash is the audit chain head
// at the boundary — the seed that lets the surviving suffix verify across the
// prune without re-deriving from genesis.
type Checkpoint struct {
	TenantID     string
	BoundarySeq  uint64
	BoundaryHash string
	RecordCount  int
	ArchiveURI   string
}

// CheckpointSource yields a tenant's latest sealed retention boundary, or ok=false
// if none has been sealed. Search and Export anchor the live chain on it.
type CheckpointSource interface {
	LatestAuditCheckpoint(ctx context.Context, tenantID string) (Checkpoint, bool, error)
}

// CheckpointSink persists a sealed retention boundary. The retention worker writes
// one after it has archived and verified a segment, before pruning.
type CheckpointSink interface {
	SaveAuditCheckpoint(ctx context.Context, cp Checkpoint) error
}

// Service answers audit queries and exports signed evidence bundles over the
// event log.
type Service struct {
	log         *events.Log
	signer      *jose.SigningKey
	checkpoints CheckpointSource // optional; when set, queries anchor on the latest sealed boundary (R4.4)
	now         func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithCheckpoints wires the retention checkpoint source so a tenant's queries
// replay from (and seal onto) its latest sealed boundary instead of genesis —
// keeping the chain verifiable after archived records are pruned (R4.4).
func WithCheckpoints(src CheckpointSource) Option {
	return func(s *Service) { s.checkpoints = src }
}

// NewService returns an audit service over the event log, signing evidence
// bundles with signer.
func NewService(log *events.Log, signer *jose.SigningKey, opts ...Option) *Service {
	s := &Service{log: log, signer: signer, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// searchSeed returns the replay floor and chain seed for a tenant: a sealed
// retention boundary anchors the live chain just past the archived prefix. With no
// checkpoint source, no tenant, or no sealed boundary it is (0, "") — i.e. genesis.
func (s *Service) searchSeed(ctx context.Context, tenantID string) (from uint64, seed string, err error) {
	if s.checkpoints == nil || tenantID == "" {
		return 0, "", nil
	}
	cp, ok, err := s.checkpoints.LatestAuditCheckpoint(ctx, tenantID)
	if err != nil {
		return 0, "", err
	}
	if !ok {
		return 0, "", nil
	}
	return cp.BoundarySeq + 1, cp.BoundaryHash, nil
}

// Search returns the records matching q, in append order. It replays the log and
// applies the filters; the event log stays the source of truth. When a tenant has
// a sealed retention boundary (R4.4), the replay starts just past the archived
// prefix and the chain is seeded from the boundary hash, so the surviving records
// keep the exact hashes they had in the full chain.
func (s *Service) Search(ctx context.Context, q Query) ([]Record, error) {
	// Fail closed on a missing tenant scope (TENANT-003): the audit log is
	// cross-tenant, and matches() only filters when TenantID is set, so an empty
	// TenantID would leak every tenant's records. Reject it — a missing scope is an
	// error, not "all tenants". Export and VerifyChain route through here, so all
	// three query surfaces are covered by this one check.
	if q.TenantID == "" {
		return nil, ErrMissingTenant
	}
	from, seed, err := s.searchSeed(ctx, q.TenantID)
	if err != nil {
		return nil, err
	}
	out := []Record{}
	err = s.log.Replay(ctx, from, func(e events.Event) error {
		if !q.matches(e) {
			return nil
		}
		out = append(out, Record{
			Sequence: e.Sequence, ID: e.ID, Type: e.Type,
			TenantID: e.TenantID, Time: e.Time, Actor: e.Actor, Data: json.RawMessage(e.Data),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	// Hash-link the returned records (R2.1), seeded from the sealed boundary so the
	// chain attests to exactly this slice as a continuation of the archived prefix;
	// a later tampering of any record is detectable by VerifyChain.
	SealFrom(seed, out)
	return out, nil
}

func (q Query) matches(e events.Event) bool {
	if q.TenantID != "" && e.TenantID != q.TenantID { // AN-1
		return false
	}
	if q.AsOfSequence != 0 && e.Sequence > q.AsOfSequence {
		return false
	}
	if !q.Since.IsZero() && e.Time.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && e.Time.After(q.Until) {
		return false
	}
	if len(q.Types) > 0 && !contains(q.Types, e.Type) {
		return false
	}
	if q.Contains != "" && !strings.Contains(e.Type, q.Contains) && !strings.Contains(string(e.Data), q.Contains) {
		return false
	}
	return true
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// Bundle is a self-contained, signable export of audit records. ChainHead is the
// head of the tamper-evident hash chain over Records: signed with the bundle, it
// anchors the records at export time so any later alteration of the underlying
// log is detectable by recomputing the chain (R2.1).
type Bundle struct {
	TenantID    string    `json:"tenant_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Query       Query     `json:"query"`
	Records     []Record  `json:"records"`
	Count       int       `json:"count"`
	// PrevHash is the chain head this bundle continues from — "" (genesis) for a
	// from-the-start export, or the previous archived segment's head for a
	// retention segment (R4.4). It seeds verification so contiguous segments chain.
	PrevHash  string `json:"prev_hash,omitempty"`
	ChainHead string `json:"chain_head"`
}

// Export runs the query and returns the matching records as a signed evidence
// bundle (a compact JWS whose payload is the Bundle). An auditor verifies it with
// VerifyBundle and the service's verification keys.
func (s *Service) Export(ctx context.Context, q Query) (string, error) {
	recs, err := s.Search(ctx, q)
	if err != nil {
		return "", err
	}
	_, seed, err := s.searchSeed(ctx, q.TenantID)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(Bundle{
		TenantID: q.TenantID, GeneratedAt: s.now().UTC(), Query: q,
		Records: recs, Count: len(recs), PrevHash: seed, ChainHead: chainHead(recs),
	})
	if err != nil {
		return "", err
	}
	return s.signer.Sign(payload)
}

// VerifyChain reports the head of the hash chain over records and an error if any
// record's stored hash does not match its recomputed link — i.e. a stored event
// was altered, dropped, inserted, or reordered (R2.1 tamper detection).
func (s *Service) VerifyChain(ctx context.Context, tenantID string) (string, error) {
	recs, err := s.Search(ctx, Query{TenantID: tenantID})
	if err != nil {
		return "", err
	}
	// Verify from the same sealed boundary Search hashed the survivors onto (R4.4),
	// so a pruned tenant's chain checks out as a continuation rather than reporting
	// a false tamper at the first surviving record.
	_, seed, err := s.searchSeed(ctx, tenantID)
	if err != nil {
		return "", err
	}
	return VerifyChainFrom(seed, recs)
}

// VerificationKeys returns the public key set that verifies bundles exported by
// this service.
func (s *Service) VerificationKeys() *jose.JWKSet { return s.signer.JWKS() }

// VerifyBundle verifies a signed evidence bundle against keys and returns it. A
// bad signature is an error; so is an internally inconsistent chain (the records
// do not reproduce the signed ChainHead), which catches tampering with the
// bundle's records that somehow passed the signature check.
func VerifyBundle(signed string, keys *jose.JWKSet) (Bundle, error) {
	payload, err := keys.Verify(signed)
	if err != nil {
		return Bundle{}, err
	}
	var b Bundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return Bundle{}, err
	}
	head, err := VerifyChainFrom(b.PrevHash, b.Records)
	if err != nil {
		return Bundle{}, err
	}
	if head != b.ChainHead {
		return Bundle{}, errors.New("audit: bundle chain head does not match its records")
	}
	return b, nil
}
