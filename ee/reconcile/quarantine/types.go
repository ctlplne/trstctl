// SPDX-License-Identifier: LicenseRef-trstctl-EE

package quarantine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/idem"
)

const (
	EventTypeEntered   = "xrec.quarantine.entered"
	EventTypeRefused   = "xrec.quarantine.refused"
	EventTypeCompleted = "xrec.reconciliation.completed"
	EventTypeReleased  = "xrec.quarantine.released"

	StateConsistent  State = "consistent"
	StateDiverged    State = "diverged"
	StateQuarantined State = "quarantined"
)

var (
	ErrInvalidQuarantine = errors.New("quarantine: invalid request")
	ErrInvalidCompletion = errors.New("quarantine: invalid completion")
	ErrInvalidOverride   = errors.New("quarantine: invalid operator override")
	// ErrStateUnavailable is returned by a containment state that cannot answer.
	// Quarantine is a containment control, so "cannot answer" must REFUSE, never
	// fall through to AllowAdmission().
	ErrStateUnavailable = errors.New("quarantine: containment state unavailable")
)

type State string

type EventAppender interface {
	Append(context.Context, eventspec.Event) (eventspec.Event, error)
}

type Options struct {
	Log         EventAppender
	Idempotency idem.Idempotencer
	State       *MemoryState
	// Admission is the containment read seam Manager.Admit consults. It defaults
	// to State so existing callers are unchanged, and exists so a durable
	// containment state can be wired without the admission decision depending on
	// the process-local fold. EVERY read the admission decision makes goes through
	// this one seam -- the tenant gate AND the per-authority lookup -- so a durable
	// state can never diverge from the record lookup and re-open the fail-open hole
	// this seam was introduced to close.
	Admission    AdmissionState
	Policy       Policy
	Now          func() time.Time
	OverrideKeys map[string]crypto.PublicKey
}

type Manager struct {
	log          EventAppender
	idem         idem.Idempotencer
	state        *MemoryState
	admission    AdmissionState
	pol          Policy
	now          func() time.Time
	overrideKeys map[string]crypto.PublicKey
}

type Record struct {
	TenantID    string `json:"tenant_id"`
	AuthorityID string `json:"authority_id"`
	WitnessID   string `json:"witness_id"`
	Reason      string `json:"reason,omitempty"`
	State       State  `json:"state"`
	Open        bool   `json:"open"`
	EnteredAt   int64  `json:"entered_at"`
}

type Decision struct {
	Entered     bool
	TenantID    string
	AuthorityID string
	WitnessID   string
	Reason      string
	State       State
	Event       eventspec.Event
}

type Entered struct {
	TenantID     string `json:"tenant_id"`
	AuthorityID  string `json:"authority_id"`
	WitnessID    string `json:"witness_id"`
	Reason       string `json:"reason"`
	FromState    State  `json:"from_state"`
	ThroughState State  `json:"through_state"`
	ToState      State  `json:"to_state"`
	EnteredAt    int64  `json:"entered_at"`
}

type Refused struct {
	RefusalID      string `json:"refusal_id"`
	TenantID       string `json:"tenant_id"`
	AuthorityID    string `json:"authority_id"`
	WitnessID      string `json:"witness_id,omitempty"`
	Operation      string `json:"operation"`
	IdentityID     string `json:"identity_id,omitempty"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	RefusedAt      int64  `json:"refused_at"`
}

func NewManager(opts Options) *Manager {
	st := opts.State
	if st == nil {
		st = NewMemoryState()
	}
	pol := opts.Policy
	if pol.empty() {
		pol = ReferencePolicy()
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	adm := opts.Admission
	if adm == nil {
		adm = st
	}
	return &Manager{log: opts.Log, idem: opts.Idempotency, state: st, admission: adm, pol: pol, now: now, overrideKeys: copyKeys(opts.OverrideKeys)}
}

func (m *Manager) State() *MemoryState {
	if m == nil || m.state == nil {
		return NewMemoryState()
	}
	return m.state
}

type MemoryState struct {
	mu      sync.RWMutex
	records map[string]Record
}

func NewMemoryState() *MemoryState {
	return &MemoryState{records: map[string]Record{}}
}

func (s *MemoryState) Lookup(tenantID, authorityID string) (Record, bool) {
	if s == nil {
		return Record{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[stateKey(tenantID, authorityID)]
	return rec, ok
}

// AdmissionState is the containment read seam Manager.Admit consults. It carries
// BOTH reads the admission decision makes so they cannot be answered by two
// different substrates: HasOpenTenantQuarantine gates the decision and
// LookupOpenQuarantine resolves which observed authority is contained. Splitting
// them across a durable state and a process-local map is exactly how a
// containment control silently fails open (a state reporting OPEN plus an empty
// local map found no authority and therefore allowed), so they are one interface.
//
// Both methods report an error rather than a bare bool so a substrate that CANNOT
// ANSWER refuses admission (fail closed) instead of silently reporting "no open
// quarantine" (fail open).
type AdmissionState interface {
	HasOpenTenantQuarantine(ctx context.Context, tenantID string) (bool, error)
	LookupOpenQuarantine(ctx context.Context, tenantID, authorityID string) (Record, bool, error)
}

var _ AdmissionState = (*MemoryState)(nil)

// HasOpenTenantQuarantine reports whether the tenant has any open quarantine.
//
// The records it reads are the fold of that tenant's own xrec.quarantine.entered
// and xrec.quarantine.released events (AN-2: the state change IS the event and
// this is a projection of the log, never a directly written state table).
// StateProjection rebuilds the fold from sequence 0 on every boot, so the answer
// survives a process restart. A nil state cannot answer and therefore refuses.
func (s *MemoryState) HasOpenTenantQuarantine(_ context.Context, tenantID string) (bool, error) {
	if s == nil {
		return false, ErrStateUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rec := range s.records {
		if rec.TenantID == tenantID && rec.Open && rec.State == StateQuarantined {
			return true, nil
		}
	}
	return false, nil
}

// LookupOpenQuarantine returns the OPEN quarantine record for one tenant and
// authority, if any. It is the second half of the admission decision and is
// deliberately on the same interface as the tenant gate: a durable containment
// state must answer both, or the two answers can disagree and the disagreement
// resolves to "allow".
func (s *MemoryState) LookupOpenQuarantine(_ context.Context, tenantID, authorityID string) (Record, bool, error) {
	if s == nil {
		return Record{}, false, ErrStateUnavailable
	}
	rec, ok := s.Lookup(tenantID, authorityID)
	if !ok || !rec.Open || rec.State != StateQuarantined {
		return Record{}, false, nil
	}
	return rec, true, nil
}

// reset drops every folded quarantine record. Only StateProjection.Reset calls
// it, immediately before the projector replays the event log from sequence 0.
func (s *MemoryState) reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = map[string]Record{}
}

func (s *MemoryState) enter(tenantID, authorityID, witnessID, reason string, at int64) (Record, State, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := stateKey(tenantID, authorityID)
	prev, ok := s.records[key]
	from := StateConsistent
	if ok {
		from = prev.State
	}
	if ok && prev.Open && prev.State == StateQuarantined && prev.WitnessID == witnessID {
		return prev, from, false
	}
	rec := Record{
		TenantID:    tenantID,
		AuthorityID: authorityID,
		WitnessID:   witnessID,
		Reason:      reason,
		State:       StateQuarantined,
		Open:        true,
		EnteredAt:   at,
	}
	s.records[key] = rec
	return rec, from, true
}

func (s *MemoryState) openByWitness(tenantID, witnessID string) []Record {
	if s == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	witnessID = strings.TrimSpace(witnessID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Record{}
	for _, rec := range s.records {
		if rec.TenantID == tenantID && rec.WitnessID == witnessID && rec.Open && rec.State == StateQuarantined {
			out = append(out, rec)
		}
	}
	return out
}

func (s *MemoryState) release(tenantID, authorityID, witnessID string) (Record, bool) {
	if s == nil {
		return Record{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := stateKey(tenantID, authorityID)
	rec, ok := s.records[key]
	if !ok || rec.WitnessID != strings.TrimSpace(witnessID) || !rec.Open || rec.State != StateQuarantined {
		return Record{}, false
	}
	rec.State = StateConsistent
	rec.Open = false
	s.records[key] = rec
	return rec, true
}

func stateKey(tenantID, authorityID string) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(authorityID)
}

func copyKeys(in map[string]crypto.PublicKey) map[string]crypto.PublicKey {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]crypto.PublicKey, len(in))
	for k, v := range in {
		out[k] = crypto.PublicKey{Algorithm: v.Algorithm, DER: append([]byte(nil), v.DER...)}
	}
	return out
}
