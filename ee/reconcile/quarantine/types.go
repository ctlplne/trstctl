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
)

type State string

type EventAppender interface {
	Append(context.Context, eventspec.Event) (eventspec.Event, error)
}

type Options struct {
	Log          EventAppender
	Idempotency  idem.Idempotencer
	State        *MemoryState
	Policy       Policy
	Now          func() time.Time
	OverrideKeys map[string]crypto.PublicKey
}

type Manager struct {
	log          EventAppender
	idem         idem.Idempotencer
	state        *MemoryState
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
	return &Manager{log: opts.Log, idem: opts.Idempotency, state: st, pol: pol, now: now, overrideKeys: copyKeys(opts.OverrideKeys)}
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

func (s *MemoryState) HasOpenTenantQuarantine(tenantID string) bool {
	if s == nil {
		return false
	}
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rec := range s.records {
		if rec.TenantID == tenantID && rec.Open && rec.State == StateQuarantined {
			return true
		}
	}
	return false
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
