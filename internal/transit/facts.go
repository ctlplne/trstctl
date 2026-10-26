// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// Lifecycle facts (A126). A key's creation and each rotation is a fact in the
// event log: which key, of which kind, at which version. The key bytes are not
// in the log; they stay sealed in the keyring. Each version carries a random
// fact ID, stored with its material in the sealed keyring and used as the
// event's ID, so a fact keeps one identity on every replica and across
// retries, and a subject erasure that rewrites the key name in history still
// leaves the fact linked to its version. A fact is appended only after its
// version's material is saved, so the log never records a key that does not
// exist; one whose append fails is appended by the next reconcile.

const (
	EventKeyCreated = "transit.key.created"
	EventKeyRotated = "transit.key.rotated"
	// FactSchemaVersion is the lifecycle-fact payload: key, kind and version.
	// Schema 1 was an audit record naming only the key.
	FactSchemaVersion = 2
	factIDPrefix      = "tf-"
)

// Fact is one key version's lifecycle fact. It never contains key bytes.
type Fact struct {
	ID      string
	Key     string
	Kind    Kind
	Version int
}

// EventType is the fact's event: the first version is a creation, every later
// one a rotation.
func (f Fact) EventType() string {
	if f.Version == 1 {
		return EventKeyCreated
	}
	return EventKeyRotated
}

// FactRecorder keeps transit lifecycle facts in the event log.
type FactRecorder interface {
	// Recorded returns, by fact ID, when the event log recorded each of
	// factIDs it holds; an ID it does not hold is absent.
	Recorded(ctx context.Context, tenantID string, factIDs []string) (map[string]time.Time, error)
	// Record appends one fact. Recording a fact the log already holds changes
	// nothing.
	Record(ctx context.Context, tenantID string, fact Fact) error
}

// SetFactRecorder makes create and rotate record their facts in the event log
// and lets the versions listing say which facts are recorded.
func (s *Service) SetFactRecorder(r FactRecorder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.facts = r
}

func (s *Service) factRecorder() FactRecorder {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.facts
}

// ValidFactID reports whether id has the shape newFactID produces.
func ValidFactID(id string) bool {
	if len(id) != len(factIDPrefix)+32 || id[:len(factIDPrefix)] != factIDPrefix {
		return false
	}
	_, err := hex.DecodeString(id[len(factIDPrefix):])
	return err == nil
}

func newFactID() (string, error) {
	raw, err := crypto.RandomBytes(16)
	if err != nil {
		return "", fmt.Errorf("transit: generate a fact ID: %w", err)
	}
	return factIDPrefix + hex.EncodeToString(raw), nil
}

// afterSave records the facts of the named key once a create or rotate is
// saved. A failed append leaves the mutation done (its material is saved) and
// the fact for the next reconcile. Without a recorder the service keeps the
// earlier audit record, now emitted only after the save.
func (s *Service) afterSave(ctx context.Context, tenantID string, k *Keyring, name, eventType string) {
	rec := s.factRecorder()
	if rec == nil {
		k.event(ctx, eventType, name)
		return
	}
	_ = s.recordFacts(ctx, rec, tenantID, k.keyFacts(name))
}

// recordFacts appends, oldest first, each of facts the event log does not
// hold yet.
func (s *Service) recordFacts(ctx context.Context, rec FactRecorder, tenantID string, facts []Fact) error {
	if len(facts) == 0 {
		return nil
	}
	ids := make([]string, 0, len(facts))
	for _, f := range facts {
		ids = append(ids, f.ID)
	}
	recorded, err := rec.Recorded(ctx, tenantID, ids)
	if err != nil {
		return fmt.Errorf("transit: read recorded facts: %w", err)
	}
	for _, f := range facts {
		if _, done := recorded[f.ID]; done {
			continue
		}
		if err := rec.Record(ctx, tenantID, f); err != nil {
			return fmt.Errorf("transit: record the %s fact for %q version %d: %w", f.EventType(), f.Key, f.Version, err)
		}
	}
	return nil
}

// ReconcileFacts records every fact of the tenant's shared keyring the event
// log lacks: facts whose append failed, and the versions saved before facts
// existed, which first receive fact IDs saved with their material. It needs
// the shared keyring and a recorder; without them there is nothing to do.
func (s *Service) ReconcileFacts(ctx context.Context, tenantID string) error {
	p, rec := s.sharedState(), s.factRecorder()
	if p == nil || rec == nil {
		return nil
	}
	if _, _, found, err := p.store.LoadTransitKeyring(ctx, tenantID); err != nil || !found {
		return err
	}
	if err := s.mutateShared(ctx, p, tenantID, func(k *Keyring) (func(), error) {
		return k.assignMissingFacts()
	}); err != nil {
		return err
	}
	k, err := s.loadShared(ctx, p, tenantID, false)
	if err != nil {
		return err
	}
	return s.recordFacts(ctx, rec, tenantID, k.allFacts())
}

// keyFacts lists the named key's facts, oldest first; versions without a fact
// ID are skipped.
func (k *Keyring) keyFacts(name string) []Fact {
	k.mu.Lock()
	defer k.mu.Unlock()
	nk, ok := k.keys[name]
	if !ok {
		return nil
	}
	return nk.factsOf(name)
}

// allFacts lists every key's facts, by key name and then version.
func (k *Keyring) allFacts() []Fact {
	k.mu.Lock()
	defer k.mu.Unlock()
	names := make([]string, 0, len(k.keys))
	for name := range k.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Fact
	for _, name := range names {
		out = append(out, k.keys[name].factsOf(name)...)
	}
	return out
}

func (nk *namedKey) factsOf(name string) []Fact {
	var out []Fact
	for version := 1; version <= nk.latest && version < len(nk.facts); version++ {
		if nk.facts[version] != "" {
			out = append(out, Fact{ID: nk.facts[version], Key: name, Kind: nk.kind, Version: version})
		}
	}
	return out
}

// assignMissingFacts gives a fact ID to every version that has none (versions
// saved before facts existed). It returns a nil undo when nothing changed, so
// the caller saves only a ring it changed.
func (k *Keyring) assignMissingFacts() (func(), error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	type slot struct {
		key     *namedKey
		version int
	}
	var assigned []slot
	for _, nk := range k.keys {
		nk.padFacts()
		for version := 1; version <= nk.latest; version++ {
			if nk.facts[version] != "" {
				continue
			}
			id, err := newFactID()
			if err != nil {
				for _, s := range assigned {
					s.key.facts[s.version] = ""
				}
				return nil, err
			}
			nk.facts[version] = id
			assigned = append(assigned, slot{key: nk, version: version})
		}
	}
	if len(assigned) == 0 {
		return nil, nil
	}
	return func() {
		k.mu.Lock()
		defer k.mu.Unlock()
		for _, s := range assigned {
			if s.version < len(s.key.facts) {
				s.key.facts[s.version] = ""
			}
		}
	}, nil
}

// padFacts makes facts one entry per version (index 0 unused), with "" for a
// version that has no fact ID. The caller holds k.mu.
func (nk *namedKey) padFacts() {
	for len(nk.facts) < nk.latest+1 {
		nk.facts = append(nk.facts, "")
	}
}

// validFacts checks a stored key's fact IDs: none, or one entry per version,
// each empty or a fact ID, none repeated.
func validFacts(facts []string, latest int) error {
	if len(facts) == 0 {
		return nil
	}
	if len(facts) != latest+1 || facts[0] != "" {
		return fmt.Errorf("%d stored fact IDs for latest %d", len(facts)-1, latest)
	}
	seen := map[string]bool{}
	for _, id := range facts[1:] {
		if id == "" {
			continue
		}
		if !ValidFactID(id) || seen[id] {
			return errors.New("a stored fact ID is malformed or repeated")
		}
		seen[id] = true
	}
	return nil
}

// hasFacts reports whether any version has a fact ID.
func (nk *namedKey) hasFacts() bool {
	for _, id := range nk.facts {
		if id != "" {
			return true
		}
	}
	return false
}

// adoptFacts takes the fact IDs another replica saved for versions this ring
// holds without one, and for versions it is about to adopt. A version's fact
// ID never changes once saved, so an ID this ring already holds is kept.
func (nk *namedKey) adoptFacts(stored []string) {
	if len(stored) == 0 {
		return
	}
	for len(nk.facts) < len(stored) {
		nk.facts = append(nk.facts, "")
	}
	for version, id := range stored {
		if version > 0 && nk.facts[version] == "" {
			nk.facts[version] = id
		}
	}
}
