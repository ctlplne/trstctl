// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const durableScopesFile = "pcas-delegation-scopes.json"

// DurableScopeStore stores signer-enforced delegation scopes in the signer
// custody directory. It is intentionally file-backed: the signer process owns the
// enforcement view and needs no SQL driver or control-plane callback (AN-4).
type DurableScopeStore struct {
	mu   sync.Mutex
	path string
}

type durableScopes struct {
	Scopes []Scope `json:"scopes"`
}

func NewDurableScopeStore(dir string) *DurableScopeStore {
	return &DurableScopeStore{path: filepath.Join(dir, durableScopesFile)}
}

func (s *DurableScopeStore) UpsertScope(scope Scope) error {
	if scope.ID == "" {
		return errors.New("delegation: scope id required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tree, err := s.loadTreeLocked()
	if err != nil {
		return err
	}
	tree.AddScope(scope.ID, scope.Parent, scope.Constraint)
	return s.saveTreeLocked(tree)
}

func (s *DurableScopeStore) RaiseFloor(scopeID string, epochFloor uint64) error {
	if scopeID == "" {
		return errors.New("delegation: scope id required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tree, err := s.loadTreeLocked()
	if err != nil {
		return err
	}
	scope, ok := tree.scopes[scopeID]
	if !ok {
		return fmt.Errorf("delegation: unknown scope %q", scopeID)
	}
	if epochFloor > scope.Constraint.EpochFloor {
		scope.Constraint.EpochFloor = epochFloor
		tree.scopes[scopeID] = scope
	}
	return s.saveTreeLocked(tree)
}

func (s *DurableScopeStore) LoadTree() (*Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadTreeLocked()
}

func (s *DurableScopeStore) CheckAndBind(scope string, targetEpoch uint64) (string, error) {
	tree, err := s.LoadTree()
	if err != nil {
		return "", err
	}
	return NewMinterConstraint(tree).CheckAndBind(scope, targetEpoch)
}

func (s *DurableScopeStore) loadTreeLocked() (*Tree, error) {
	tree := NewTree()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return tree, nil
	}
	if err != nil {
		return nil, err
	}
	var persisted durableScopes
	if err := json.Unmarshal(data, &persisted); err != nil {
		return nil, fmt.Errorf("delegation: read durable scopes: %w", err)
	}
	for _, scope := range persisted.Scopes {
		tree.AddScope(scope.ID, scope.Parent, scope.Constraint)
	}
	return tree, nil
}

func (s *DurableScopeStore) saveTreeLocked(tree *Tree) error {
	persisted := durableScopes{Scopes: make([]Scope, 0, len(tree.scopes))}
	for _, scope := range tree.scopes {
		persisted.Scopes = append(persisted.Scopes, scope)
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
