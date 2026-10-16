// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

const durableScopesFile = "pcas-delegation-scopes-v2.json"

// Command is the public, tenant-bound instruction sent to the isolated signer.
// OperationID is the outbox request ID. Exact retries return the original receipt.
type Command struct {
	TenantID      string `json:"tenant_id"`
	OperationID   string `json:"operation_id"`
	Kind          string `json:"kind"`
	ScopeID       string `json:"scope_id"`
	ParentScopeID string `json:"parent_scope_id,omitempty"`
	EpochFloor    uint64 `json:"epoch_floor"`
}

// Receipt is the signer's durable, signed readback of the applied scope state.
type Receipt struct {
	Command
	AppliedParentScopeID string `json:"applied_parent_scope_id"`
	AppliedFloor         uint64 `json:"applied_floor"`
	PublicKeyDER         []byte `json:"public_key_der"`
	Signature            []byte `json:"signature"`
}

func (r Receipt) SignedBody() ([]byte, error) {
	return json.Marshal(struct {
		Domain string `json:"domain"`
		Command
		AppliedParentScopeID string `json:"applied_parent_scope_id"`
		AppliedFloor         uint64 `json:"applied_floor"`
	}{Domain: "trstctl/pcas/delegation/receipt/v1", Command: r.Command,
		AppliedParentScopeID: r.AppliedParentScopeID, AppliedFloor: r.AppliedFloor})
}

func (r Receipt) Verify() error {
	body, err := r.SignedBody()
	if err != nil {
		return err
	}
	return crypto.VerifyMessage(r.PublicKeyDER, body, r.Signature)
}

type persistedScope struct {
	TenantID string `json:"tenant_id"`
	Scope
}

type persistedOperation struct {
	Digest  string  `json:"digest"`
	Receipt Receipt `json:"receipt"`
}

type durableScopes struct {
	Scopes     []persistedScope              `json:"scopes"`
	Operations map[string]persistedOperation `json:"operations"`
}

// DurableScopeStore is signer-owned enforcement state; it has no SQL access.
// The scope and operation receipt are atomically replaced in one fsynced file.
type DurableScopeStore struct {
	mu   sync.Mutex
	path string
}

func NewDurableScopeStore(dir string) *DurableScopeStore {
	return &DurableScopeStore{path: filepath.Join(dir, durableScopesFile)}
}

func scopeKey(tenantID, id string) string { return tenantID + "\x00" + id }

// Apply invokes sign only after validating the resulting tenant tree. The sign
// callback must journal a signature by operation ID, so a crash between signing
// and the scope-file rename replays byte-identical evidence.
func (s *DurableScopeStore) Apply(cmd Command, sign func(string, []byte) ([]byte, []byte, error)) (Receipt, error) {
	if cmd.TenantID == "" || cmd.OperationID == "" || cmd.ScopeID == "" ||
		(cmd.Kind != "scope" && cmd.Kind != "floor") || cmd.ScopeID == cmd.ParentScopeID {
		return Receipt{}, errors.New("delegation: invalid tenant, operation, kind or scope")
	}
	if cmd.Kind == "floor" && cmd.ParentScopeID != "" {
		return Receipt{}, errors.New("delegation: floor command cannot change parent")
	}
	body, err := json.Marshal(cmd)
	if err != nil {
		return Receipt{}, err
	}
	digest := crypto.SHA256Sum(body)
	digestHex := hex.EncodeToString(digest[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return Receipt{}, err
	}
	opKey := scopeKey(cmd.TenantID, cmd.OperationID)
	if old, exists := state.Operations[opKey]; exists {
		if old.Digest != digestHex {
			return Receipt{}, errors.New("delegation: operation id reused with different command")
		}
		if err := old.Receipt.Verify(); err != nil {
			return Receipt{}, fmt.Errorf("delegation: corrupt stored receipt: %w", err)
		}
		return old.Receipt, nil
	}
	index := -1
	for i := range state.Scopes {
		if scopeKey(state.Scopes[i].TenantID, state.Scopes[i].ID) == scopeKey(cmd.TenantID, cmd.ScopeID) {
			index = i
			break
		}
	}
	if cmd.Kind == "floor" && index < 0 {
		return Receipt{}, fmt.Errorf("delegation: unknown scope %q", cmd.ScopeID)
	}
	if index >= 0 {
		current := state.Scopes[index]
		if cmd.Kind == "scope" && current.Parent != cmd.ParentScopeID {
			return Receipt{}, errors.New("delegation: scope parent is immutable")
		}
		if cmd.EpochFloor < current.Constraint.EpochFloor {
			return Receipt{}, errors.New("delegation: epoch floor cannot decrease")
		}
		state.Scopes[index].Constraint.EpochFloor = cmd.EpochFloor
	} else {
		state.Scopes = append(state.Scopes, persistedScope{TenantID: cmd.TenantID,
			Scope: Scope{ID: cmd.ScopeID, Parent: cmd.ParentScopeID, Constraint: Constraint{EpochFloor: cmd.EpochFloor}}})
		index = len(state.Scopes) - 1
	}
	if _, err := treeForTenant(state.Scopes, cmd.TenantID).Path(cmd.ScopeID); err != nil {
		return Receipt{}, err // missing ancestor or cycle
	}
	receipt := Receipt{Command: cmd, AppliedParentScopeID: state.Scopes[index].Parent,
		AppliedFloor: state.Scopes[index].Constraint.EpochFloor}
	signedBody, err := receipt.SignedBody()
	if err != nil {
		return Receipt{}, err
	}
	if sign == nil {
		return Receipt{}, errors.New("delegation: signer receipt callback unavailable")
	}
	receipt.PublicKeyDER, receipt.Signature, err = sign(cmd.OperationID, signedBody)
	if err != nil {
		return Receipt{}, err
	}
	if err := receipt.Verify(); err != nil {
		return Receipt{}, fmt.Errorf("delegation: invalid signer receipt: %w", err)
	}
	state.Operations[opKey] = persistedOperation{Digest: digestHex, Receipt: receipt}
	if err := s.saveLocked(state); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func treeForTenant(scopes []persistedScope, tenantID string) *Tree {
	tree := NewTree()
	for _, scope := range scopes {
		if scope.TenantID == tenantID {
			tree.AddScope(scope.ID, scope.Parent, scope.Constraint)
		}
	}
	return tree
}

// CheckAndBind reads the signer's durable tenant tree on every mint.
func (s *DurableScopeStore) CheckAndBind(tenantID, scope string, targetEpoch uint64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	return NewMinterConstraint(treeForTenant(state.Scopes, tenantID)).CheckAndBind(tenantID, scope, targetEpoch)
}

func (s *DurableScopeStore) loadLocked() (durableScopes, error) {
	state := durableScopes{Operations: map[string]persistedOperation{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("delegation: read durable scopes: %w", err)
	}
	if state.Operations == nil {
		return state, errors.New("delegation: missing operation journal")
	}
	seen := map[string]bool{}
	for _, scope := range state.Scopes {
		key := scopeKey(scope.TenantID, scope.ID)
		if scope.TenantID == "" || scope.ID == "" || seen[key] {
			return state, errors.New("delegation: invalid or duplicate persisted scope")
		}
		seen[key] = true
	}
	for _, op := range state.Operations {
		if err := op.Receipt.Verify(); err != nil {
			return state, fmt.Errorf("delegation: invalid persisted receipt: %w", err)
		}
	}
	return state, nil
}

func (s *DurableScopeStore) saveLocked(state durableScopes) error {
	sort.Slice(state.Scopes, func(i, j int) bool {
		return scopeKey(state.Scopes[i].TenantID, state.Scopes[i].ID) < scopeKey(state.Scopes[j].TenantID, state.Scopes[j].ID)
	})
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".pcas-delegation-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Chmod(0o600); err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	d, err := os.Open(dir) // #nosec G304 -- signer-owned keystore directory selected at signer startup; fsync makes the scope rename durable (CWE-22)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
