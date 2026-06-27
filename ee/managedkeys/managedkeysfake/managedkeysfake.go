// Package managedkeysfake is an in-memory crypto.RemoteKeyLifecycle backend that
// models a cloud KMS / networked HSM for tests and local development. It lets the
// served managed-key lifecycle (ee/managedkeys) be exercised end to end —
// generate -> rotate -> revoke -> zeroize — without a real provider, the same role
// digicertfake/adcsfake play for their CA backends.
//
// It mirrors the real provider's remote-custody semantics: keys are "born in the
// provider" (their material is generated here and a provider-style key id is
// returned), and the lifecycle is enforced at the device — a revoked key refuses to
// sign, a zeroized key is destroyed and gone. The private material is generated
// through the AN-3 crypto boundary (crypto.SoftwareBackend) so the returned public
// keys are real and verifiable.
package managedkeysfake

import (
	"context"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

var _ crypto.RemoteKeyLifecycle = (*Backend)(nil)

// keyState is the provider-side state of a fake managed key.
type keyState int

const (
	stateActive keyState = iota
	stateDisabled
	stateScheduledDeletion
)

// managed is one key held "in the provider". The Signer wraps real generated
// material so signatures and public keys are valid; state gates use.
type managed struct {
	signer crypto.Signer
	alg    crypto.Algorithm
	state  keyState
}

// Backend is an in-memory RemoteKeyLifecycle. The zero value is not usable; build
// one with New.
type Backend struct {
	mu   sync.Mutex
	seq  int
	keys map[string]*managed
}

// New constructs an empty fake KMS backend.
func New() *Backend { return &Backend{keys: map[string]*managed{}} }

// Name identifies the backend.
func (b *Backend) Name() string { return "fake-kms" }

// GenerateManagedKey mints a key "in the provider" and returns a Signer plus a
// KeyRef. The material is generated locally through the crypto boundary; only the
// handle (a provider-style id) and public key cross out.
func (b *Backend) GenerateManagedKey(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, crypto.KeyRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, crypto.KeyRef{}, err
	}
	signer, err := crypto.NewSoftwareBackend().GenerateKey(alg)
	if err != nil {
		return nil, crypto.KeyRef{}, fmt.Errorf("fake-kms: generate: %w", err)
	}
	b.mu.Lock()
	b.seq++
	id := fmt.Sprintf("fake-kms-key-%04d", b.seq)
	b.keys[id] = &managed{signer: signer, alg: alg, state: stateActive}
	b.mu.Unlock()
	return signer, crypto.KeyRef{ID: id, Algorithm: alg}, nil
}

// RotateKey mints a successor key of the same algorithm. The prior key is left
// intact (supersede-then-retire), matching the real backend.
func (b *Backend) RotateKey(ctx context.Context, ref crypto.KeyRef) (crypto.Signer, crypto.KeyRef, error) {
	if ref.ID == "" {
		return nil, crypto.KeyRef{}, fmt.Errorf("fake-kms: rotate requires a key ref")
	}
	b.mu.Lock()
	_, ok := b.keys[ref.ID]
	b.mu.Unlock()
	if !ok {
		return nil, crypto.KeyRef{}, fmt.Errorf("fake-kms: rotate: unknown key %q", ref.ID)
	}
	return b.GenerateManagedKey(ctx, ref.Algorithm)
}

// RevokeKey disables the key so it refuses further signatures (fail-closed at the
// provider). Reversible until zeroized.
func (b *Backend) RevokeKey(_ context.Context, ref crypto.KeyRef) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.keys[ref.ID]
	if !ok {
		return fmt.Errorf("fake-kms: revoke: unknown key %q", ref.ID)
	}
	if m.state == stateScheduledDeletion {
		return fmt.Errorf("fake-kms: revoke: key %q is scheduled for deletion", ref.ID)
	}
	m.state = stateDisabled
	return nil
}

// ZeroizeKey schedules destruction of the key material; afterwards it is gone and
// cannot sign. Irreversible (the remote analogue of wiping a locked buffer).
func (b *Backend) ZeroizeKey(_ context.Context, ref crypto.KeyRef) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.keys[ref.ID]
	if !ok {
		return fmt.Errorf("fake-kms: zeroize: unknown key %q", ref.ID)
	}
	m.state = stateScheduledDeletion
	m.signer = nil // material destroyed at the provider
	return nil
}

// Active reports whether ref is a known, non-revoked, non-zeroized key — so a test
// can assert the provider-side state after a lifecycle op.
func (b *Backend) Active(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.keys[id]
	return ok && m.state == stateActive
}

// Disabled reports whether ref is a revoked (disabled) key.
func (b *Backend) Disabled(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.keys[id]
	return ok && m.state == stateDisabled
}

// Zeroized reports whether ref's material has been destroyed at the provider.
func (b *Backend) Zeroized(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.keys[id]
	return ok && m.state == stateScheduledDeletion
}
