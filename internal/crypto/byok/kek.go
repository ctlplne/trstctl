package byok

// AN-8: this file's key material lives in seal.LocalKEK (a locked secret.Buffer)
// and transient []byte that is wiped; no secret-named field is a string. The
// invariant is pinned by internal/crypto's TestKeyMaterialFieldsAreNotStrings (see
// byok.go's package doc for why the //trstctl:keymaterial marker is not used).

import (
	"context"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// ManagedKEK is the secrets key-encryption key (KEK) under the same lifecycle as a
// signing key: generate-or-import → rotate → revoke → zeroize, event-sourced and
// held in locked memory (a seal.LocalKEK, AES-256 in an mlock'd/zeroized buffer).
// The KEK roots envelope encryption for sealed secrets, so its lifecycle is the
// highest-blast-radius rotation in the product.
//
// Rotate here is a re-wrap rotation: a fresh KEK is generated and becomes the
// active wrapper, the prior KEK is destroyed, and the new version is recorded. An
// operator re-wraps existing DEKs under the new KEK out of band (the prior KEK's
// sealed blobs are re-Open'd with the old wrapper before it is zeroized in a real
// migration); this type owns the in-memory key custody and the lifecycle event
// trail, not the bulk re-encryption.
type ManagedKEK struct {
	mu      sync.Mutex
	keyID   string
	sink    EventSink
	kek     *seal.LocalKEK
	origin  Origin
	version int
	state   State
}

// GenerateKEK mints a fresh random 256-bit KEK in the boundary and brings it under
// lifecycle management at version 1, emitting EventKeyGenerated.
func GenerateKEK(ctx context.Context, sink EventSink, tenantID, keyID string) (*ManagedKEK, error) {
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	raw, err := seal.GenerateKEK()
	if err != nil {
		return nil, fmt.Errorf("byok: generate KEK: %w", err)
	}
	defer secret.Wipe(raw)
	lk, err := seal.NewLocalKEK(raw)
	if err != nil {
		return nil, fmt.Errorf("byok: wrap KEK: %w", err)
	}
	m := &ManagedKEK{keyID: keyID, sink: sink, kek: lk, origin: OriginGenerated, version: 1, state: StateActive}
	if err := m.emit(ctx, EventKeyGenerated, tenantID, 0); err != nil {
		m.kek.Destroy()
		return nil, err
	}
	return m, nil
}

// ImportKEK is the BYOK on-ramp for the KEK: it takes an operator-supplied 32-byte
// key as []byte (never a string — AN-8), moves it into a locked buffer, and wipes
// the caller's transient copy. It emits EventKeyImported at version 1.
func ImportKEK(ctx context.Context, sink EventSink, tenantID, keyID string, raw []byte) (*ManagedKEK, error) {
	defer secret.Wipe(raw)
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	lk, err := seal.NewLocalKEK(raw)
	if err != nil {
		return nil, fmt.Errorf("byok: import KEK: %w", err)
	}
	m := &ManagedKEK{keyID: keyID, sink: sink, kek: lk, origin: OriginImported, version: 1, state: StateActive}
	if err := m.emit(ctx, EventKeyImported, tenantID, 0); err != nil {
		m.kek.Destroy()
		return nil, err
	}
	return m, nil
}

// KeyID returns the stable logical key id.
func (m *ManagedKEK) KeyID() string { return m.keyID }

// Version returns the current KEK version.
func (m *ManagedKEK) Version() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version
}

// State returns the current lifecycle state.
func (m *ManagedKEK) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// WrapDEK wraps a data-encryption key under the live KEK. It is REFUSED
// (fail-closed) once the KEK is revoked or zeroized — so a retired KEK can no
// longer protect new DEKs.
func (m *ManagedKEK) WrapDEK(dek []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.state {
	case StateRevoked:
		return nil, ErrRevoked
	case StateZeroized:
		return nil, ErrZeroized
	}
	return m.kek.WrapDEK(dek)
}

// UnwrapDEK unwraps a DEK under the live KEK. Like WrapDEK it is refused once the
// KEK is revoked or zeroized.
func (m *ManagedKEK) UnwrapDEK(wrapped []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.state {
	case StateRevoked:
		return nil, ErrRevoked
	case StateZeroized:
		return nil, ErrZeroized
	}
	return m.kek.UnwrapDEK(wrapped)
}

// Rotate re-keys the KEK: a fresh KEK becomes active, the prior KEK's locked
// buffer is destroyed, the version increments, and EventKeyRotated is emitted.
func (m *ManagedKEK) Rotate(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrTenantRequired
	}
	m.mu.Lock()
	if m.state != StateActive {
		st := m.state
		m.mu.Unlock()
		return fmt.Errorf("%w (state=%s)", ErrNotActive, st)
	}
	raw, err := seal.GenerateKEK()
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("byok: rotate KEK generate: %w", err)
	}
	fresh, err := seal.NewLocalKEK(raw)
	secret.Wipe(raw)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("byok: rotate KEK wrap: %w", err)
	}
	prior := m.kek
	priorVersion := m.version
	m.kek = fresh
	m.version++
	m.mu.Unlock()

	prior.Destroy()
	return m.emit(ctx, EventKeyRotated, tenantID, priorVersion)
}

// Revoke administratively retires the KEK; WrapDEK/UnwrapDEK are refused
// afterward. The material is not yet wiped (Zeroize does that). Idempotent.
func (m *ManagedKEK) Revoke(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrTenantRequired
	}
	m.mu.Lock()
	switch m.state {
	case StateRevoked:
		m.mu.Unlock()
		return nil
	case StateZeroized:
		m.mu.Unlock()
		return ErrZeroized
	}
	m.state = StateRevoked
	m.mu.Unlock()
	return m.emit(ctx, EventKeyRevoked, tenantID, 0)
}

// Zeroize destroys and wipes the KEK's locked buffer and moves to StateZeroized.
// Terminal; WrapDEK/UnwrapDEK are refused afterward. Idempotent.
func (m *ManagedKEK) Zeroize(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrTenantRequired
	}
	m.mu.Lock()
	if m.state == StateZeroized {
		m.mu.Unlock()
		return nil
	}
	m.kek.Destroy()
	m.state = StateZeroized
	m.mu.Unlock()
	return m.emit(ctx, EventKeyZeroized, tenantID, 0)
}

func (m *ManagedKEK) emit(ctx context.Context, typ, tenantID string, replaces int) error {
	if m.sink == nil {
		return nil
	}
	m.mu.Lock()
	ev := LifecycleEvent{
		Type: typ, TenantID: tenantID, KeyID: m.keyID, Version: m.version,
		Origin: m.origin, Kind: "kek", Replaces: replaces,
	}
	m.mu.Unlock()
	return m.sink.Emit(ctx, ev)
}
