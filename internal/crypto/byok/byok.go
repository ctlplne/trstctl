// Package byok implements the full bring-your-own-key (BYOK) / HSM key lifecycle
// for the highest-value keys trstctl custodies — CA/issuing signing keys and the
// secrets key-encryption key (KEK) — inside the AN-3 crypto boundary
// (EXC-CRYPTO-01, CRYPTO-005).
//
// The lifecycle is generate-or-import → rotate → revoke → zeroize, and every
// transition is:
//
//   - event-sourced (AN-2): each step emits a structured lifecycle event through
//     an injected EventSink. The package does NOT import internal/events or the
//     store — it stays a pure crypto-boundary citizen — so the served control
//     plane wires its real events.Log-backed sink behind this seam (the same
//     dependency-inversion pattern internal/crypto uses for every backend). A
//     test wires an in-memory sink and asserts the event sequence directly.
//   - memory-safe (AN-8): key material never lives in a string. A signing key is
//     held as a *crypto.LockedSigner (PKCS#8 DER in an mlock'd, MADV_DONTDUMP,
//     zeroized secret.Buffer, parsed to an unprotected key only for the
//     milliseconds of a signature); a KEK is held in a *seal.LocalKEK (same
//     locked buffer). On Rotate the superseded material is destroyed; on Zeroize
//     the live material is destroyed and the buffer's bytes are wiped, after which
//     the key can no longer sign or wrap.
//
// BYOK (import an externally-generated key) and generate (mint a fresh key in the
// boundary) are the two on-ramps; an HSM/KMS-resident key plugs in through the
// same Managed* handles because crypto.LockedSigner and the wrap interface are the
// boundary's portable shapes (the durable HSM-custody story — the key never
// materializing in this address space — is the KMS-backend path that implements
// the same interfaces).
//
// AN-8 note: this package handles key material but deliberately does NOT carry the
// //trstctl:keymaterial marker. That marker's marked-package rule forbids ANY
// string-typed field, which would false-positive on the legitimate non-secret
// strings here (the key id, the tenant id, the lifecycle event-type constants).
// The real AN-8 invariant — no field whose NAME denotes secret material is a
// string; the actual private bytes live in secret.Buffer-backed handles
// (crypto.LockedSigner / seal.LocalKEK) and transient []byte that is wiped — is
// pinned by internal/crypto's TestKeyMaterialFieldsAreNotStrings, which scans this
// package (the same approach the crypto core and signer use, per CRYPTO-003).
package byok

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// State is a managed key's lifecycle state.
type State string

const (
	// StateActive: the key is live and may sign / wrap.
	StateActive State = "active"
	// StateRevoked: the key is administratively revoked. It must not sign or wrap;
	// the material is still in memory (a subsequent Zeroize releases it) so an
	// operator can prove which key was retired, but every cryptographic operation
	// is refused (fail-closed).
	StateRevoked State = "revoked"
	// StateZeroized: the material has been destroyed and wiped from locked memory.
	// Terminal; nothing can be done with the handle but inspect its metadata.
	StateZeroized State = "zeroized"
)

// Origin records how the key entered the lifecycle, for the audit trail.
type Origin string

const (
	// OriginGenerated: minted inside the crypto boundary.
	OriginGenerated Origin = "generated"
	// OriginImported: supplied by the operator (true BYOK).
	OriginImported Origin = "imported"
)

// Event types emitted on the AN-2 log for every lifecycle transition. They are
// stable strings so a projection / audit consumer can dispatch on them.
const (
	EventKeyGenerated = "byok.key.generated"
	EventKeyImported  = "byok.key.imported"
	EventKeyRotated   = "byok.key.rotated"
	EventKeyRevoked   = "byok.key.revoked"
	EventKeyZeroized  = "byok.key.zeroized"
)

// Errors a lifecycle operation can return.
var (
	// ErrRevoked is returned when an operation is attempted on a revoked key.
	ErrRevoked = errors.New("byok: key is revoked")
	// ErrZeroized is returned when an operation is attempted on a zeroized key.
	ErrZeroized = errors.New("byok: key has been zeroized")
	// ErrNotActive is returned when a transition requires an active key.
	ErrNotActive = errors.New("byok: key is not active")
	// ErrTenantRequired is returned when an operation is missing a tenant id (AN-1:
	// every lifecycle event carries its tenant).
	ErrTenantRequired = errors.New("byok: tenant id is required")
)

// LifecycleEvent is the structured payload describing a single lifecycle
// transition. It is intentionally key-MATERIAL-free: it carries the key's
// identity, algorithm, version, and public key (DER) — never the private bytes —
// so it is safe to persist to the event log, the audit trail, and an export.
type LifecycleEvent struct {
	Type      string    // one of the Event* constants
	TenantID  string    // AN-1
	KeyID     string    // stable id for this logical key across rotations
	Version   int       // monotonically increasing version (rotation count + 1)
	Algorithm string    // signing algorithm (empty for a KEK)
	Origin    Origin    // generated | imported
	Kind      string    // "signing" | "kek"
	PublicDER []byte    // PKIX public key for a signing key (nil for a KEK; never private)
	Replaces  int       // the version this one supersedes (0 for the first)
	Time      time.Time // emit time (set by the sink on append when zero)
}

// EventSink receives lifecycle events. The served control plane implements it
// over events.Log (AN-2); tests implement it in memory. Emit must be safe for the
// caller to treat as at-least-once persisted before it returns nil — a returned
// error aborts the transition so a state change is never silently un-recorded.
type EventSink interface {
	Emit(ctx context.Context, e LifecycleEvent) error
}

// ManagedSigner is a CA/issuing signing key under lifecycle management. Its
// private material lives in a crypto.LockedSigner (locked, non-dumpable,
// zeroizable; parsed per-signature only). SignDigest is refused once the key is
// revoked or zeroized (fail-closed).
type ManagedSigner struct {
	mu      sync.Mutex
	keyID   string
	kind    string // "signing"
	sink    EventSink
	signer  *crypto.LockedSigner
	pub     crypto.PublicKey
	alg     crypto.Algorithm
	origin  Origin
	version int
	state   State
}

// GenerateSigner mints a fresh signing key inside the boundary and brings it under
// lifecycle management at version 1, emitting EventKeyGenerated. The private key
// is held in locked memory from the moment of creation.
func GenerateSigner(ctx context.Context, sink EventSink, tenantID, keyID string, alg crypto.Algorithm) (*ManagedSigner, error) {
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, fmt.Errorf("byok: generate signing key: %w", err)
	}
	m := newManagedSigner(sink, keyID, ls, alg, OriginGenerated)
	if err := m.emit(ctx, EventKeyGenerated, tenantID, 0); err != nil {
		m.signer.Destroy() // do not leak a key whose creation we could not record
		return nil, err
	}
	return m, nil
}

// ImportSigner is the true BYOK on-ramp: it takes an operator-supplied private key
// as PKCS#8 DER ([]byte, never a string — AN-8), moves it into locked memory, and
// wipes the caller's transient copy. The caller passes the algorithm the key uses.
// It emits EventKeyImported at version 1. The supplied der slice is zeroized by
// this call regardless of outcome so the unprotected copy does not linger.
func ImportSigner(ctx context.Context, sink EventSink, tenantID, keyID string, alg crypto.Algorithm, der []byte) (*ManagedSigner, error) {
	defer secret.Wipe(der)
	if tenantID == "" {
		return nil, ErrTenantRequired
	}
	ls, err := crypto.NewLockedSignerFromPKCS8(alg, der)
	if err != nil {
		return nil, fmt.Errorf("byok: import signing key: %w", err)
	}
	m := newManagedSigner(sink, keyID, ls, alg, OriginImported)
	if err := m.emit(ctx, EventKeyImported, tenantID, 0); err != nil {
		m.signer.Destroy()
		return nil, err
	}
	return m, nil
}

func newManagedSigner(sink EventSink, keyID string, ls *crypto.LockedSigner, alg crypto.Algorithm, origin Origin) *ManagedSigner {
	return &ManagedSigner{
		keyID: keyID, kind: "signing", sink: sink, signer: ls,
		pub: ls.Public(), alg: alg, origin: origin, version: 1, state: StateActive,
	}
}

// KeyID returns the stable logical key id (unchanged across rotations).
func (m *ManagedSigner) KeyID() string { return m.keyID }

// Version returns the current key version (1 for the first, +1 per rotation).
func (m *ManagedSigner) Version() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version
}

// State returns the current lifecycle state.
func (m *ManagedSigner) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Public returns the current public key (changes on rotation). It is safe to call
// in any state; after zeroize it returns the last public key, which is not secret.
func (m *ManagedSigner) Public() crypto.PublicKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pub
}

// Algorithm reports the key's signing algorithm.
func (m *ManagedSigner) Algorithm() crypto.Algorithm {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.alg
}

// SignDigest signs a pre-computed digest with the live key. It is REFUSED
// (fail-closed) once the key is revoked or zeroized — this is the property that
// makes revocation/zeroization meaningful: an old key cannot sign after retirement.
func (m *ManagedSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.state {
	case StateRevoked:
		return nil, ErrRevoked
	case StateZeroized:
		return nil, ErrZeroized
	}
	return m.signer.SignDigest(digest, opts)
}

// Rotate re-keys the signer: it generates a fresh key of the same algorithm,
// atomically swaps it in as the new live key (incrementing the version), DESTROYS
// the superseded key's locked buffer, and emits EventKeyRotated recording the new
// and prior versions. After Rotate, SignDigest uses the new key and the old
// private material is gone from memory. Rotate requires the key be active.
func (m *ManagedSigner) Rotate(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrTenantRequired
	}
	m.mu.Lock()
	if m.state != StateActive {
		st := m.state
		m.mu.Unlock()
		return fmt.Errorf("%w (state=%s)", ErrNotActive, st)
	}
	fresh, err := crypto.GenerateLockedKey(m.alg)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("byok: rotate generate: %w", err)
	}
	prior := m.signer
	priorVersion := m.version
	m.signer = fresh
	m.pub = fresh.Public()
	m.version++
	newVersion := m.version
	m.mu.Unlock()

	// The superseded private key is destroyed regardless of whether the event
	// emit succeeds — the old material must not linger. If the emit fails, the
	// rotation has still happened in memory; the error is surfaced so the caller
	// can react (and the prior key is already gone, so there is no rollback to a
	// usable old key).
	prior.Destroy()
	if err := m.emit(ctx, EventKeyRotated, tenantID, priorVersion); err != nil {
		return err
	}
	_ = newVersion
	return nil
}

// Revoke administratively retires the key: it moves to StateRevoked, after which
// SignDigest is refused, and emits EventKeyRevoked. The material is NOT yet wiped
// (Zeroize does that) so an operator/auditor can still prove the key's identity;
// but it can no longer be used. Revoke is idempotent for an already-revoked key
// (returns nil without re-emitting); it is refused on a zeroized key.
func (m *ManagedSigner) Revoke(ctx context.Context, tenantID string) error {
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

// Zeroize destroys and wipes the key's locked buffer and moves to StateZeroized.
// After Zeroize the private material is gone from memory, SignDigest is refused,
// and the handle is terminal. It emits EventKeyZeroized. Zeroize is idempotent.
func (m *ManagedSigner) Zeroize(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrTenantRequired
	}
	m.mu.Lock()
	if m.state == StateZeroized {
		m.mu.Unlock()
		return nil
	}
	m.signer.Destroy()
	m.state = StateZeroized
	m.mu.Unlock()
	return m.emit(ctx, EventKeyZeroized, tenantID, 0)
}

func (m *ManagedSigner) emit(ctx context.Context, typ, tenantID string, replaces int) error {
	if m.sink == nil {
		return nil
	}
	m.mu.Lock()
	ev := LifecycleEvent{
		Type: typ, TenantID: tenantID, KeyID: m.keyID, Version: m.version,
		Algorithm: string(m.alg), Origin: m.origin, Kind: m.kind,
		PublicDER: append([]byte(nil), m.pub.DER...), Replaces: replaces,
	}
	m.mu.Unlock()
	return m.sink.Emit(ctx, ev)
}
