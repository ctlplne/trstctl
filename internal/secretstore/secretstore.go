// Package secretstore is the legacy/compat secret-store core (S16.3, F63). It
// predates the served secret-store path (internal/secrets.Vault, wired from
// internal/server.loadRunSecrets), which is the only secret store the running
// control plane mounts today. secretstore is retained ONLY so historical
// secret.version.written event history still replays and so the older API/env
// surfaces in this package keep compiling; NEW writes in production go through the
// served seal path, not here. See CRYPTO-004.
//
// Like the served vault, the catastrophic-risk requirements still hold:
//   - the key-encryption key (KEK) lives behind the crypto boundary in locked,
//     zeroizable memory (a seal.KeyWrapper), never as a raw []byte on the Go heap
//     (AN-3/AN-8);
//   - values are envelope-encrypted at rest with the binary seal container (a fresh
//     per-secret DEK wrapped by the KEK), held as []byte and never logged (AN-8);
//   - every write is an event so version history reconstructs from the log (AN-2);
//   - writes are idempotent (AN-5); and all state is tenant-scoped (AN-1).
package secretstore

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Config configures a Store. Supply the KEK as a seal.KeyWrapper (preferred — an
// HSM/KMS or a LocalKEK in locked memory) or, for back-compat callers, as 32 raw
// KEK bytes which New immediately copies into a LocalKEK (locked memory) and which
// the caller should Wipe afterward. New never retains the raw bytes on the heap.
type Config struct {
	// KeyWrapper wraps each secret's data-encryption key. When set it is used as-is
	// and the Store does not own its lifecycle (the caller Destroys it). This is the
	// path that keeps the KEK off the Go heap end to end.
	KeyWrapper seal.KeyWrapper
	// KEK is a back-compat way to pass a 32-byte key-encryption key as raw bytes.
	// New copies it into a LocalKEK (locked, zeroizable memory) and does not keep the
	// slice; callers should Wipe their copy. Ignored when KeyWrapper is set.
	KEK []byte

	TenantID string
	Audit    auditsink.Auditor
	Clock    func() time.Time
}

// Store is the legacy/compat secret-store core. It holds the KEK as a
// seal.KeyWrapper (locked memory behind the crypto boundary), never as raw bytes
// on the Go heap (CRYPTO-004 / AN-8).
type Store struct {
	tenantID   string
	wrapper    seal.KeyWrapper
	ownWrapper *seal.LocalKEK // non-nil only when Store created the wrapper from raw bytes
	audit      auditsink.Auditor
	clock      func() time.Time
	mu         sync.Mutex
	versions   map[string][]rev
	idem       map[string]int
}

type rev struct {
	Version   int
	Sealed    []byte // binary seal container (internal/crypto/seal), like the served vault
	CreatedAt time.Time
	Deleted   bool
}

// New validates configuration and constructs a Store.
func New(cfg Config) (*Store, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("secrets: TenantID required (AN-1)")
	}
	s := &Store{
		tenantID: cfg.TenantID,
		audit:    cfg.Audit,
		clock:    cfg.Clock,
		versions: map[string][]rev{},
		idem:     map[string]int{},
	}
	switch {
	case cfg.KeyWrapper != nil:
		s.wrapper = cfg.KeyWrapper
	case len(cfg.KEK) == 32:
		// Copy the raw KEK into locked, zeroizable memory and drop the heap copy.
		k, err := seal.NewLocalKEK(cfg.KEK)
		if err != nil {
			return nil, fmt.Errorf("secrets: load KEK: %w", err)
		}
		s.wrapper = k
		s.ownWrapper = k
	case len(cfg.KEK) != 0:
		return nil, fmt.Errorf("secrets: KEK must be 32 bytes (AES-256)")
	default:
		return nil, fmt.Errorf("secrets: a KeyWrapper or a 32-byte KEK is required")
	}
	if s.audit == nil {
		s.audit = auditsink.Nop{}
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s, nil
}

// Close zeroizes the KEK if (and only if) this Store created it from raw bytes. A
// caller-supplied KeyWrapper is owned by the caller and is left untouched.
func (s *Store) Close() {
	if s.ownWrapper != nil {
		s.ownWrapper.Destroy()
	}
}

func (s *Store) aad(path string) []byte { return []byte(s.tenantID + "|" + path) }

// Put stores a new version of the secret at path, envelope-encrypted with the
// binary seal container. It is idempotent on idempotencyKey: a replay returns the
// original version.
func (s *Store) Put(ctx context.Context, path string, value []byte, idempotencyKey string) (int, error) {
	if path == "" {
		return 0, fmt.Errorf("secrets: empty path")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if idempotencyKey != "" {
		if v, ok := s.idem[idempotencyKey]; ok {
			return v, nil
		}
	}
	sealed, err := seal.Seal(s.wrapper, value, s.aad(path))
	if err != nil {
		return 0, err
	}
	next := len(s.versions[path]) + 1
	// The version-written event is the AN-2 source of truth — version history
	// reconstructs from the log, so a write that cannot be recorded MUST fail
	// closed rather than silently leave a local version with no event behind it
	// (CODE-001). Emit before mutating the in-memory map and idempotency record so
	// a dropped event leaves no orphaned local state.
	if err := s.emitWrite(ctx, path, next, sealed); err != nil {
		return 0, fmt.Errorf("secrets: record write event: %w", err)
	}
	s.versions[path] = append(s.versions[path], rev{Version: next, Sealed: sealed, CreatedAt: s.clock().UTC()})
	if idempotencyKey != "" {
		s.idem[idempotencyKey] = next
	}
	return next, nil
}

// emitWrite records the version-written event (the AN-2 source of truth for the
// secret's history) and RETURNS the append error instead of discarding it
// (CODE-001): a lost write event would make the version unrebuildable from the
// log, so Put fails closed on a dropped event.
func (s *Store) emitWrite(ctx context.Context, path string, version int, sealed []byte) error {
	payload, err := json.Marshal(writeEvent{Path: path, Version: version, Sealed: sealed})
	if err != nil {
		return err
	}
	return s.audit.Audit(ctx, EventVersionWritten, s.tenantID, payload)
}

// EventVersionWritten is the event type emitted for each secret write.
const EventVersionWritten = "secret.version.written"

// writeEvent is the version-written event payload. Sealed is the binary seal
// container (the format the served vault uses); Envelope is the pre-CRYPTO-004
// legacy JSON envelope kept ONLY so historical events still decode on replay.
// Exactly one is populated for any given record.
type writeEvent struct {
	Path     string          `json:"path"`
	Version  int             `json:"version"`
	Sealed   []byte          `json:"sealed,omitempty"`
	Envelope crypto.Envelope `json:"envelope,omitempty"`
}

// Get returns the latest non-deleted version's plaintext and its version number.
// The returned []byte is the caller's to wipe when done (AN-8).
func (s *Store) Get(_ context.Context, path string) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	revs := s.versions[path]
	if len(revs) == 0 {
		return nil, 0, fmt.Errorf("secrets: %q not found", path)
	}
	last := revs[len(revs)-1]
	if last.Deleted { // current state is a tombstone (rollback can restore it)
		return nil, 0, fmt.Errorf("secrets: %q is deleted", path)
	}
	pt, err := seal.Open(s.wrapper, last.Sealed, s.aad(path))
	return pt, last.Version, err
}

// GetVersion returns a specific version's plaintext.
func (s *Store) GetVersion(_ context.Context, path string, version int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.versions[path] {
		if r.Version == version && !r.Deleted {
			return seal.Open(s.wrapper, r.Sealed, s.aad(path))
		}
	}
	return nil, fmt.Errorf("secrets: %q v%d not found", path, version)
}

// Versions lists the live (non-deleted) version numbers at path, ascending.
func (s *Store) Versions(path string) []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []int
	for _, r := range s.versions[path] {
		if !r.Deleted {
			out = append(out, r.Version)
		}
	}
	return out
}

// rollbackPlaintextHook, when non-nil, is invoked by Rollback with the intermediate
// plaintext buffer just before it is wiped. It exists only so a test can prove the
// wipe actually zeroizes that exact buffer; it is nil in production.
var rollbackPlaintextHook func([]byte)

// Rollback re-publishes the plaintext of toVersion as a new version. The
// intermediate plaintext is wiped through the crypto boundary (secret.Wipe, which
// keeps the zeroing alive so the compiler cannot elide it — CRYPTO-004/CRYPTO-006),
// not a hand-rolled loop the optimizer may treat as dead.
func (s *Store) Rollback(ctx context.Context, path string, toVersion int) (int, error) {
	pt, err := s.GetVersion(ctx, path, toVersion)
	if err != nil {
		return 0, err
	}
	defer func() {
		if rollbackPlaintextHook != nil {
			rollbackPlaintextHook(pt)
		}
		secret.Wipe(pt)
	}()
	return s.Put(ctx, path, pt, "")
}

// Delete soft-deletes the secret (a tombstone version; history is retained).
func (s *Store) Delete(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.versions[path]) == 0 {
		return fmt.Errorf("secrets: %q not found", path)
	}
	next := len(s.versions[path]) + 1
	// The delete tombstone is event-sourced (AN-2); fail closed if it cannot be
	// recorded rather than soft-deleting locally with no event (CODE-001).
	if err := s.audit.Audit(ctx, "secret.deleted", s.tenantID, []byte(fmt.Sprintf(`{"path":%q}`, path))); err != nil {
		return fmt.Errorf("secrets: record delete event: %w", err)
	}
	s.versions[path] = append(s.versions[path], rev{Version: next, Deleted: true, CreatedAt: s.clock().UTC()})
	return nil
}

// Purge hard-removes all versions of a secret.
func (s *Store) Purge(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Record the purge (AN-2 source of truth) BEFORE destroying local state, and
	// fail closed if it cannot be recorded — a hard delete with no event behind it
	// is an unrebuildable, unauditable removal (CODE-001).
	if err := s.audit.Audit(ctx, "secret.purged", s.tenantID, []byte(fmt.Sprintf(`{"path":%q}`, path))); err != nil {
		return fmt.Errorf("secrets: record purge event: %w", err)
	}
	delete(s.versions, path)
	return nil
}

// Rev is one still-encrypted version produced by Reconstruct. It is a pure
// projection of a version-written event and carries the ciphertext exactly as it
// was recorded — Reconstruct never decrypts, so it needs no KEK. Exactly one field
// is set: Sealed for the current binary seal container, or Legacy for a
// pre-CRYPTO-004 JSON envelope. Open it with the matching KEK.
type Rev struct {
	Sealed []byte           // binary seal container (internal/crypto/seal); use seal.Open
	Legacy *crypto.Envelope // pre-CRYPTO-004 JSON envelope; use crypto.OpenEnvelope
}

// AAD returns the additional-authenticated-data a sealed version is bound to, so a
// caller opening a Rev uses the exact binding Put sealed it with.
func AAD(tenantID, path string) []byte { return []byte(tenantID + "|" + path) }

// Open decrypts a reconstructed version under w (which must wrap the same KEK the
// value was sealed with) and the path's AAD. The returned plaintext is the caller's
// to wipe (AN-8). A binary-container Rev opens through the seal boundary; a legacy
// Rev opens the JSON envelope through the crypto boundary with the raw KEK borrowed
// transiently from locked memory (it never lands on the heap).
func (rv Rev) Open(w seal.KeyWrapper, tenantID, path string) ([]byte, error) {
	aad := AAD(tenantID, path)
	switch {
	case rv.Sealed != nil:
		return seal.Open(w, rv.Sealed, aad)
	case rv.Legacy != nil:
		lk, ok := w.(*seal.LocalKEK)
		if !ok {
			return nil, fmt.Errorf("secrets: opening a legacy JSON envelope requires a local KEK")
		}
		var (
			pt  []byte
			err error
		)
		if werr := lk.WithKey(func(kek []byte) error {
			pt, err = crypto.OpenEnvelope(kek, *rv.Legacy, aad)
			return err
		}); werr != nil {
			return nil, werr
		}
		return pt, nil
	default:
		return nil, fmt.Errorf("secrets: reconstructed version has no ciphertext")
	}
}

// Reconstruct rebuilds per-path encrypted version history from the event log for a
// tenant, proving the read model is a projection of the event stream (AN-2). It
// never decrypts (so it takes no KEK) and never silently drops a record: each
// version-written event is decoded by which ciphertext it carries — the current
// binary seal container, or a pre-CRYPTO-004 legacy JSON envelope — and any record
// carrying neither fails closed. Open each returned Rev with the matching KEK.
func Reconstruct(records []auditsink.Record, tenantID string) (map[string][]Rev, error) {
	out := map[string][]Rev{}
	for _, r := range records {
		if r.Type != EventVersionWritten || r.TenantID != tenantID {
			continue
		}
		var ev writeEvent
		if err := json.Unmarshal(r.Data, &ev); err != nil {
			return nil, fmt.Errorf("secrets: decode version-written event: %w", err)
		}
		switch {
		case len(ev.Sealed) > 0:
			out[ev.Path] = append(out[ev.Path], Rev{Sealed: ev.Sealed})
		case ev.Envelope.Ciphertext != nil:
			env, err := crypto.NormalizeEnvelope(ev.Envelope)
			if err != nil {
				return nil, fmt.Errorf("secrets: decode legacy envelope for %q version %d: %w", ev.Path, ev.Version, err)
			}
			out[ev.Path] = append(out[ev.Path], Rev{Legacy: &env})
		default:
			return nil, fmt.Errorf("secrets: version-written event for %q version %d has no ciphertext", ev.Path, ev.Version)
		}
	}
	return out, nil
}
