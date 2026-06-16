// Package secrets is the encrypted, versioned secret-store core (S16.3, F63): the
// catastrophic-risk heart of the secret store. Values are envelope-encrypted at
// rest (per-secret DEK wrapped by the KEK, via the crypto boundary), held as
// []byte and never logged (AN-8); every write is an event so version history
// reconstructs from the log (AN-2); writes are idempotent (AN-5); and all state
// is tenant-scoped (AN-1). This package is storage + history only — access control
// and the external API are S16.3a; the developer environment model is S16.4.
package secretstore

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

// Config configures a Store.
type Config struct {
	TenantID string
	KEK      []byte // 32-byte key-encryption key (software or HSM-derived, S9.x)
	Audit    auditsink.Auditor
	Clock    func() time.Time
}

// Store is the secret-store core.
type Store struct {
	tenantID string
	kek      []byte
	audit    auditsink.Auditor
	clock    func() time.Time
	mu       sync.Mutex
	versions map[string][]rev
	idem     map[string]int
}

type rev struct {
	Version   int
	Env       crypto.Envelope
	CreatedAt time.Time
	Deleted   bool
}

// New validates configuration and constructs a Store.
func New(cfg Config) (*Store, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("secrets: TenantID required (AN-1)")
	}
	if len(cfg.KEK) != 32 {
		return nil, fmt.Errorf("secrets: KEK must be 32 bytes (AES-256)")
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Store{tenantID: cfg.TenantID, kek: cfg.KEK, audit: cfg.Audit, clock: cfg.Clock, versions: map[string][]rev{}, idem: map[string]int{}}, nil
}

func (s *Store) aad(path string) []byte { return []byte(s.tenantID + "|" + path) }

// Put stores a new version of the secret at path, envelope-encrypted. It is
// idempotent on idempotencyKey: a replay returns the original version.
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
	env, err := crypto.SealEnvelope(s.kek, value, s.aad(path))
	if err != nil {
		return 0, err
	}
	next := len(s.versions[path]) + 1
	// The version-written event is the AN-2 source of truth — version history
	// reconstructs from the log, so a write that cannot be recorded MUST fail
	// closed rather than silently leave a local version with no event behind it
	// (CODE-001). Emit before mutating the in-memory map and idempotency record so
	// a dropped event leaves no orphaned local state.
	if err := s.emitWrite(ctx, path, next, env); err != nil {
		return 0, fmt.Errorf("secrets: record write event: %w", err)
	}
	s.versions[path] = append(s.versions[path], rev{Version: next, Env: env, CreatedAt: s.clock().UTC()})
	if idempotencyKey != "" {
		s.idem[idempotencyKey] = next
	}
	return next, nil
}

// emitWrite records the version-written event (the AN-2 source of truth for the
// secret's history) and RETURNS the append error instead of discarding it
// (CODE-001): a lost write event would make the version unrebuildable from the
// log, so Put fails closed on a dropped event.
func (s *Store) emitWrite(ctx context.Context, path string, version int, env crypto.Envelope) error {
	payload, err := json.Marshal(writeEvent{Path: path, Version: version, Envelope: env})
	if err != nil {
		return err
	}
	return s.audit.Audit(ctx, EventVersionWritten, s.tenantID, payload)
}

// EventVersionWritten is the event type emitted for each secret write.
const EventVersionWritten = "secret.version.written"

type writeEvent struct {
	Path     string          `json:"path"`
	Version  int             `json:"version"`
	Envelope crypto.Envelope `json:"envelope"`
}

// Get returns the latest non-deleted version's plaintext and its version number.
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
	pt, err := crypto.OpenEnvelope(s.kek, last.Env, s.aad(path))
	return pt, last.Version, err
}

// GetVersion returns a specific version's plaintext.
func (s *Store) GetVersion(_ context.Context, path string, version int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.versions[path] {
		if r.Version == version && !r.Deleted {
			return crypto.OpenEnvelope(s.kek, r.Env, s.aad(path))
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

// Rollback re-publishes the plaintext of toVersion as a new version.
func (s *Store) Rollback(ctx context.Context, path string, toVersion int) (int, error) {
	pt, err := s.GetVersion(ctx, path, toVersion)
	if err != nil {
		return 0, err
	}
	v, err := s.Put(ctx, path, pt, "")
	for i := range pt {
		pt[i] = 0
	}
	return v, err
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

// Reconstruct rebuilds per-path version envelopes from the event log for a tenant,
// proving the read model is a projection of the event stream (AN-2). The returned
// envelopes are still encrypted; callers with the KEK can OpenEnvelope them.
func Reconstruct(records []auditsink.Record, tenantID string) map[string][]crypto.Envelope {
	out := map[string][]crypto.Envelope{}
	for _, r := range records {
		if r.Type != EventVersionWritten || r.TenantID != tenantID {
			continue
		}
		var ev writeEvent
		if json.Unmarshal(r.Data, &ev) == nil {
			out[ev.Path] = append(out[ev.Path], ev.Envelope)
		}
	}
	return out
}
