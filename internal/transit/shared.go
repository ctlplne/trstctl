// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Shared keyring (A125). With shared persistence installed, each tenant's
// keyring is one row every replica reads and writes, sealed under the tenant's
// key domain. A replica loads a tenant's row the first time the tenant is used,
// reloads it when an operation names a key or version it does not hold, and
// saves a create or rotate only over the revision it last read, so two replicas
// changing one tenant's keys at once cannot overwrite each other.

// TenantKeyringStore keeps each tenant's sealed keyring with a revision.
// Implementations confine every call to the named tenant.
type TenantKeyringStore interface {
	// LoadTransitKeyring returns the tenant's sealed keyring and its revision;
	// found is false when the tenant has none.
	LoadTransitKeyring(ctx context.Context, tenantID string) (sealed []byte, revision int64, found bool, err error)
	// SaveTransitKeyring stores sealed only if the tenant's revision is still
	// expected (0: no row yet) and returns the new revision; saved is false
	// when another replica saved first.
	SaveTransitKeyring(ctx context.Context, tenantID string, sealed []byte, expected int64) (revision int64, saved bool, err error)
}

// TenantSealer seals and opens one tenant's keyring under that tenant's key
// domain.
type TenantSealer interface {
	SealTenantKeyring(ctx context.Context, tenantID string, plaintext, aad []byte) ([]byte, error)
	OpenTenantKeyring(ctx context.Context, tenantID string, sealed, aad []byte) ([]byte, error)
}

const (
	sharedRingFormat = "trstctl.transit.tenant-keyring.v1"
	// sharedSaveAttempts bounds how often a mutation reloads and reapplies
	// after losing a save to another replica.
	sharedSaveAttempts = 4
)

// persistedTenantRing is one tenant's sealed row.
type persistedTenantRing struct {
	Format   string                  `json:"format"`
	TenantID string                  `json:"tenant_id"`
	Keys     map[string]persistedKey `json:"keys"`
}

func sharedRingAAD(tenantID string) []byte { return []byte(sharedRingFormat + "|" + tenantID) }

// keyMiss is a lookup failure: the ring holds no such key, kind or version. A
// shared keyring resolves it by reloading the tenant's row, since another
// replica may have created the key or version.
type keyMiss struct{ msg string }

func (e keyMiss) Error() string { return e.msg }

func missf(format string, args ...any) error { return keyMiss{msg: fmt.Sprintf(format, args...)} }

func isKeyMiss(err error) bool {
	var miss keyMiss
	return errors.As(err, &miss)
}

// tenantSync serializes one tenant's loads and mutations on this replica and
// remembers the revision the ring holds.
type tenantSync struct {
	mu       sync.Mutex
	loaded   bool
	revision int64
}

type sharedPersistence struct {
	store   TenantKeyringStore
	sealer  TenantSealer
	mu      sync.Mutex
	tenants map[string]*tenantSync
}

func (p *sharedPersistence) sync(tenantID string) *tenantSync {
	p.mu.Lock()
	defer p.mu.Unlock()
	ts := p.tenants[tenantID]
	if ts == nil {
		ts = &tenantSync{}
		p.tenants[tenantID] = ts
	}
	return ts
}

// SetSharedPersistence makes each tenant's keyring a shared, sealed row. It
// replaces the whole-service checkpoint; the two are exclusive.
func (s *Service) SetSharedPersistence(store TenantKeyringStore, sealer TenantSealer) error {
	if store == nil || sealer == nil {
		return errors.New("transit: a shared keyring needs a store and a sealer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shared = &sharedPersistence{store: store, sealer: sealer, tenants: map[string]*tenantSync{}}
	s.persist = nil
	return nil
}

func (s *Service) sharedState() *sharedPersistence {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shared
}

// withRing runs op on the tenant's ring. With a shared keyring the tenant's
// row is loaded first, and an op that names a key or version this replica
// does not hold reloads the row once and runs again.
func (s *Service) withRing(ctx context.Context, tenantID string, op func(*Keyring) error) error {
	p := s.sharedState()
	if p == nil {
		return op(s.ring(tenantID))
	}
	k, err := s.loadShared(ctx, p, tenantID, false)
	if err != nil {
		return err
	}
	if err := op(k); !isKeyMiss(err) {
		return err
	}
	if k, err = s.loadShared(ctx, p, tenantID, true); err != nil {
		return err
	}
	return op(k)
}

// loadShared returns the tenant's ring, loading its row on first use or, with
// refresh, catching up to the stored revision.
func (s *Service) loadShared(ctx context.Context, p *sharedPersistence, tenantID string, refresh bool) (*Keyring, error) {
	k := s.ring(tenantID)
	ts := p.sync(tenantID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.loaded && !refresh {
		return k, nil
	}
	if err := s.refreshLocked(ctx, p, tenantID, ts, k); err != nil {
		return nil, err
	}
	ts.loaded = true
	return k, nil
}

// readShared returns the tenant's ring caught up to the stored revision for a
// metadata read, or nil when the tenant has no keyring anywhere; a read for an
// empty tenant allocates nothing.
func (s *Service) readShared(ctx context.Context, p *sharedPersistence, tenantID string) (*Keyring, error) {
	s.mu.Lock()
	k := s.rings[tenantID]
	s.mu.Unlock()
	if k == nil {
		if _, _, found, err := p.store.LoadTransitKeyring(ctx, tenantID); err != nil || !found {
			return nil, err
		}
	}
	return s.loadShared(ctx, p, tenantID, true)
}

// refreshLocked catches the ring up to the stored row. The caller holds ts.mu.
func (s *Service) refreshLocked(ctx context.Context, p *sharedPersistence, tenantID string, ts *tenantSync, k *Keyring) error {
	sealed, revision, found, err := p.store.LoadTransitKeyring(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("transit: load the shared keyring: %w", err)
	}
	if !found || revision == ts.revision {
		return nil
	}
	plaintext, err := p.sealer.OpenTenantKeyring(ctx, tenantID, sealed, sharedRingAAD(tenantID))
	if err != nil {
		return fmt.Errorf("transit: open the shared keyring: %w", err)
	}
	defer secret.Wipe(plaintext)
	var ring persistedTenantRing
	if err := json.Unmarshal(plaintext, &ring); err != nil {
		wipePersistedRing(ring.Keys)
		return errors.New("transit: the shared keyring did not decode")
	}
	if ring.Format != sharedRingFormat || ring.TenantID != tenantID {
		wipePersistedRing(ring.Keys)
		return errors.New("transit: the shared keyring is not this tenant's")
	}
	if err := k.catchUp(ring.Keys); err != nil {
		return err
	}
	ts.revision = revision
	return nil
}

// saveLocked seals the ring and saves it over the revision it holds. The
// caller holds ts.mu.
func (s *Service) saveLocked(ctx context.Context, p *sharedPersistence, tenantID string, ts *tenantSync, k *Keyring) (bool, error) {
	keys, err := k.export()
	if err != nil {
		return false, fmt.Errorf("transit: export the keyring: %w", err)
	}
	defer wipePersistedRing(keys)
	plaintext, err := json.Marshal(persistedTenantRing{Format: sharedRingFormat, TenantID: tenantID, Keys: keys})
	if err != nil {
		return false, fmt.Errorf("transit: encode the keyring: %w", err)
	}
	defer secret.Wipe(plaintext)
	sealed, err := p.sealer.SealTenantKeyring(ctx, tenantID, plaintext, sharedRingAAD(tenantID))
	if err != nil {
		return false, fmt.Errorf("transit: seal the shared keyring: %w", err)
	}
	revision, saved, err := p.store.SaveTransitKeyring(ctx, tenantID, sealed, ts.revision)
	if err != nil {
		return false, fmt.Errorf("transit: save the shared keyring: %w", err)
	}
	if saved {
		ts.revision = revision
	}
	return saved, nil
}

// mutateShared applies a create or rotate to the tenant's ring caught up to
// the stored revision and saves it; when another replica saved first, the
// change is undone, the ring caught up again and the change reapplied. An
// apply that changes nothing returns a nil undo, and nothing is saved.
func (s *Service) mutateShared(ctx context.Context, p *sharedPersistence, tenantID string, apply func(*Keyring) (undo func(), err error)) error {
	k := s.ring(tenantID)
	ts := p.sync(tenantID)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for attempt := 0; attempt < sharedSaveAttempts; attempt++ {
		if err := s.refreshLocked(ctx, p, tenantID, ts, k); err != nil {
			return err
		}
		ts.loaded = true
		undo, err := apply(k)
		if err != nil {
			return err
		}
		if undo == nil {
			return nil
		}
		saved, err := s.saveLocked(ctx, p, tenantID, ts, k)
		if err != nil {
			undo()
			return err
		}
		if saved {
			return nil
		}
		undo()
	}
	return errors.New("transit: the keyring kept changing on other replicas; retry the request")
}

// catchUp brings the ring up to a keyring another replica saved: keys this
// ring lacks are added and newer versions appended. Rings only grow and every
// save is a compare-and-swap, so a stored key never holds fewer versions than
// this ring or another kind. Adopted buffers move into the ring and every
// other buffer in keys is wiped (AN-8).
func (k *Keyring) catchUp(keys map[string]persistedKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keys == nil {
		k.keys = map[string]*namedKey{}
	}
	for name, p := range keys {
		if err := validPersistedKey(p); err != nil {
			wipePersistedRing(keys)
			return fmt.Errorf("transit: stored key %q: %w", name, err)
		}
		if nk, held := k.keys[name]; held && (nk.kind != p.Kind || p.Latest < nk.latest) {
			wipePersistedRing(keys)
			return fmt.Errorf("transit: stored key %q disagrees with this replica's", name)
		}
	}
	for name, p := range keys {
		nk, held := k.keys[name]
		if !held {
			restored, err := restoreKey(name, p)
			if err != nil {
				return err
			}
			k.keys[name] = restored
			continue
		}
		nk.adoptFacts(p.Facts)
		if p.Latest == nk.latest {
			wipePersistedKey(p)
			continue
		}
		from, to := nk.latest+1, p.Latest+1
		switch nk.kind {
		case KindAEAD:
			nk.aead = append(nk.aead, p.AEAD[from:to]...)
			wipeKeyBytes(p.AEAD[:from])
		case KindHMAC:
			nk.hmac = append(nk.hmac, p.HMAC[from:to]...)
			wipeKeyBytes(p.HMAC[:from])
		case KindSign:
			added := make([]*crypto.LockedSigner, 0, to-from)
			for _, der := range p.SignPKCS8[from:to] {
				ls, err := crypto.LockedKeyFromPKCS8(der)
				if err != nil {
					for _, s := range added {
						s.Destroy()
					}
					wipePersistedKey(p)
					return fmt.Errorf("transit: restore signing key %q: %w", name, err)
				}
				added = append(added, ls)
			}
			nk.sign = append(nk.sign, added...)
			wipeKeyBytes(p.SignPKCS8)
		}
		nk.latest = p.Latest
	}
	return nil
}

// validPersistedKey checks a stored key's version history is dense for its
// kind before anything is adopted from it.
func validPersistedKey(p persistedKey) error {
	if p.Latest < 1 {
		return errors.New("no versions")
	}
	var versions int
	switch p.Kind {
	case KindAEAD:
		versions = len(p.AEAD)
	case KindHMAC:
		versions = len(p.HMAC)
	case KindSign:
		versions = len(p.SignPKCS8)
	default:
		return fmt.Errorf("unknown kind %q", p.Kind)
	}
	if versions != p.Latest+1 {
		return fmt.Errorf("%d stored versions for latest %d", versions-1, p.Latest)
	}
	return validFacts(p.Facts, p.Latest)
}

func wipeKeyBytes(keys [][]byte) {
	for _, b := range keys {
		secret.Wipe(b)
	}
}

// ImportFileKeyring copies each tenant's keyring from a file checkpoint a
// previous version wrote into the shared store, for tenants that have no row
// yet, and returns the tenants it imported (A125). The file is left as it is:
// it remains the operator's copy, and a tenant that already has a row keeps it.
func ImportFileKeyring(ctx context.Context, file *Store, store TenantKeyringStore, sealer TenantSealer) ([]string, error) {
	if file == nil {
		return nil, nil
	}
	if store == nil || sealer == nil {
		return nil, errors.New("transit: importing a keyring file needs a store and a sealer")
	}
	found, err := file.HasState()
	if err != nil || !found {
		return nil, err
	}
	staged := NewService(nil)
	defer staged.Destroy()
	if err := file.Load(staged); err != nil {
		return nil, err
	}
	staged.mu.Lock()
	tenants := make([]string, 0, len(staged.rings))
	for tenantID := range staged.rings {
		tenants = append(tenants, tenantID)
	}
	staged.mu.Unlock()
	sort.Strings(tenants)
	p := &sharedPersistence{store: store, sealer: sealer, tenants: map[string]*tenantSync{}}
	var imported []string
	for _, tenantID := range tenants {
		if _, _, exists, err := store.LoadTransitKeyring(ctx, tenantID); err != nil {
			return imported, fmt.Errorf("transit: import the keyring file: %w", err)
		} else if exists {
			continue
		}
		ts := p.sync(tenantID)
		ts.mu.Lock()
		saved, err := staged.saveLocked(ctx, p, tenantID, ts, staged.ring(tenantID))
		ts.mu.Unlock()
		if err != nil {
			return imported, fmt.Errorf("transit: import the keyring file: %w", err)
		}
		if saved {
			imported = append(imported, tenantID)
		}
	}
	return imported, nil
}
