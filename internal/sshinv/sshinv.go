// Package sshinv holds the shared inventory shape for discovered SSH keys, used
// by both the network host-key scanner (internal/discovery/sshscan) and the
// agent's on-host SSH inventory (internal/agent/sshdiscovery). A Found is
// reconciled into the inventory through a Sink — an idempotent upsert by
// fingerprint, so the same key discovered in several places is one row.
//
// Key metadata is produced by the crypto boundary (internal/crypto/sshkeys,
// sshprobe); this package carries only the crypto-free Found and imports no
// crypto.
package sshinv

import (
	"context"
	"sync"

	"trstctl.com/trstctl/internal/store"
)

// Discovery source kinds.
const (
	SourceHostProbe      = "ssh-host-probe"      // a network SSH handshake (F2)
	SourceHostKey        = "ssh-host-key"        // an /etc/ssh host key file
	SourceUserKey        = "ssh-user-key"        // a user's ~/.ssh public key
	SourceAuthorizedKeys = "ssh-authorized-keys" // an authorized_keys grant
	SourceKnownHosts     = "ssh-known-hosts"     // a known_hosts trusted host key
	SourceTrustedCA      = "ssh-trusted-ca"      // an sshd TrustedUserCAKeys CA
)

// Found is a discovered SSH key.
type Found struct {
	Source         string // discovery source kind
	Location       string // host:port or file path it was found at
	KeyType        string // ssh-ed25519, ssh-rsa, ...
	Fingerprint    string // OpenSSH SHA256 fingerprint
	Comment        string
	StandingAccess bool // grants persistent login (an authorized_keys entry)
	Orphaned       bool // an unattributable standing-access grant
}

// Sink reconciles a discovered SSH key into the inventory.
type Sink interface {
	Record(ctx context.Context, f Found) error
}

// MemorySink records discoveries in memory for tests.
type MemorySink struct {
	mu    sync.Mutex
	found []Found
}

var _ Sink = (*MemorySink)(nil)

// NewMemorySink returns an empty in-memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Record stores the discovery.
func (m *MemorySink) Record(_ context.Context, f Found) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.found = append(m.found, f)
	return nil
}

// All returns the discoveries recorded so far.
func (m *MemorySink) All() []Found {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Found, len(m.found))
	copy(out, m.found)
	return out
}

// StoreSink reconciles discovered SSH keys into the inventory (the ssh_keys
// table) via an idempotent upsert keyed by (tenant, fingerprint).
type StoreSink struct {
	store    *store.Store
	tenantID string
}

var _ Sink = (*StoreSink)(nil)

// NewStoreSink records discoveries for a tenant.
func NewStoreSink(s *store.Store, tenantID string) *StoreSink {
	return &StoreSink{store: s, tenantID: tenantID}
}

// Record upserts the discovered SSH key's metadata into the inventory.
func (ss *StoreSink) Record(ctx context.Context, f Found) error {
	_, err := ss.store.UpsertSSHKey(ctx, store.SSHKey{
		TenantID:       ss.tenantID,
		Fingerprint:    f.Fingerprint,
		KeyType:        f.KeyType,
		Comment:        f.Comment,
		Source:         f.Source,
		Location:       f.Location,
		StandingAccess: f.StandingAccess,
		Orphaned:       f.Orphaned,
	})
	return err
}
