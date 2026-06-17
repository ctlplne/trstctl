// Package secretshare provides one-time self-destructing secret-sharing links and
// secret-change approvals (S19.3, F60). A link is single-use — a second view
// returns nothing — and expiry-bound; single-use is enforced server-side. Secret
// *changes* go through the S12.3 approval primitive. All actions are audited
// (AN-2); shared material is []byte and never logged (AN-8).
package secretshare

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	secretpkg "trstctl.com/trstctl/internal/crypto/secret"
)

type link struct {
	secret    []byte
	shareID   string // public, non-secret correlation id (safe to audit)
	expiresAt time.Time
	viewed    bool
}

// Sharer issues and redeems one-time secret links.
type Sharer struct {
	tenantID string
	audit    auditsink.Auditor
	clock    func() time.Time
	mu       sync.Mutex
	links    map[string]*link // token SHA-256 hex -> link; the bearer token itself is never retained
}

// New constructs a Sharer.
func New(tenantID string, audit auditsink.Auditor, clock func() time.Time) *Sharer {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	if clock == nil {
		clock = time.Now
	}
	return &Sharer{tenantID: tenantID, audit: audit, clock: clock, links: map[string]*link{}}
}

// Create stores a secret behind a single-use token that expires after ttl. The
// returned token is the bearer capability that redeems the secret: it travels
// out-of-band to the recipient and is NEVER written to the audit/event log
// (AN-8) — a random non-secret shareID plus a non-reversible SHA-256 of the
// token are audited instead, so the trail is preserved without leaking the
// credential.
func (s *Sharer) Create(ctx context.Context, secret []byte, ttl time.Duration) ([]byte, error) {
	tb, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	token := make([]byte, hex.EncodedLen(len(tb)))
	hex.Encode(token, tb)
	secretpkg.Wipe(tb)
	tokenHash := crypto.SHA256Hex(token)
	idb, err := crypto.RandomBytes(16)
	if err != nil {
		secretpkg.Wipe(token)
		return nil, err
	}
	shareID := hex.EncodeToString(idb)
	secretpkg.Wipe(idb)
	s.mu.Lock()
	s.links[tokenHash] = &link{secret: append([]byte(nil), secret...), shareID: shareID, expiresAt: s.clock().Add(ttl)}
	s.mu.Unlock()
	_ = auditsink.Emit(ctx, s.audit, nil, "secret.shared", s.tenantID,
		[]byte(fmt.Sprintf(`{"share_id":%q,"token_sha256":%q}`, shareID, tokenHash)))
	return token, nil
}

// View returns the shared secret exactly once. A second view, or a view after
// expiry, returns an error and the link is destroyed.
func (s *Sharer) View(ctx context.Context, token []byte) ([]byte, error) {
	tokenHash := crypto.SHA256Hex(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[tokenHash]
	if !ok {
		return nil, fmt.Errorf("secretshare: link not found or already consumed")
	}
	if l.viewed || s.clock().After(l.expiresAt) {
		// Self-destruct on expiry/re-view: zeroize the stored bytes before handing the
		// backing array to the GC (AN-8). A link that expires unviewed must not leave
		// its secret lingering in freed heap.
		secretpkg.Wipe(l.secret)
		l.secret = nil
		delete(s.links, tokenHash)
		return nil, fmt.Errorf("secretshare: link expired or already viewed")
	}
	l.viewed = true
	// Move the secret out of the link and return it to the caller. The caller now
	// owns the only copy; the link's reference is cleared and the entry deleted, so
	// nothing in this package retains the bytes (AN-8).
	out := l.secret
	l.secret = nil
	shareID := l.shareID
	delete(s.links, tokenHash) // self-destruct on first successful view
	// Audit the non-secret shareID and a non-reversible hash of the token — never
	// the token itself, which is the bearer capability (AN-8).
	_ = auditsink.Emit(ctx, s.audit, nil, "secret.share.viewed", s.tenantID,
		[]byte(fmt.Sprintf(`{"share_id":%q,"token_sha256":%q}`, shareID, tokenHash)))
	return out, nil
}

// Destroy zeroizes and removes every still-pending shared secret. It is for clean
// shutdown / eviction: any link that was created but never viewed has its secret
// bytes wiped before the backing arrays reach the GC (AN-8), closing the window in
// which an un-redeemed secret lingers in freed heap.
func (s *Sharer) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, l := range s.links {
		secretpkg.Wipe(l.secret)
		l.secret = nil
		delete(s.links, token)
	}
}

// changeIssuer adapts an apply func to approval.Issuer.
type changeIssuer struct {
	apply func(ctx context.Context, reqID, resource string) (string, error)
}

func (c changeIssuer) Issue(ctx context.Context, _ /*tenantID*/, reqID, resource string) (string, error) {
	return c.apply(ctx, reqID, resource)
}

// NewChangeApprovals returns an approval.Manager (S12.3) configured so an approved
// secret change is applied via apply — GitOps-style approval over secret
// mutations, reusing the Phase-2 approval primitive on the secrets surface.
func NewChangeApprovals(tenantID string, apply func(ctx context.Context, reqID, resource string) (string, error), audit auditsink.Auditor) (*approval.Manager, error) {
	return approval.New(approval.Config{
		TenantID: tenantID,
		Store:    approval.NewMemoryStore(),
		Issuer:   changeIssuer{apply: apply},
		Audit:    audit,
	})
}
