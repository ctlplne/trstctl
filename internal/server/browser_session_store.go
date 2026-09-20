// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// postgresBrowserSessionStore adapts the tenant-scoped PostgreSQL repository to
// the authentication package without making auth depend on the datastore layer.
// Only one-way digests cross into browser_sessions; display claims remain solely
// in the signed HttpOnly cookie.
type postgresBrowserSessionStore struct {
	store *store.Store
}

func newBrowserSessionIssuer(secret []byte, ttl time.Duration, st *store.Store) *auth.SessionIssuer {
	if st == nil {
		// Unit-only builders may intentionally omit the assembled datastore. The
		// real control-plane composition always supplies it through buildBrowserAuth.
		return auth.NewSessionIssuer(secret, ttl)
	}
	return auth.NewSessionIssuerWithStore(secret, ttl, ttl, postgresBrowserSessionStore{store: st})
}

func (s postgresBrowserSessionStore) Create(ctx context.Context, rec auth.SessionRecord) error {
	return s.store.CreateBrowserSession(ctx, store.BrowserSession{
		TenantID:    rec.TenantID,
		SessionHash: rec.ID,
		SubjectHash: browserSessionSubjectHash(rec.TenantID, rec.Subject),
		ExpiresAt:   time.Unix(rec.ExpiresAt, 0),
		CreatedAt:   rec.CreatedAt,
		LastSeenAt:  rec.LastSeenAt,
		RevokedAt:   rec.RevokedAt,
	})
}

func (s postgresBrowserSessionStore) Get(ctx context.Context, tenantID, id string) (auth.SessionRecord, error) {
	rec, err := s.store.GetBrowserSession(ctx, tenantID, id)
	if err != nil {
		if store.IsNotFound(err) {
			return auth.SessionRecord{}, auth.ErrSessionNotFound
		}
		return auth.SessionRecord{}, err
	}
	return auth.SessionRecord{
		Session: auth.Session{
			ID: rec.SessionHash, TenantID: rec.TenantID, ExpiresAt: rec.ExpiresAt.Unix(),
		},
		CreatedAt: rec.CreatedAt, LastSeenAt: rec.LastSeenAt, RevokedAt: rec.RevokedAt,
	}, nil
}

func (s postgresBrowserSessionStore) Revoke(ctx context.Context, tenantID, id string, revokedAt time.Time) error {
	err := s.store.RevokeBrowserSession(ctx, tenantID, id, revokedAt)
	if store.IsNotFound(err) {
		return auth.ErrSessionNotFound
	}
	return err
}

func (s postgresBrowserSessionStore) RevokeSubject(ctx context.Context, tenantID, subject string, revokedAt time.Time) error {
	return s.store.RevokeBrowserSessionsBySubject(ctx, tenantID, browserSessionSubjectHash(tenantID, subject), revokedAt)
}

func (s postgresBrowserSessionStore) Touch(ctx context.Context, tenantID, id string, seenAt time.Time) error {
	err := s.store.TouchBrowserSession(ctx, tenantID, id, seenAt)
	if store.IsNotFound(err) {
		return auth.ErrSessionNotFound
	}
	return err
}

func browserSessionSubjectHash(tenantID, subject string) string {
	return crypto.SHA256Hex([]byte(tenantID + "\x00" + subject))
}
