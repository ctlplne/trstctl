package ctmonitor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"certctl.io/certctl/internal/crypto/ctlog"
	"certctl.io/certctl/internal/notify"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/store"
)

// StoreKnownGood treats a logged certificate as expected when the tenant's
// inventory already contains it (by fingerprint, or by issuer and serial for a
// precertificate).
type StoreKnownGood struct {
	store *store.Store
}

// NewStoreKnownGood builds a KnownGood backed by the certificate inventory.
func NewStoreKnownGood(s *store.Store) *StoreKnownGood { return &StoreKnownGood{store: s} }

// IsKnown reports whether the certificate is already inventoried.
func (k *StoreKnownGood) IsKnown(ctx context.Context, tenantID string, e ctlog.Entry) (bool, error) {
	return k.store.CertificateExists(ctx, tenantID, e.FingerprintSHA256, e.Issuer, e.SerialHex)
}

// StoreAlerter raises CT findings onto the shared notification surface through
// the outbox (AN-6): the alert is enqueued on notify.DestinationCTLog — the same
// surface and Alert payload as expiration alerts — in its own transaction. The
// idempotency key (log URL + entry index) lets at-least-once delivery collapse
// to a single effect downstream (AN-5).
type StoreAlerter struct {
	store  *store.Store
	outbox *orchestrator.Outbox
}

// NewStoreAlerter builds an Alerter over the store and outbox.
func NewStoreAlerter(s *store.Store, ob *orchestrator.Outbox) *StoreAlerter {
	return &StoreAlerter{store: s, outbox: ob}
}

// Raise enqueues an unexpected-issuance alert.
func (a *StoreAlerter) Raise(ctx context.Context, tenantID string, f Finding) error {
	payload, err := json.Marshal(notify.Alert{
		Kind:     notify.KindUnexpectedIssuance,
		TenantID: tenantID,
		Subject:  f.Subject,
		Serial:   f.Serial,
		NotAfter: f.NotAfter,
		Detail: fmt.Sprintf("unexpected certificate for watched domain %q in CT log %s (index %d, issuer %q)",
			f.MatchedDomain, f.LogURL, f.Index, f.Issuer),
	})
	if err != nil {
		return err
	}
	idem := fmt.Sprintf("ct:%s:%d", f.LogURL, f.Index)
	return a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := a.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    notify.DestinationCTLog,
			IdempotencyKey: idem,
			Payload:        payload,
		})
		return err
	})
}

// StorePersistence adapts the certificate store to the Scheduler's Persistence
// seam: watched domains and CT-log checkpoints live in PostgreSQL (AN-1
// tenant-scoped), so monitoring resumes across restarts.
type StorePersistence struct {
	store *store.Store
}

// NewStorePersistence builds a Persistence backed by the store.
func NewStorePersistence(s *store.Store) *StorePersistence { return &StorePersistence{store: s} }

// WatchedDomains returns the tenant's watched domains.
func (p *StorePersistence) WatchedDomains(ctx context.Context, tenantID string) ([]string, error) {
	return p.store.ListWatchedDomains(ctx, tenantID)
}

// Checkpoints returns the tenant's tracked logs as LogStates.
func (p *StorePersistence) Checkpoints(ctx context.Context, tenantID string) ([]LogState, error) {
	cps, err := p.store.ListCTLogCheckpoints(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]LogState, len(cps))
	for i, c := range cps {
		out[i] = LogState{URL: c.LogURL, Checkpoint: c.NextIndex}
	}
	return out, nil
}

// SaveCheckpoint persists a log's advanced checkpoint.
func (p *StorePersistence) SaveCheckpoint(ctx context.Context, tenantID, logURL string, next int64) error {
	return p.store.SaveCTLogCheckpoint(ctx, tenantID, logURL, next)
}
