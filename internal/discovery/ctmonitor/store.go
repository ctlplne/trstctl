// SPDX-License-Identifier: MPL-2.0

package ctmonitor

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
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
	store          *store.Store
	boundedDomains []string
	boundedLogs    map[string]struct{}
	projectResults bool
}

// NewStorePersistence builds a Persistence backed by the store.
func NewStorePersistence(s *store.Store) *StorePersistence {
	return &StorePersistence{store: s, projectResults: true}
}

// NewStorePersistenceForWatchlist bounds one discovery-source run to that
// source's current domains and logs. The store still enforces the tenant's
// event-projected active set, while a second CT source cannot be polled or have
// findings attributed to this run by accident.
func NewStorePersistenceForWatchlist(s *store.Store, domains, logs []string) *StorePersistence {
	allowed := make(map[string]struct{}, len(logs))
	for _, logURL := range logs {
		allowed[logURL] = struct{}{}
	}
	return &StorePersistence{
		store:          s,
		boundedDomains: append([]string(nil), domains...),
		boundedLogs:    allowed,
		projectResults: false,
	}
}

// WatchedDomains returns the tenant's watched domains.
func (p *StorePersistence) WatchedDomains(ctx context.Context, tenantID string) ([]string, error) {
	if p.boundedDomains != nil {
		return append([]string(nil), p.boundedDomains...), nil
	}
	return p.store.ListWatchedDomains(ctx, tenantID)
}

// Checkpoints returns the tenant's tracked logs as LogStates.
func (p *StorePersistence) Checkpoints(ctx context.Context, tenantID string) ([]LogState, error) {
	cps, err := p.store.ListCTLogCheckpoints(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]LogState, len(cps))
	out = out[:0]
	for _, c := range cps {
		if p.boundedLogs != nil {
			if _, ok := p.boundedLogs[c.LogURL]; !ok {
				continue
			}
		}
		out = append(out, LogState{URL: c.LogURL, Checkpoint: c.NextIndex})
	}
	return out, nil
}

// SavePollResult persists one active log's progress or failure detail.
func (p *StorePersistence) SavePollResult(ctx context.Context, tenantID string, result LogPollResult) error {
	// A served discovery run carries these facts in discovery.run.completed;
	// its projector owns the durable checkpoint/health write (AN-2). The
	// unbounded constructor preserves the small library compatibility seam.
	if !p.projectResults {
		return nil
	}
	status := store.CTPollSucceeded
	if result.Status == LogPollFailed {
		status = store.CTPollFailed
	}
	return p.store.SaveCTLogPollResult(ctx, tenantID, result.URL, result.Checkpoint, status, result.Error)
}
