// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type expiringPreparationCustody struct {
	*eventprotect.FileAuthority
	expire func(context.Context) error
}

func (c expiringPreparationCustody) WithCustodyFence(ctx context.Context, ref eventprotect.KeyRef, visit func(context.Context) error) error {
	return c.FileAuthority.WithCustodyFence(ctx, ref, func(fenced context.Context) error {
		if err := c.expire(fenced); err != nil {
			return err
		}
		return visit(fenced)
	})
}

// The SQL lease changes after the initial claim read and before the independent
// custody callback. No wall-clock acceleration or fake claim authority is used.
func TestPreparationRefusesClaimThatExpiresWhileWaitingForCustody(t *testing.T) {
	s := newStore(t)
	base := t.TempDir()
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: s})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	admission := &eventprivacy.SourceAdmission{Guard: s, Custody: keys}
	reader := &eventprivacy.SourceKeys{Custody: keys}
	policy := &eventprivacy.SourcePolicy{}
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")}, func(log *events.Log) {
		policy.Log = log
		admission.Policy.Log = log
		reader.Policy.Log = log
		admission.Holds = eventprivacy.RetainedHoldPolicy{Policy: *policy}
	}, events.WithEventProtection(events.EventProtection{Admission: admission, Keys: reader}), events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(s)), events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	p := projections.New(s)
	record := func(ctx context.Context, next events.Event) (events.Event, error) {
		var event events.Event
		err := s.WithTenant(ctx, next.TenantID, func(tx pgx.Tx) error {
			var err error
			event, err = log.Append(ctx, next)
			if err != nil {
				return err
			}
			return p.ApplyTx(ctx, tx, event)
		})
		return event, err
	}
	registration, err := record(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("fixture")})
	if err != nil {
		t.Fatal(err)
	}
	requested, err := eventprivacy.NewRequested(tenantA, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(requested)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(requested), Type: eventprivacy.EventRequested, TenantID: tenantA, Data: wire}); err != nil {
		t.Fatal(err)
	}
	life, err := policy.LatestLifetime(t.Context(), tenantA)
	if err != nil || life.Request == nil {
		t.Fatal(err)
	}
	claim := store.EventKeyPreparationClaim{AttemptID: "fdc5ca32-fb7d-4ea3-b640-fcf032cb0ac5", Attempts: 1, Command: eventprivacy.PreparationCommand(*life.Request)}
	if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `UPDATE outbox SET status='processing',worker_id='fixture',attempts=1,lease_until=clock_timestamp()+interval '1 minute',receiver_pending_ids=ARRAY[$3::uuid] WHERE tenant_id=$1 AND idempotency_key=$2 RETURNING id`, tenantA, store.EventKeyPreparationOutboxKey(requested.KeyID), claim.AttemptID).Scan(&claim.ID)
	}); err != nil {
		t.Fatal(err)
	}
	custody := expiringPreparationCustody{FileAuthority: keys, expire: func(ctx context.Context) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenantA, claim.ID)
			return err
		})
	}}
	recorded := false
	receiver := eventprivacy.PreparationReceiver{Policy: *policy, Claims: s, Guard: s, Custody: custody, Record: func(ctx context.Context, next events.Event) (events.Event, error) {
		recorded = true
		return record(ctx, next)
	}}
	if err := receiver.Prepare(t.Context(), claim); err == nil {
		t.Error("expired committed invocation provisioned key custody")
	}
	if _, err := keys.CreationEvidence(t.Context(), claim.Command.Ref); !errors.Is(err, eventprotect.ErrKey) {
		t.Errorf("expired invocation touched independent key creation: %v", err)
	}
	if recorded {
		t.Error("expired invocation published activation")
	}
}
