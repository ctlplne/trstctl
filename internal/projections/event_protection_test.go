// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestEventProtectionRequestReplaysOneTransactionalPreparationIntent(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	ctx := t.Context()
	registration, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("fixture")})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewRequested(tenantA, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := log.Append(ctx, events.Event{ID: eventprivacy.RequestedEventID(request), Type: projections.EventTenantEventProtectionRequested, TenantID: tenantA, Data: wire})
	if err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("force projection rollback")
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := p.ApplyTx(ctx, tx, requested); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	count := func() int {
		t.Helper()
		var n int
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2`, tenantA, store.EventKeyPreparationDestination).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() != 0 {
		t.Fatal("rolled-back request projection leaked key preparation")
	}
	for i := 0; i < 2; i++ {
		if err := p.Project(ctx, log); err != nil {
			t.Fatal(err)
		}
	}
	if count() != 1 {
		t.Fatal("retained source replay did not derive one exact preparation intent")
	}
	changed := request
	changed.RetentionNanos++
	requested.Data, err = json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, requested); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("projection replaced retained first policy: %v", err)
	}
}
