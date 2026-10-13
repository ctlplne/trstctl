// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A retrying claim must wait for the pending command before taking the token
// row. Recovery owns that command first and then updates the token. Reversing
// these two locks is a second ABBA deadlock even when tail replay is ordered.
func TestAPITokenRevocationClaimWaitsBeforeLockingToken(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "claim-order"}); err != nil {
		t.Fatal(err)
	}
	rec, err := s.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantA, TokenHash: strings.Repeat("b", 64), Subject: "claim-order",
		Scopes: []string{"access:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.APITokenRevoked{ID: rec.ID, Reason: "claim order"})
	if err != nil {
		t.Fatal(err)
	}
	first := store.APITokenRevocationCommand{TenantID: tenantA, TokenID: rec.ID,
		Event: events.Event{ID: uuid.NewString(), TenantID: tenantA,
			Type: projections.EventAPITokenRevoked, SchemaVersion: events.DefaultSchemaVersion,
			Time: time.Now().UTC().Truncate(time.Microsecond), Data: payload}}
	_, created, err := s.ClaimAPITokenRevocationCommand(ctx, first)
	if err != nil || !created {
		t.Fatalf("first claim: created=%v err=%v", created, err)
	}
	second := first
	second.Event.ID = uuid.NewString()
	second.Event.Time = second.Event.Time.Add(time.Microsecond)
	var probeErr error
	var claimDone chan error
	err = s.WithTenant(ctx, tenantA, func(holder pgx.Tx) error {
		if _, err := s.LockAPITokenRevocationCommandTx(ctx, holder, tenantA, rec.ID); err != nil {
			return err
		}
		claimDone = make(chan error, 1)
		go func() {
			_, _, err := s.ClaimAPITokenRevocationCommand(ctx, second)
			claimDone <- err
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var waiting bool
			if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity WHERE wait_event_type = 'Lock'
				  AND query LIKE '%api_token_revocation_commands%'
				  AND query NOT LIKE '%pg_stat_activity%')`).Scan(&waiting); err != nil {
				return err
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("competing claim did not wait on the command row")
			}
			time.Sleep(10 * time.Millisecond)
		}
		probeErr = s.WithTenant(ctx, tenantA, func(probe pgx.Tx) error {
			var id string
			return probe.QueryRow(ctx,
				`SELECT id::text FROM api_tokens WHERE tenant_id = $1 AND id = $2 FOR UPDATE NOWAIT`,
				tenantA, rec.ID).Scan(&id)
		})
		if probeErr != nil {
			return nil // release the holder; the assertion below reports the original inversion.
		}
		return s.ApplyAPITokenRevokedTx(ctx, holder, tenantA, rec.ID, "recovery", "first command", first.Event.Time)
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimDone != nil {
		if err := <-claimDone; !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("competing claim after recovery = %v, want conflict", err)
		}
	}
	if probeErr != nil {
		t.Fatalf("competing claim locked token before command: %v", probeErr)
	}
}
