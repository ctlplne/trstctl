// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
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

// A recovery worker locks the durable command before touching the token row.
// Catch-up replay must use that same order. Otherwise each owns the row the
// other needs and PostgreSQL aborts an ordinary revocation as a deadlock.
func TestAPITokenRevocationReplayLocksCommandBeforeToken(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "lock-order"}); err != nil {
		t.Fatal(err)
	}
	rec, err := s.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantA, TokenHash: strings.Repeat("a", 64), Subject: "lock-order",
		Scopes: []string{"access:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.APITokenRevoked{ID: rec.ID, Reason: "lock order"})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: uuid.NewString(), TenantID: tenantA,
		Type: projections.EventAPITokenRevoked, SchemaVersion: events.DefaultSchemaVersion,
		Time: time.Now().UTC().Truncate(time.Microsecond), Data: payload, Sequence: 1}
	_, created, err := s.ClaimAPITokenRevocationCommand(ctx, store.APITokenRevocationCommand{
		TenantID: tenantA, TokenID: rec.ID, Event: event,
	})
	if err != nil || !created {
		t.Fatalf("claim command: created=%v err=%v", created, err)
	}
	projector := projections.New(s)
	var probeErr error
	var replayErr error
	var replayDone chan error
	err = s.WithTenant(ctx, tenantA, func(holder pgx.Tx) error {
		if _, err := s.LockAPITokenRevocationCommandTx(ctx, holder, tenantA, rec.ID); err != nil {
			return err
		}
		replayDone = make(chan error, 1)
		go func() {
			replayDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `SET LOCAL application_name = 'api_token_revoke_replay_order_peer'`); err != nil {
					return err
				}
				return projector.ApplyTx(ctx, tx, event)
			})
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var waiting bool
			if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE application_name = 'api_token_revoke_replay_order_peer'
				  AND wait_event_type = 'Lock'
				  AND query LIKE '%api_token_revocation_commands%')`).Scan(&waiting); err != nil {
				return err
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("replay did not wait on the durable command row")
			}
			time.Sleep(10 * time.Millisecond)
		}
		probeErr = s.WithTenant(ctx, tenantA, func(probe pgx.Tx) error {
			var id string
			return probe.QueryRow(ctx,
				`SELECT id::text FROM api_tokens WHERE tenant_id = $1 AND id = $2 FOR UPDATE NOWAIT`,
				tenantA, rec.ID).Scan(&id)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if replayDone != nil {
		replayErr = <-replayDone
	}
	if probeErr != nil {
		t.Fatalf("replay took token row before command row: %v", probeErr)
	}
	if replayErr != nil {
		t.Fatalf("replay after command release: %v", replayErr)
	}
}
