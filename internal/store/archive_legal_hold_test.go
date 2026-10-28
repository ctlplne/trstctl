// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A208: an archive legal hold projects pending with a queued "set" effect,
// reads applied only from a recorded read-back, and a release queues a
// "clear" effect before it reads released. A second active hold on one object,
// a release of a hold that is not active, and replays change nothing; another
// tenant sees none of it.
func TestArchiveLegalHoldsProjectWithTheirBucketEffects(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	const holdA, holdB = "a2080000-0000-4000-8000-0000000007a1", "a2080000-0000-4000-8000-0000000007a2"
	object := "tenant/" + tenantA + "/audit/a208-segment-1.jws"
	at := time.Date(2026, 10, 28, 6, 0, 0, 0, time.UTC)
	apply := func(fn func(tx pgx.Tx) error) error { return s.WithTenant(ctx, tenantA, fn) }
	place := func(id string, sequence uint64) error {
		return apply(func(tx pgx.Tx) error {
			return s.PlaceArchiveLegalHoldTx(ctx, tx, store.ArchiveLegalHold{TenantID: tenantA, ID: id, Object: object,
				Reason: "litigation hold 2026-208", PlacedBy: "auditor@example.test", PlacedAt: at, EventSequence: sequence})
		})
	}
	effects := func() []store.ArchiveLegalHoldEffect {
		t.Helper()
		var out []store.ArchiveLegalHoldEffect
		if err := apply(func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2
				AND idempotency_key LIKE 'archive-legal-hold:a2080000-%' ORDER BY id`, tenantA, store.ArchiveLegalHoldDestination)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var raw []byte
				var effect store.ArchiveLegalHoldEffect
				if err := rows.Scan(&raw); err != nil {
					return err
				}
				if err := json.Unmarshal(raw, &effect); err != nil {
					return err
				}
				out = append(out, effect)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	status := func(id string) store.ArchiveLegalHold {
		t.Helper()
		h, err := s.GetArchiveLegalHold(ctx, tenantA, id)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	for i := 0; i < 2; i++ { // the second is a replay
		if err := place(holdA, 208101); err != nil {
			t.Fatal(err)
		}
	}
	if h := status(holdA); h.Status != "pending" || h.PlacedBy != "auditor@example.test" || !h.Active() {
		t.Fatalf("placed hold reads %+v", h)
	}
	if got := effects(); len(got) != 1 || !got[0].On || got[0].Object != object {
		t.Fatalf("effects after placing = %+v", got)
	}
	// A second hold on the same object while one is active records nothing.
	if err := place(holdB, 208102); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetArchiveLegalHold(ctx, tenantA, holdB); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("a second active hold was recorded: %v", err)
	}
	if active, found, err := s.ActiveArchiveLegalHoldFor(ctx, tenantA, object); err != nil || !found || active.ID != holdA {
		t.Fatalf("active hold = %+v %v %v", active, found, err)
	}

	record := func(id, outcome, detail string, sequence uint64) error {
		return apply(func(tx pgx.Tx) error {
			return s.RecordArchiveLegalHoldOutcomeTx(ctx, tx, tenantA, id, outcome, detail, at.Add(time.Minute), sequence)
		})
	}
	// A "released" before a release was asked for changes nothing.
	if err := record(holdA, "released", "", 208103); err != nil {
		t.Fatal(err)
	}
	if h := status(holdA); h.Status != "pending" {
		t.Fatalf("an early release outcome moved the hold to %s", h.Status)
	}
	if err := record(holdA, "applied", "", 208104); err != nil {
		t.Fatal(err)
	}
	if h := status(holdA); h.Status != "applied" || h.AppliedAt == nil {
		t.Fatalf("applied hold reads %+v", h)
	}
	for i := 0; i < 2; i++ {
		if err := apply(func(tx pgx.Tx) error {
			return s.RequestArchiveLegalHoldReleaseTx(ctx, tx, tenantA, holdA, at.Add(2*time.Minute), 208105)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := effects(); len(got) != 2 || got[1].On {
		t.Fatalf("effects after the release = %+v", got)
	}
	if err := record(holdA, "released", "", 208106); err != nil {
		t.Fatal(err)
	}
	if h := status(holdA); h.Status != "released" || h.ReleasedAt == nil || h.Active() {
		t.Fatalf("released hold reads %+v", h)
	}
	// A released hold cannot be released again; a new hold may be placed.
	if err := apply(func(tx pgx.Tx) error {
		return s.RequestArchiveLegalHoldReleaseTx(ctx, tx, tenantA, holdA, at.Add(3*time.Minute), 208107)
	}); err != nil {
		t.Fatal(err)
	}
	if h := status(holdA); h.Status != "released" {
		t.Fatalf("a second release moved the hold to %s", h.Status)
	}
	if err := place(holdB, 208108); err != nil {
		t.Fatal(err)
	}
	if err := record(holdB, "failed", "the bucket does not have S3 Object Lock enabled", 208109); err != nil {
		t.Fatal(err)
	}
	if h := status(holdB); h.Status != "failed" || h.StatusDetail == "" {
		t.Fatalf("failed hold reads %+v", h)
	}

	if holds, err := s.ListArchiveLegalHolds(ctx, tenantB, 100); err != nil || len(holds) != 0 {
		t.Fatalf("tenant B lists %+v %v", holds, err)
	}
	if _, err := s.GetArchiveLegalHold(ctx, tenantB, holdA); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant B reads tenant A's hold: %v", err)
	}
}
