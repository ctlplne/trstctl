// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateMetadataReceiptBatchesPreserveExactEnvelopeChecks(t *testing.T) {
	s, log, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	in, _ := recordingCertificates(t)
	if _, err := orchestrator.NewOrchestrator(log, s, nil).RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatal(err)
	}
	var original events.Event
	if err := log.Replay(ctx, 2, func(e events.Event) error { original = e; return nil }); err != nil {
		t.Fatal(err)
	}
	if original.Sequence != 2 {
		t.Fatal("expected the actual completed certificate recording")
	}
	duplicate := original
	duplicate.Sequence += 100
	missing := original
	missing.ID, missing.Sequence = "absent-event", original.Sequence+101
	unsequenced := original
	unsequenced.Sequence = 0
	page := []events.Event{original, missing, duplicate, unsequenced, original}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.LockCertificateMetadataOrderTx(ctx, tx, tenantA); err != nil {
			return err
		}
		got, err := s.CertificateMetadataEventsAppliedTx(ctx, tx, tenantA, page)
		if err != nil {
			return err
		}
		for i, want := range []bool{true, false, true, false, true} {
			single, err := s.CertificateMetadataEventAppliedTx(ctx, tx, page[i])
			if err != nil || got[i] != want || single != want {
				t.Fatalf("receipt %d: batch=%t single=%t want=%t err=%v", i, got[i], single, want, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A known ID and an occupied sequence must each bind the whole envelope.
	// These are rejected inputs to a read, never changes to retained history.
	for _, field := range []string{"payload", "id", "actor", "time", "schema", "sequence-collision"} {
		t.Run(field, func(t *testing.T) {
			wrong := original
			switch field {
			case "payload":
				wrong.Data = append(append([]byte(nil), wrong.Data...), ' ')
			case "id":
				wrong.ID += "-different"
			case "actor":
				wrong.Actor = &events.Actor{Subject: "negative-batch-control"}
			case "time":
				wrong.Time = wrong.Time.Add(time.Second)
			case "schema":
				wrong.SchemaVersion++
			case "sequence-collision":
				wrong = missing
				wrong.Sequence = original.Sequence
			}
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				_, err := s.CertificateMetadataEventsAppliedTx(ctx, tx, tenantA, []events.Event{original, wrong})
				return err
			}); !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("batch accepted altered %s: %v", field, err)
			}
		})
	}

	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		got, err := s.CertificateMetadataEventsAppliedTx(ctx, tx, tenantA, []events.Event{original})
		if err == nil && got[0] {
			t.Fatal("another tenant's RLS session read a completed receipt")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"mixed-tenants", "oversized", "invalid-sequence", "empty-id"} {
		t.Run(kind, func(t *testing.T) {
			page := []events.Event{original}
			switch kind {
			case "mixed-tenants":
				foreign := original
				foreign.TenantID = tenantB
				page = append(page, foreign)
			case "oversized":
				page = make([]events.Event, store.CertificateMetadataReceiptBatchLimit+1)
			case "invalid-sequence":
				page[0].Sequence = math.MaxUint64
			case "empty-id":
				page[0].ID = ""
			}
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				measured := &recoveryWorkTx{Tx: tx}
				_, err := s.CertificateMetadataEventsAppliedTx(ctx, measured, tenantA, page)
				if err == nil || measured.calls != 0 {
					t.Fatalf("invalid %s: err=%v SQL calls=%d", kind, err, measured.calls)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
