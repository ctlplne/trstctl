// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateMetadataCompletedZeroRowRepeatIsInertAcrossSnapshotAndRebuild(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	in, _ := recordingCertificates(t)
	in.Source, in.IssuanceIdempotencyKey = "import", ""
	in.CertificateDER, in.CertificatePEM = nil, nil
	// The shipped command really executes before this fingerprint exists. Its
	// zero-row effect must not be reinterpreted after a newer import creates it.
	if err := o.SupersedeCertificate(ctx, tenantA, in.Fingerprint, in.Serial, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var completed events.Event
	if err := log.Replay(ctx, 2, func(e events.Event) error { completed = e; return nil }); err != nil {
		t.Fatal(err)
	}
	if completed.Sequence != 2 {
		t.Fatal("missing real zero-row command")
	}
	certificate, err := o.RecordCertificate(ctx, tenantA, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	read := func() []byte {
		c, err := s.GetCertificate(ctx, tenantA, certificate.ID)
		if err != nil || c.Status != "active" {
			t.Fatalf("completed zero-row replay changed later import: status=%s err=%v", c.Status, err)
		}
		return certificateOrderState(t, ctx, s, in.Fingerprint)
	}
	before := read()
	for range 2 {
		if err := projector.Apply(ctx, completed); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, read()) {
			t.Fatal("exact completed repeat changed state")
		}
	}
	// Negative envelopes never enter the log: these exercise rejection at the
	// projector boundary, not rewritten source history or invented evidence.
	for _, field := range []string{"payload", "id", "sequence", "actor", "time", "schema"} {
		t.Run(field, func(t *testing.T) {
			wrong := completed
			switch field {
			case "payload":
				wrong.Data = append(append([]byte(nil), wrong.Data...), ' ')
			case "id":
				wrong.ID += "-different"
			case "sequence":
				wrong.Sequence++
			case "actor":
				wrong.Actor = &events.Actor{Subject: "negative-control"}
			case "time":
				wrong.Time = wrong.Time.Add(time.Second)
			case "schema":
				wrong.SchemaVersion++
			}
			wantErr := store.ErrIdempotencyConflict
			if field == "schema" {
				// Unknown versions are refused before any receipt lookup/decoding.
				wantErr = projections.ErrUnknownSchemaVersion
			}
			if err := projector.Apply(ctx, wrong); !errors.Is(err, wantErr) {
				t.Fatalf("changed envelope accepted: %v", err)
			}
			if !bytes.Equal(before, read()) {
				t.Fatal("rejected envelope changed state")
			}
		})
	}
	if _, err := projector.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	// Cold-start fixture fault uses the owner pool; the app role correctly
	// cannot reset the global checkpoint. No live deployment is touched.
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := s.ResetProjectionCheckpointTx(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if restored, err := projector.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("cold receipt restore: %t %v", restored, err)
	}
	if err := projector.Apply(ctx, completed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, read()) {
		t.Fatal("snapshot lost exact zero-row completion")
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, completed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, read()) {
		t.Fatal("ordered rebuild differs from original completed history")
	}
}

func TestCertificateMetadataExactRetainedDuplicateAcrossDedupeExpiry(t *testing.T) {
	s := newStore(t)
	log := openLogWithOptions(t, events.WithDuplicateWindowForTesting(100*time.Millisecond))
	projector := projections.New(s)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	tenant, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegisteredJSON("metadata-duplicate")})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	o := orchestrator.NewOrchestrator(log, s, nil)
	in, _ := recordingCertificates(t)
	in.Source, in.IssuanceIdempotencyKey = "import", ""
	in.CertificateDER, in.CertificatePEM = nil, nil
	if err := o.SupersedeCertificate(ctx, tenantA, in.Fingerprint, in.Serial, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var original events.Event
	if err := log.Replay(ctx, 2, func(e events.Event) error { original = e; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	duplicate, err := log.Append(ctx, original)
	if err != nil || duplicate.Sequence <= original.Sequence {
		t.Fatalf("retained duplicate not exercised: %d %v", duplicate.Sequence, err)
	}
	if canonical, found, err := log.EventByID(ctx, original.ID); err != nil || !found || canonical.Sequence != original.Sequence {
		t.Fatalf("log rejected its identical duplicate: %v", err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCertificateByFingerprint(ctx, tenantA, in.Fingerprint)
	if err != nil || c.Status != "active" {
		t.Fatalf("duplicate zero-row command changed later import: %s %v", c.Status, err)
	}
}

func TestCertificateMetadataMissingOldEventRefusesBeforeEffectsAndCheckpoint(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	in, _ := recordingCertificates(t)
	in.Source, in.IssuanceIdempotencyKey = "import", ""
	in.CertificateDER, in.CertificatePEM = nil, nil
	if _, err := o.RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := s.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A retained append can race after a recording sampled its recovery cut.
	// Replay actual retained recording bytes to reproduce that ordering at the
	// projector, independently of the pre-append command check.
	var original events.Event
	if err := log.Replay(ctx, 2, func(e events.Event) error { original = e; return nil }); err != nil {
		t.Fatal(err)
	}
	older := original
	older.ID = ""
	older.Time = time.Time{}
	older.Sequence = 0
	older, err = log.Append(ctx, older)
	if err != nil {
		t.Fatal(err)
	}
	newer := original
	newer.ID = ""
	newer.Time = time.Time{}
	newer.Sequence = 0
	newer, err = log.Append(ctx, newer)
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, newer); err != nil {
		t.Fatal(err)
	}
	before := certificateOrderState(t, ctx, s, in.Fingerprint)
	if err := projector.ProjectCatchUp(ctx, log); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("unapplied older event accepted: %v", err)
	}
	if !bytes.Equal(before, certificateOrderState(t, ctx, s, in.Fingerprint)) {
		t.Fatal("refusal changed certificate")
	}
	if after, err := s.ProjectionCheckpoint(ctx); err != nil || after != checkpoint {
		t.Fatalf("refusal advanced checkpoint: %d %v", after, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		done, err := s.CertificateMetadataEventAppliedTx(ctx, tx, older)
		if done {
			t.Error("refusal invented completion")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, certificateOrderState(t, ctx, s, in.Fingerprint)) {
		t.Fatal("ordered rebuild changed equivalent public material")
	}
}

func TestCertificateMetadataStatementGuardRejectsUnappliedZeroRowWrite(t *testing.T) {
	s, log, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	in, _ := recordingCertificates(t)
	if _, err := orchestrator.NewOrchestrator(log, s, nil).RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatal(err)
	}
	before := certificateOrderState(t, ctx, s, in.Fingerprint)
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.WithCertificateProjectionOrderTx(ctx, tx, tenantA, 1, func() error {
			_, err := tx.Exec(ctx, `UPDATE certificates SET status='superseded' WHERE tenant_id=$1 AND fingerprint='owned-no-matching-row'`, tenantA)
			return err
		})
	})
	if !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("statement guard accepted missing old zero-row effect: %v", err)
	}
	if !bytes.Equal(before, certificateOrderState(t, ctx, s, in.Fingerprint)) {
		t.Fatal("rejected statement changed current state")
	}
}

func TestCertificateMetadataLegacyHeadCannotInventExactReceipt(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	in, _ := recordingCertificates(t)
	if _, err := orchestrator.NewOrchestrator(log, s, nil).RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatal(err)
	}
	var original events.Event
	if err := log.Replay(ctx, 2, func(e events.Event) error { original = e; return nil }); err != nil {
		t.Fatal(err)
	}
	// Isolated loss/legacy-provenance fixture: retain the real head and material
	// but remove its exact completion proof, as an upgrade from207 would lack.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM certificate_metadata_receipts WHERE tenant_id=$1`, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, alteration := range []string{"actor", "payload-bytes", "none"} {
		candidate := original
		if alteration == "payload-bytes" {
			candidate.Data = append(append([]byte(nil), candidate.Data...), ' ')
		}
		if alteration == "actor" {
			candidate.Actor = &events.Actor{Subject: "negative-legacy-envelope"}
		}
		if err := p.Apply(ctx, candidate); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
			t.Fatalf("legacy head supplied exact completion (%s): %v", alteration, err)
		}
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			var n int
			err := tx.QueryRow(ctx, `SELECT count(*) FROM certificate_metadata_receipts WHERE tenant_id=$1`, tenantA).Scan(&n)
			if n != 0 {
				t.Error("legacy head manufactured exact receipt")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, original); err != nil {
		t.Fatal(err)
	}
}
