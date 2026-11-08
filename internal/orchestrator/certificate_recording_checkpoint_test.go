// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// checkpointObservation is an inventory observation: a fingerprint and the
// facts an export or scan names, no certificate bytes.
func checkpointObservation(i int) store.Certificate {
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	name := fmt.Sprintf("leaf-%04d.checkpoint.test", i)
	return store.Certificate{TenantID: tenantA, Subject: "CN=" + name, SANs: []string{name}, Serial: fmt.Sprintf("%x", 4096+i),
		Issuer: "CN=Checkpoint Import CA", KeyAlgorithm: "ECDSA-P256", NotAfter: &notAfter, Source: "discovered", ObservationOnly: true,
		Fingerprint: crypto.SHA256Hex([]byte(fmt.Sprintf("a266-checkpoint-%d", i)))}
}

func recoveryState(t *testing.T, s *store.Store) store.CertificateRecordingRecoveryState {
	t.Helper()
	var state store.CertificateRecordingRecoveryState
	if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		var err error
		state, err = s.CertificateRecordingRecoveryStateTx(t.Context(), tx, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

// receiptOf is the completion receipt digest of observation i's recording.
func receiptOf(t *testing.T, s *store.Store, i int) (sequence uint64, digest string) {
	t.Helper()
	if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT r.event_sequence,r.event_digest FROM certificate_metadata_receipts r
			JOIN certificates c ON c.tenant_id=r.tenant_id AND c.recording_event_id=r.event_id
			WHERE r.tenant_id=$1 AND c.fingerprint=$2`, tenantA, checkpointObservation(i).Fingerprint).Scan(&sequence, &digest)
	}); err != nil {
		t.Fatal(err)
	}
	return sequence, digest
}

// A266: recording a new certificate reads the tenant's certificate history
// only past its recovery checkpoint, plus one rotating page of the history
// below it. It used to start after the new leaf's own head, which is zero, so
// every new certificate re-read every earlier one and an import's cost grew
// with the square of the inventory. Verification is kept: a receipt changed
// through SQL anywhere in the history refuses the next append, one changed
// where no trigger sees it is found within one rotation, an event a failed
// transaction left past the checkpoint is still recovered before the next
// append, and a rebuild resets the state with the read model.
func TestCertificateRecordingReadsHistoryOnlyPastTheTenantCheckpoint(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	pageLimit := uint64(orchestrator.CertificateHistoryReverifyPageForTest)
	if pageLimit == 0 || pageLimit > uint64(store.CertificateMetadataReceiptBatchLimit) {
		t.Fatalf("re-verification page %d must fit one receipt read of %d", pageLimit, store.CertificateMetadataReceiptBatchLimit)
	}

	const n = 300
	for i := 0; i < n; i++ {
		before, err := log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		visited, reverified := o.CertificateRecoveryEventsVisited(), o.CertificateHistoryEventsReverified()
		if _, err := o.RecordCertificate(ctx, tenantA, checkpointObservation(i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		// From the second recording on, the scan past the checkpoint reads at
		// most the previous recording's own event, and the rotating check at
		// most one receipt page, however long the history.
		if read := o.CertificateRecoveryEventsVisited() - visited; i > 0 && read > 1 {
			t.Fatalf("recording %d read %d events past the checkpoint; want at most the one recorded since", i, read)
		}
		if again := o.CertificateHistoryEventsReverified() - reverified; again > pageLimit {
			t.Fatalf("recording %d re-verified %d history events; want at most one page of %d", i, again, pageLimit)
		}
		// The tenant has no watermark row before its first certificate, so
		// the first recording leaves no checkpoint; every later one leaves the
		// cut it verified.
		want := before
		if i == 0 {
			want = 0
		}
		if state := recoveryState(t, s); state.Through != want || state.RecheckFrom != 0 {
			t.Fatalf("recording %d left %+v, want the checkpoint at %d and nothing to recheck", i, state, want)
		}
	}
	if total := o.CertificateHistoryEventsReverified(); total < n {
		t.Fatalf("the rotating check re-verified %d history events across %d recordings; it never came round", total, n)
	}

	// A receipt changed through SQL, however old, refuses the next append and
	// keeps refusing until it is repaired.
	sequence, digest := receiptOf(t, s, 7)
	setDigest := func(value string) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE certificate_metadata_receipts SET event_digest=$3 WHERE tenant_id=$1 AND event_sequence=$2`,
				tenantA, sequence, value)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setDigest(fmt.Sprintf("%064x", 7))
	if state := recoveryState(t, s); state.RecheckFrom != sequence {
		t.Fatalf("a changed receipt left %+v, want a recheck from %d", state, sequence)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := o.RecordCertificate(ctx, tenantA, checkpointObservation(n)); !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("attempt %d: a changed historical receipt did not refuse the append: %v", attempt, err)
		}
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("the refusal appended: %d %v", after, err)
	}
	setDigest(digest)
	if _, err := o.RecordCertificate(ctx, tenantA, checkpointObservation(n)); err != nil {
		t.Fatalf("the repaired receipt still refused: %v", err)
	}
	if state := recoveryState(t, s); state.RecheckFrom != 0 {
		t.Fatalf("the recheck stayed after a clean scan: %+v", state)
	}

	// A receipt changed where no trigger sees it is found by the rotating
	// check within one pass over the history.
	sequence, digest = receiptOf(t, s, 11)
	outOfBand := func(value string) {
		t.Helper()
		if _, err := s.SystemPool().Exec(ctx, `ALTER TABLE certificate_metadata_receipts DISABLE TRIGGER certificate_metadata_receipt_recheck`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := s.SystemPool().Exec(context.Background(), `ALTER TABLE certificate_metadata_receipts ENABLE TRIGGER certificate_metadata_receipt_recheck`); err != nil {
				t.Error(err)
			}
		}()
		setDigest(value)
	}
	outOfBand(fmt.Sprintf("%064x", 11))
	if state := recoveryState(t, s); state.RecheckFrom != 0 {
		t.Fatalf("the out-of-band change was seen by the trigger: %+v", state)
	}
	found := false
	head, err = log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// One pass over the whole history re-checks each of its events once.
	start := o.CertificateHistoryEventsReverified()
	for i := n + 1; ; i++ {
		_, err := o.RecordCertificate(ctx, tenantA, checkpointObservation(i))
		if errors.Is(err, store.ErrIdempotencyConflict) {
			found = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if o.CertificateHistoryEventsReverified()-start > head+pageLimit {
			break
		}
	}
	if !found {
		t.Fatal("the rotating check never reached the receipt changed out of band")
	}
	outOfBand(digest)
	setDigest(digest)

	// An event a failed transaction leaves past the checkpoint is recovered
	// before the next append, exactly as before.
	orphan, survivor := checkpointObservation(2*n), checkpointObservation(2*n+1)
	if _, err := s.SystemPool().Exec(ctx, `CREATE FUNCTION checkpoint_recording_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF NEW.fingerprint=$fp$`+orphan.Fingerprint+`$fp$ THEN RAISE EXCEPTION 'owned checkpoint projection rollback'; END IF;
  RETURN NEW; END $$;
  CREATE TRIGGER checkpoint_recording_fail BEFORE INSERT ON certificates FOR EACH ROW EXECUTE FUNCTION checkpoint_recording_fail()`); err != nil {
		t.Fatal(err)
	}
	dropped := false
	drop := func() {
		if dropped {
			return
		}
		dropped = true
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := s.SystemPool().Exec(cleanupCtx, `DROP TRIGGER IF EXISTS checkpoint_recording_fail ON certificates; DROP FUNCTION IF EXISTS checkpoint_recording_fail()`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(drop)
	checkpoint := recoveryState(t, s)
	if _, err := o.RecordCertificate(ctx, tenantA, orphan); err == nil {
		t.Fatal("the owned SQL failure was not exercised")
	}
	if got := recoveryState(t, s); got != checkpoint {
		t.Fatalf("a rolled-back recording moved the recovery state from %+v to %+v", checkpoint, got)
	}
	if _, err := s.GetCertificateByFingerprint(ctx, tenantA, orphan.Fingerprint); !store.IsNotFound(err) {
		t.Fatalf("the failed projection left a certificate: %v", err)
	}
	drop()
	if _, err := o.RecordCertificate(ctx, tenantA, survivor); err != nil {
		t.Fatal(err)
	}
	for _, c := range []store.Certificate{orphan, survivor} {
		if _, err := s.GetCertificateByFingerprint(ctx, tenantA, c.Fingerprint); err != nil {
			t.Fatalf("certificate %s was not recovered past the checkpoint: %v", c.Fingerprint, err)
		}
	}

	// A rebuild truncates the watermark row with the read model; the next
	// recording verifies from the tenant's registration once and checkpoints
	// again.
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if state := recoveryState(t, s); state != (store.CertificateRecordingRecoveryState{}) {
		t.Fatalf("the rebuilt read model kept recovery state %+v", state)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	visited := o.CertificateRecoveryEventsVisited()
	if _, err := o.RecordCertificate(ctx, tenantA, checkpointObservation(2*n+2)); err != nil {
		t.Fatal(err)
	}
	if read := o.CertificateRecoveryEventsVisited() - visited; read < n {
		t.Fatalf("the first recording after a rebuild read %d earlier events; want the whole history it re-verifies", read)
	}
	if state := recoveryState(t, s); state.Through != before {
		t.Fatalf("recovery state after the rebuild = %+v, want the checkpoint at %d", state, before)
	}
}
