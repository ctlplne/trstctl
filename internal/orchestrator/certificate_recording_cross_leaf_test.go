// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A real external-CA renewal left its event in NATS after its SQL transaction
// failed. An unrelated ACME leaf then advanced the tenant metadata watermark,
// making the missing older certificate impossible to project at the next boot.
func TestCertificateRecordingRecoversDifferentLeafBeforeNewAppend(t *testing.T) {
	s, log, p := recordingSpine(t)
	first, _ := recordingCertificates(t)
	next, _ := recordingCertificates(t)
	next.IssuanceIdempotencyKey += "-different-leaf"
	if first.Fingerprint == next.Fingerprint {
		t.Fatal("fixture certificates are not distinct")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	_, err := s.SystemPool().Exec(ctx, `CREATE FUNCTION cross_leaf_recording_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid THEN
   RAISE EXCEPTION 'owned cross-leaf projection rollback';
  END IF; RETURN NEW; END $$;
  CREATE TRIGGER cross_leaf_recording_fail BEFORE INSERT ON certificates FOR EACH ROW EXECUTE FUNCTION cross_leaf_recording_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := s.SystemPool().Exec(cleanupCtx, `DROP TRIGGER IF EXISTS cross_leaf_recording_fail ON certificates; DROP FUNCTION IF EXISTS cross_leaf_recording_fail()`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(cleanup)
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordCertificate(ctx, tenantA, first); err == nil {
		t.Fatal("owned SQL failure was not exercised")
	}
	retained, err := log.LastSequence(ctx)
	if err != nil || retained != before+1 {
		t.Fatalf("append did not survive SQL failure: %d %v", retained, err)
	}
	if _, err := s.GetCertificateByFingerprint(ctx, tenantA, first.Fingerprint); !store.IsNotFound(err) {
		t.Fatalf("failed projection left a certificate: %v", err)
	}
	cleanup()
	if _, err := o.RecordCertificate(ctx, tenantA, next); err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		for _, input := range []store.Certificate{first, next} {
			got, err := s.GetCertificateByFingerprint(ctx, tenantA, input.Fingerprint)
			if err != nil || !bytes.Equal(got.CertificateDER, input.CertificateDER) || got.IssuanceIdempotencyKey != input.IssuanceIdempotencyKey {
				t.Fatalf("retained leaf %s was not recovered: %v", input.Fingerprint, err)
			}
		}
	}
	// First check the actual restart path: a successful new issuance must not
	// make an earlier retained event permanently unsafe to replay.
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("restart after unrelated successful issuance: %v", err)
	}
	check()
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	check()
	if head, err := log.LastSequence(ctx); err != nil || head != retained+1 {
		t.Fatalf("recovery duplicated immutable source events: %d %v", head, err)
	}
}
