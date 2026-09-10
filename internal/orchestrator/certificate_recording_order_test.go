// SPDX-License-Identifier: MPL-2.0
package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Prepared real PostgreSQL + real embedded NATS regression. 100/110/120
// describe causal positions, not fabricated native sequence numbers. The test
// captures every actual sequence and proves append succeeds before SQL fails.
// No native execution or passing result is claimed by this source preparation.
func TestCertificateRecordingRecoveryRefusesLaterMetadataThenOrderedRebuild(t *testing.T) {
	for _, later := range []string{"ownership", "privacy-retention"} {
		t.Run(later, func(t *testing.T) {
			s, log, p := recordingSpine(t)
			ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
			defer cancel()
			o := orchestrator.NewOrchestrator(log, s, nil)
			ownerA, err := o.CreateOwnerRecord(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "first owner"})
			if err != nil {
				t.Fatal(err)
			}
			ownerB, err := o.CreateOwnerRecord(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "later owner"})
			if err != nil {
				t.Fatal(err)
			}
			issued, _ := recordingCertificates(t)
			issued.OwnerID = &ownerA.ID
			observed := issued
			observed.Source = "import"
			observed.CertificateDER = nil
			observed.CertificatePEM = nil
			observed.IssuanceIdempotencyKey = ""
			observed.KeyOrigin = ""
			original, err := o.RecordCertificate(ctx, tenantA, observed)
			if err != nil {
				t.Fatal(err)
			}
			record100, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			cleanup := installRecordingPublicRollback(t, ctx, s)
			if _, err := o.RecordCertificate(ctx, tenantA, issued); err == nil {
				t.Fatal("owned SQL rollback was not exercised")
			}
			record110, err := log.LastSequence(ctx)
			if err != nil || record110 != record100+1 {
				t.Fatalf("append did not win before SQL rollback: %d %d %v", record100, record110, err)
			}
			cleanup()
			row, err := s.GetCertificateByFingerprint(ctx, tenantA, issued.Fingerprint)
			if err != nil || (row.OwnerID == nil || *row.OwnerID != ownerA.ID) || len(row.CertificatePEM) != 0 {
				t.Fatalf("SQL rollback did not retain original projection: %v", err)
			}
			if later == "ownership" {
				if _, err := o.AssignOwnership(ctx, tenantA, ownerB.ID, []string{"certificate/" + original.ID}, "R4 later assignment", "owned-test-principal"); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, err := json.Marshal(projections.PrivacyRetentionEnforced{RunID: "40400000-0000-4000-8000-000000000101", Cutoffs: store.PrivacyRetentionCutoffs{CertificateTerminalBefore: issued.NotAfter.Add(time.Hour)}})
				if err != nil {
					t.Fatal(err)
				}
				e, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventPrivacyRetentionEnforced, Data: raw})
				if err != nil {
					t.Fatal(err)
				}
				if err := p.Apply(ctx, e); err != nil {
					t.Fatal(err)
				}
			}
			later120, err := log.LastSequence(ctx)
			if err != nil || later120 <= record110 {
				t.Fatalf("later event absent: %d %v", later120, err)
			}
			before := certificateOrderState(t, ctx, s, issued.Fingerprint)
			// Both the command's selective recording recovery and the ordinary
			// tail projector must refuse before any SQL or new immutable append.
			if _, err := o.RecordCertificate(ctx, tenantA, issued); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
				t.Fatalf("selective recovery did not require ordered rebuild: %v", err)
			}
			if after := certificateOrderState(t, ctx, s, issued.Fingerprint); !bytes.Equal(after, before) {
				t.Fatal("refused command changed certificate/ownership read state")
			}
			if err := p.ProjectCatchUp(ctx, log); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
				t.Fatalf("tail replay did not refuse the same older missing recording: %v", err)
			}
			if after := certificateOrderState(t, ctx, s, issued.Fingerprint); !bytes.Equal(after, before) {
				t.Fatal("refused tail replay changed certificate/ownership read state")
			}
			if head, err := log.LastSequence(ctx); err != nil || head != later120 {
				t.Fatalf("refusal appended another source event: %d %v", head, err)
			}
			if err := p.Rebuild(ctx, log); err != nil {
				t.Fatal(err)
			}
			recovered, err := s.GetCertificateByFingerprint(ctx, tenantA, issued.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.ID != original.ID || !bytes.Equal(recovered.CertificatePEM, issued.CertificatePEM) || !bytes.Equal(recovered.CertificateDER, issued.CertificateDER) || recovered.IssuanceEventID == "" {
				t.Fatal("ordered rebuild lost exact immutable public result")
			}
			if later == "ownership" {
				if recovered.OwnerID == nil || *recovered.OwnerID != ownerB.ID {
					t.Fatal("record110 rewound certificate owner120")
				}
				assignments, err := s.ListOwnershipAssignments(ctx, tenantA)
				if err != nil || len(assignments) != 1 || assignments[0].OwnerID != ownerB.ID || assignments[0].LastEventSeq != later120 {
					t.Fatalf("ownership assignment disagrees with certificate: %v", err)
				}
			} else if recovered.Source != "" || len(recovered.SANs) != 0 || recovered.DeploymentLocation != "" || recovered.Subject == issued.Subject {
				t.Fatal("record110 restored metadata cleared by privacy120")
			}
			results, err := s.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantA, issued.IssuanceIdempotencyKey)
			if err != nil || len(results) != 1 || results[0].ID != original.ID || !bytes.Equal(results[0].CertificatePEM, issued.CertificatePEM) {
				t.Fatalf("exact public-result key no longer identifies one retained leaf: %v", err)
			}
			rebuilt := certificateOrderState(t, ctx, s, issued.Fingerprint)
			if _, err := o.RecordCertificate(ctx, tenantA, issued); err != nil {
				t.Fatal(err)
			}
			if err := p.ProjectCatchUp(ctx, log); err != nil {
				t.Fatal(err)
			}
			if after := certificateOrderState(t, ctx, s, issued.Fingerprint); !bytes.Equal(after, rebuilt) {
				t.Fatal("exact old retry rewound later metadata after ordered rebuild")
			}
			if head, err := log.LastSequence(ctx); err != nil || head != later120 {
				t.Fatalf("exact retry appended: %d %v", head, err)
			}
		})
	}
}

func installRecordingPublicRollback(t *testing.T, ctx context.Context, s *store.Store) func() {
	t.Helper()
	_, err := s.SystemPool().Exec(ctx, `CREATE FUNCTION first_leaf_order_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid AND octet_length(NEW.certificate_der)>0 THEN RAISE EXCEPTION 'owned recording order rollback'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER first_leaf_order_fail BEFORE INSERT ON certificates FOR EACH ROW EXECUTE FUNCTION first_leaf_order_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.SystemPool().Exec(c, `DROP TRIGGER IF EXISTS first_leaf_order_fail ON certificates; DROP FUNCTION IF EXISTS first_leaf_order_fail()`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(cleanup)
	return cleanup
}

func certificateOrderState(t *testing.T, ctx context.Context, s *store.Store, fingerprint string) []byte {
	t.Helper()
	var raw []byte
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT jsonb_build_object('certificate',to_jsonb(c),'watermark',(SELECT to_jsonb(w) FROM certificate_metadata_watermarks w WHERE w.tenant_id=$1),'ownership',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.inventory_id),'[]'::jsonb) FROM ownership_assignments a WHERE a.tenant_id=$1 AND a.inventory_id='certificate/'||c.id::text)) FROM certificates c WHERE c.tenant_id=$1 AND c.fingerprint=$2`, tenantA, fingerprint).Scan(&raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// This is a real event/projection test, not a signed agent rollback or estate
// wire proof. The retained event uses the existing validated migration payload;
// it exercises precisely the read-model effects that overlap record recovery.
func TestCertificateRecordingRecoveryPreservesLaterMigrationRollback(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	predecessor, _ := recordingCertificates(t)
	predecessor.IssuanceIdempotencyKey = "issue:transition:recording-predecessor"
	old, err := o.RecordCertificate(ctx, tenantA, predecessor)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := recordingCertificates(t)
	issued.ReplacesID = &old.ID
	observed := issued
	observed.Source = "import"
	observed.CertificateDER = nil
	observed.CertificatePEM = nil
	observed.IssuanceIdempotencyKey = ""
	observed.KeyOrigin = ""
	successor, err := o.RecordSuccessorCertificate(ctx, tenantA, observed, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	record100, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := installRecordingPublicRollback(t, ctx, s)
	if _, err := o.RecordSuccessorCertificate(ctx, tenantA, issued, old.ID); err == nil {
		t.Fatal("real SQL rollback missing")
	}
	record110, err := log.LastSequence(ctx)
	if err != nil || record110 != record100+1 {
		t.Fatalf("actual append-won event missing: %v", err)
	}
	retainedRecording, found, err := log.EventAtSequence(ctx, record110)
	if err != nil || !found || retainedRecording.ID == "" {
		t.Fatalf("missing exact append-won recording: %v", err)
	}
	var retainedPayload projections.CertificateRecorded
	if err := json.Unmarshal(retainedRecording.Data, &retainedPayload); err != nil {
		t.Fatal(err)
	}
	if retainedPayload.ReplacesID == nil || *retainedPayload.ReplacesID != old.ID ||
		retainedPayload.IssuanceIdempotencyKey != issued.IssuanceIdempotencyKey ||
		!bytes.Equal(retainedPayload.CertificatePEM, issued.CertificatePEM) ||
		!bytes.Equal(retainedPayload.CertificateDER, issued.CertificateDER) {
		t.Fatal("append-won event lost predecessor or exact public result")
	}
	cleanup()
	run := migration.Run{ID: "40400000-0000-4000-8000-000000000094", Status: migration.RunRolledBack, Waves: []migration.RunWave{{ID: "owned-wave", Ordinal: 1, Started: true, Phase: migration.PhaseRolledBack, Members: []migration.RunMember{{IdentityID: "owned-projection-member", RollbackSuccessorVerdict: migration.VerdictVerified, RollbackTrustVerdict: migration.VerdictVerified, Binding: migration.MemberBinding{
		IssuingAuthorityID: "40400000-0000-4000-8000-000000000095", TargetID: "owned-projection-target", TargetRevision: "fixture-v1", Connector: "nginx", Target: "owned-fixture", TargetConfig: json.RawMessage(`{"executor":"agent"}`), RequiredAgentID: "40400000-0000-4000-8000-000000000096", TrustAnchorPath: "/owned-fixture/root.pem", TrustAnchorPEM: predecessor.CertificatePEM, TrustAnchorFingerprint: predecessor.Fingerprint, VerifyAddress: "127.0.0.1:443", SubjectCommonName: "recording.example.test", SubjectDNSNames: []string{"recording.example.test"}, PredecessorCertificateID: old.ID, PredecessorFingerprint: old.Fingerprint, SuccessorFingerprint: issued.Fingerprint,
	}}}}}}
	// No outbox actions are dispatched by this projector-only event fixture.
	raw, err := json.Marshal(projections.MigrationRunRecorded{Run: run})
	if err != nil {
		t.Fatal(err)
	}
	later, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventMigrationRunRecorded, Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, later); err != nil {
		t.Fatal(err)
	}
	priorBefore := certificateOrderState(t, ctx, s, old.Fingerprint)
	successorBefore := certificateOrderState(t, ctx, s, successor.Fingerprint)
	if _, err := o.RecordSuccessorCertificate(ctx, tenantA, issued, old.ID); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("migration overlap accepted: %v", err)
	}
	if err := p.ProjectCatchUp(ctx, log); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("migration tail overlap accepted: %v", err)
	}
	if !bytes.Equal(priorBefore, certificateOrderState(t, ctx, s, old.Fingerprint)) || !bytes.Equal(successorBefore, certificateOrderState(t, ctx, s, successor.Fingerprint)) {
		t.Fatal("refusal changed predecessor or successor")
	}
	if head, err := log.LastSequence(ctx); err != nil || head != later.Sequence {
		t.Fatalf("refusal appended: %d %v", head, err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	restored, err := s.GetCertificateByFingerprint(ctx, tenantA, old.Fingerprint)
	if err != nil || restored.Status != "active" || restored.RenewedAt != nil {
		t.Fatalf("rollback predecessor not restored: %v", err)
	}
	recovered, err := s.GetCertificateByFingerprint(ctx, tenantA, issued.Fingerprint)
	if err != nil || recovered.Status != "superseded" || !bytes.Equal(recovered.CertificatePEM, issued.CertificatePEM) || recovered.IssuanceEventID == "" {
		t.Fatalf("rollback successor/public result mismatch: %v", err)
	}
	retained, err := s.GetMigrationRun(ctx, tenantA, run.ID)
	if err != nil || retained.LastEventSequence != later.Sequence || retained.Run.Status != migration.RunRolledBack {
		t.Fatalf("migration aggregate diverged: %v", err)
	}
	priorBefore = certificateOrderState(t, ctx, s, old.Fingerprint)
	successorBefore = certificateOrderState(t, ctx, s, successor.Fingerprint)
	for i := 0; i < 2; i++ {
		if _, err := o.RecordSuccessorCertificate(ctx, tenantA, issued, old.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priorBefore, certificateOrderState(t, ctx, s, old.Fingerprint)) || !bytes.Equal(successorBefore, certificateOrderState(t, ctx, s, successor.Fingerprint)) {
		t.Fatal("old retry undid later rollback after rebuild")
	}
	if _, err := o.RecordSuccessorCertificate(ctx, tenantA, issued, "40400000-0000-4000-8000-000000000097"); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed predecessor: want store idempotency conflict, got %v", err)
	}
	if !bytes.Equal(priorBefore, certificateOrderState(t, ctx, s, old.Fingerprint)) || !bytes.Equal(successorBefore, certificateOrderState(t, ctx, s, successor.Fingerprint)) {
		t.Fatal("changed predecessor mutated rollback state")
	}
	if head, err := log.LastSequence(ctx); err != nil || head != later.Sequence {
		t.Fatalf("old retry or conflicting predecessor appended after rollback: %d %v", head, err)
	}
	exact, found, err := log.EventByID(ctx, retainedRecording.ID)
	if err != nil || !found || exact.Sequence != retainedRecording.Sequence || !exact.Time.Equal(retainedRecording.Time) || !bytes.Equal(exact.Data, retainedRecording.Data) {
		t.Fatalf("retry changed the original immutable recording: %v", err)
	}
}

func TestCertificateRecordingUnknownMetadataRefusesBeforeNewAppend(t *testing.T) {
	s, log, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	in, _ := recordingCertificates(t)
	if _, err := o.RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatal(err)
	}
	// An actual legacy utility write supplies no event sequence. It must not
	// inherit a previous call's transaction-local projector provenance.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET source='legacy-unknown' WHERE tenant_id=$1 AND fingerprint=$2`, tenantA, in.Fingerprint)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := certificateOrderState(t, ctx, s, in.Fingerprint)
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observation := in
	observation.Source = "import"
	observation.CertificateDER = nil
	observation.CertificatePEM = nil
	observation.IssuanceIdempotencyKey = ""
	if _, err := o.RecordCertificate(ctx, tenantA, observation); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("unknown metadata admitted new append: %v", err)
	}
	if !bytes.Equal(before, certificateOrderState(t, ctx, s, in.Fingerprint)) {
		t.Fatal("unknown metadata refusal wrote state")
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("unknown metadata refusal appended: %d %v", after, err)
	}
}

// Query the actual migrated catalog: a newly added certificate column must be
// classified rather than silently bypassing the certificate-only write census.
func TestCertificateRecordingMetadataTriggerCoversNativeSchema(t *testing.T) {
	s, _, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	excluded := map[string]bool{"metadata_sequence": true, "recording_sequence": true, "recording_event_id": true, "issuance_event_id": true, "alerted_at": true}
	//trstctl:system-query — bounded catalog-only census of this owned fixture's certificate trigger and columns; no tenant data (AN-1 exemption).
	rows, err := s.SystemPool().Query(ctx, `SELECT a.attname,a.attnum=ANY(t.tgattr::smallint[]) FROM pg_attribute a JOIN pg_trigger t ON t.tgrelid=a.attrelid WHERE a.attrelid='certificates'::regclass AND a.attnum>0 AND NOT a.attisdropped AND t.tgname='certificate_metadata_order' ORDER BY a.attnum`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name string
		var covered bool
		if err := rows.Scan(&name, &covered); err != nil {
			t.Fatal(err)
		}
		n++
		if covered == excluded[name] {
			t.Fatalf("certificate column %s has wrong metadata-order classification", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("certificate trigger absent")
	}
	if store.SnapshotFormatVersion < 39 {
		t.Fatal("snapshots lack metadata ordering provenance")
	}
}

func TestCertificateRecordingMetadataOrderSurvivesColdSnapshot(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	in, _ := recordingCertificates(t)
	original, err := o.RecordCertificate(ctx, tenantA, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	before := certificateOrderState(t, ctx, s, in.Fingerprint)
	if n, err := p.Snapshot(ctx); err != nil || n == 0 {
		t.Fatalf("snapshot absent: %d %v", n, err)
	}
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM certificates WHERE tenant_id=$1 AND fingerprint=$2`, tenantA, in.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetProjectionCheckpointTx(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	cold := projections.New(s)
	restored, err := cold.RestoreFromSnapshot(ctx, log)
	if err != nil || !restored {
		t.Fatalf("actual cold restore absent: %t %v", restored, err)
	}
	if !bytes.Equal(before, certificateOrderState(t, ctx, s, in.Fingerprint)) {
		t.Fatal("cold snapshot did not preserve metadata sequence and exact result")
	}
	recovered, err := o.RecordCertificate(ctx, tenantA, in)
	if err != nil || recovered.ID != original.ID {
		t.Fatalf("restored exact retry failed: %v", err)
	}
}

func TestCertificateRecordingProjectorScopeRestoresAndAppCannotSpoofSnapshot(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	in, _ := recordingCertificates(t)
	if _, err := o.RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(projections.PrivacyRetentionEnforced{RunID: "40400000-0000-4000-8000-000000000102", Cutoffs: store.PrivacyRetentionCutoffs{}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventPrivacyRetentionEnforced, Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := p.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		var scope string
		if err := tx.QueryRow(ctx, `SELECT coalesce(current_setting('trstctl.certificate_projection_sequence',true),'')`).Scan(&scope); err != nil {
			return err
		}
		if scope != "" {
			return errors.New("projector scope leaked past callback")
		}
		// App-role UPDATE with a spoofed restore setting is not the trusted
		// owner-role INSERT path. It must mark unsequenced metadata unknown.
		if _, err := tx.Exec(ctx, `SET LOCAL trstctl.certificate_snapshot_restore='true'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE certificates SET source='unknown-after-projector' WHERE tenant_id=$1 AND fingerprint=$2`, tenantA, in.Fingerprint); err != nil {
			return err
		}
		var sequence int64
		if err := tx.QueryRow(ctx, `SELECT metadata_sequence FROM certificates WHERE tenant_id=$1 AND fingerprint=$2`, tenantA, in.Fingerprint).Scan(&sequence); err != nil {
			return err
		}
		if sequence != 0 {
			return errors.New("unsequenced write borrowed event or snapshot provenance")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertificateRecordingRecoveryChecksPredecessorOnlyLaterMetadata(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	owner, err := o.CreateOwnerRecord(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "later predecessor owner"})
	if err != nil {
		t.Fatal(err)
	}
	predecessor, _ := recordingCertificates(t)
	predecessor.IssuanceIdempotencyKey = "issue:transition:predecessor-only"
	old, err := o.RecordCertificate(ctx, tenantA, predecessor)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := recordingCertificates(t)
	issued.ReplacesID = &old.ID
	observed := issued
	observed.Source = "import"
	observed.CertificateDER = nil
	observed.CertificatePEM = nil
	observed.IssuanceIdempotencyKey = ""
	observed.KeyOrigin = ""
	if _, err := o.RecordSuccessorCertificate(ctx, tenantA, observed, old.ID); err != nil {
		t.Fatal(err)
	}
	cleanup := installRecordingPublicRollback(t, ctx, s)
	if _, err := o.RecordSuccessorCertificate(ctx, tenantA, issued, old.ID); err == nil {
		t.Fatal("SQL rollback absent")
	}
	cleanup()
	if _, err := o.AssignOwnership(ctx, tenantA, owner.ID, []string{"certificate/" + old.ID}, "later predecessor assignment", "owned-test-principal"); err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := certificateOrderState(t, ctx, s, issued.Fingerprint)
	oldBefore := certificateOrderState(t, ctx, s, old.Fingerprint)
	if _, err := o.RecordSuccessorCertificate(ctx, tenantA, issued, old.ID); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("predecessor-only overlap passed: %v", err)
	}
	if !bytes.Equal(before, certificateOrderState(t, ctx, s, issued.Fingerprint)) || !bytes.Equal(oldBefore, certificateOrderState(t, ctx, s, old.Fingerprint)) {
		t.Fatal("refusal changed a guarded row")
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatalf("refusal appended: %d %v", after, err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := s.GetCertificateByFingerprint(ctx, tenantA, old.Fingerprint)
	if err != nil || rebuilt.OwnerID == nil || *rebuilt.OwnerID != owner.ID {
		t.Fatalf("ordered rebuild lost later predecessor owner: %v", err)
	}
	if _, err := o.RecordSuccessorCertificate(ctx, tenantA, issued, old.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateRecordingRecoveryWaitsForActualLaterWriterRowLock(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	owner, err := o.CreateOwnerRecord(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "concurrent owner"})
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := recordingCertificates(t)
	observed := issued
	observed.Source = "import"
	observed.CertificateDER = nil
	observed.CertificatePEM = nil
	observed.IssuanceIdempotencyKey = ""
	observed.KeyOrigin = ""
	original, err := o.RecordCertificate(ctx, tenantA, observed)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := installRecordingPublicRollback(t, ctx, s)
	if _, err := o.RecordCertificate(ctx, tenantA, issued); err == nil {
		t.Fatal("SQL rollback absent")
	}
	cleanup()
	assignedAt := time.Now().UTC()
	raw, err := json.Marshal(projections.OwnershipAssigned{OwnerID: owner.ID, InventoryIDs: []string{"certificate/" + original.ID}, Reason: "R4 concurrent projection", AssignedBy: "owned-test-principal", AssignedAt: assignedAt})
	if err != nil {
		t.Fatal(err)
	}
	later, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventOwnershipAssigned, Time: assignedAt, Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	ownerDone := make(chan error, 1)
	go func() {
		ownerDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := p.ApplyTx(ctx, tx, later); err != nil {
				return err
			}
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	select {
	case <-held:
	case err := <-ownerDone:
		t.Fatalf("later writer failed: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	peer, err := store.Open(ctx, testDSN+"?application_name=first_leaf_order_reader")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		_, err := orchestrator.NewOrchestrator(log, peer, nil).RecordCertificate(ctx, tenantA, issued)
		done <- err
	}()
	blocked := 0
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		select {
		case err := <-done:
			t.Fatalf("recovery crossed uncommitted metadata writer: %v", err)
		default:
		}
		//trstctl:system-query — one owned fixture connection's lock wait; no tenant data or unrelated sessions (AN-1 exemption).
		if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name='first_leaf_order_reader' AND wait_event_type='Lock' AND query LIKE '%lock_certificate_metadata_order%'`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if blocked != 1 {
		t.Fatal("real recovery connection never waited for the actual metadata tenant lock")
	}
	close(release)
	released = true
	if err := <-ownerDone; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
			t.Fatalf("committed later metadata was not rechecked: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	current, err := s.GetCertificateByFingerprint(ctx, tenantA, issued.Fingerprint)
	if err != nil || current.OwnerID == nil || *current.OwnerID != owner.ID || len(current.CertificatePEM) != 0 {
		t.Fatalf("concurrent refusal lost actual later writer: %v", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != later.Sequence {
		t.Fatalf("concurrent refusal appended: %d %v", head, err)
	}
}

// The failed first recording leaves no row, so no row trigger or row lock can
// remember the later privacy UPDATE. The real statement watermark must do so.
func TestCertificateRecordingZeroRowWriterRequiresOrderedRebuild(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	issued, _ := recordingCertificates(t)
	cleanup := installRecordingPublicRollback(t, ctx, s)
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordCertificate(ctx, tenantA, issued); err == nil {
		t.Fatal("append-won SQL rollback not exercised")
	}
	failed, err := log.LastSequence(ctx)
	if err != nil || failed != before+1 {
		t.Fatalf("missing immutable failed append: %d %v", failed, err)
	}
	cleanup()
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE tenant_id=$1`, tenantA).Scan(&n)
		if err == nil && n != 0 {
			return errors.New("fixture unexpectedly has a certificate row")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(projections.PrivacyRetentionEnforced{RunID: "40400000-0000-4000-8000-000000000103", Cutoffs: store.PrivacyRetentionCutoffs{CertificateTerminalBefore: issued.NotAfter.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	later, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventPrivacyRetentionEnforced, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, later); err != nil {
		t.Fatal(err)
	}

	if _, err := o.RecordCertificate(ctx, tenantA, issued); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("zero-row later writer was forgotten: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var sequence int64
		var unknown bool
		if err := tx.QueryRow(ctx, `SELECT latest_sequence,unknown_write FROM certificate_metadata_watermarks WHERE tenant_id=$1`, tenantA).Scan(&sequence, &unknown); err != nil {
			return err
		}
		if sequence < 0 || uint64(sequence) != later.Sequence || unknown {
			return errors.New("zero-row event lost exact statement provenance")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("tail repaired out of order: %v", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != later.Sequence {
		t.Fatalf("refusal appended another event: %d %v", head, err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCertificateByFingerprint(ctx, tenantA, issued.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "" || len(got.SANs) != 0 || got.Subject == issued.Subject || !bytes.Equal(got.CertificatePEM, issued.CertificatePEM) {
		t.Fatal("ordered replay failed privacy ordering or lost public result")
	}
	stable := certificateOrderState(t, ctx, s, issued.Fingerprint)
	if _, err := o.RecordCertificate(ctx, tenantA, issued); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stable, certificateOrderState(t, ctx, s, issued.Fingerprint)) {
		t.Fatal("exact retry rewound replayed zero-row effect")
	}
}

func TestCertificateRecordingZeroRowUnknownWritesAndTenantScope(t *testing.T) {
	for _, statement := range []string{`UPDATE certificates SET source='unknown' WHERE tenant_id=$1 AND false`, `DELETE FROM certificates WHERE tenant_id=$1 AND false`} {
		t.Run(statement, func(t *testing.T) {
			s, log, _ := recordingSpine(t)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			o := orchestrator.NewOrchestrator(log, s, nil)
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, statement, tenantA); return err }); err != nil {
				t.Fatal(err)
			}
			head, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			issued, _ := recordingCertificates(t)
			if _, err := o.RecordCertificate(ctx, tenantA, issued); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
				t.Fatalf("unknown zero-row mutation accepted: %v", err)
			}
			if after, err := log.LastSequence(ctx); err != nil || after != head {
				t.Fatalf("unknown write refusal appended: %d %v", after, err)
			}
			err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				return s.WithCertificateProjectionOrderTx(ctx, tx, "22222222-2222-2222-2222-222222222222", 1, func() error { t.Error("wrong-tenant callback ran"); return nil })
			})
			if err == nil {
				t.Fatal("wrong tenant provenance accepted")
			}
			if err := s.WithTenant(ctx, "22222222-2222-2222-2222-222222222222", func(tx pgx.Tx) error {
				var n int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificate_metadata_watermarks WHERE tenant_id=$1`, tenantA).Scan(&n); err != nil {
					return err
				}
				if n != 0 {
					return errors.New("RLS exposed another tenant's watermark")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCertificateRecordingZeroRowWriterHoldsRecoveryUntilCommit(t *testing.T) {
	s, log, p := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	issued, _ := recordingCertificates(t)
	cleanup := installRecordingPublicRollback(t, ctx, s)
	if _, err := o.RecordCertificate(ctx, tenantA, issued); err == nil {
		t.Fatal("SQL rollback missing")
	}
	cleanup()
	data, err := json.Marshal(projections.PrivacyRetentionEnforced{RunID: "40400000-0000-4000-8000-000000000104", Cutoffs: store.PrivacyRetentionCutoffs{CertificateTerminalBefore: issued.NotAfter.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	later, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventPrivacyRetentionEnforced, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := p.ApplyTx(ctx, tx, later); err != nil {
				return err
			}
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	select {
	case <-held:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// An independent transaction must block even though no certificate exists.
	short, stop := context.WithTimeout(ctx, 250*time.Millisecond)
	_, err = o.RecordCertificate(short, tenantA, issued)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("recovery crossed held zero-row writer: %v", err)
	}
	close(release)
	released = true
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordCertificate(ctx, tenantA, issued); !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatalf("committed zero-row provenance not rechecked: %v", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != later.Sequence {
		t.Fatalf("refusal appended: %d %v", head, err)
	}
}

func TestCertificateMetadataStatementTriggerCoversSameNativeColumns(t *testing.T) {
	s, _, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	//trstctl:system-query — exact owned fixture trigger metadata; no tenant rows are read (AN-1 exemption).
	var same, statement, insert, update, deleted, forcedRLS bool
	err := s.SystemPool().QueryRow(ctx, `SELECT a.tgattr=b.tgattr,(b.tgtype::int&1)=0,(b.tgtype::int&4)<>0,(b.tgtype::int&16)<>0,(b.tgtype::int&8)<>0,c.relrowsecurity AND c.relforcerowsecurity
        FROM pg_trigger a JOIN pg_trigger b ON a.tgrelid=b.tgrelid
        CROSS JOIN pg_class c WHERE a.tgrelid='certificates'::regclass AND a.tgname='certificate_metadata_order'
        AND b.tgname='certificate_metadata_statement_order' AND c.oid='certificate_metadata_watermarks'::regclass`).Scan(&same, &statement, &insert, &update, &deleted, &forcedRLS)
	if err != nil || !same || !statement || !insert || !update || !deleted || !forcedRLS {
		t.Fatalf("actual statement/row/RLS coverage mismatch: %v", err)
	}
}
