// SPDX-License-Identifier: MPL-2.0
package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// These are real-PG, real-NATS tests when executed. Independent Store pools
// represent two database sessions; no process mutex or mocked transport decides
// the result. This source preparation has not executed them.
func recordingCertificates(t *testing.T) (store.Certificate, []byte) {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	rootA, err := crypto.SelfSignedCACert(ca, "recording-race-root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// A second real self-signed certificate for the same CA key and subject is
	// a different public envelope that can verify this same leaf signature.
	rootB, err := crypto.SelfSignedCACert(ca, "recording-race-root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Destroy()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "recording.example.test", DNSNames: []string{"recording.example.test"}}, subject)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := crypto.SignLeafFromCSR(rootA, ca, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(leaf)
	if err != nil {
		t.Fatal(err)
	}
	public := func(root []byte) []byte {
		return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})...)
	}
	return store.Certificate{Source: "issued", Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		CertificateDER: leaf, CertificatePEM: public(rootA), IssuanceIdempotencyKey: "issue:transition:recording-race", KeyOrigin: "requester"}, public(rootB)
}

func recordingSpine(t *testing.T) (*store.Store, *events.Log, *projections.Projector) {
	t.Helper()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	e, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegisteredJSON("recording-recovery")})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	return s, log, p
}

func TestCertificateRecordingTwoSessionsFenceFirstAppendAndReplay(t *testing.T) {
	for _, kind := range []string{"different-chain", "different-key", "identical"} {
		t.Run(kind, func(t *testing.T) {
			s, log, projector := recordingSpine(t)
			first, alternate := recordingCertificates(t)
			second := first
			if kind == "different-chain" {
				second.CertificatePEM = alternate
			}
			if kind == "different-key" {
				second.IssuanceIdempotencyKey += "-other"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			peers := make([]*store.Store, 2)
			for i := range peers {
				var err error
				peers[i], err = store.Open(ctx, testDSN+fmt.Sprintf("?application_name=first_leaf_recording_peer_%d", i))
				if err != nil {
					t.Fatal(err)
				}
				defer peers[i].Close()
			}
			held := make(chan struct{})
			release := make(chan struct{})
			gateDone := make(chan error, 1)
			go func() {
				gateDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "certificate-recording\x1f"+tenantA+"\x1f"+first.Fingerprint); err != nil {
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
			case err := <-gateDone:
				t.Fatalf("hold real PG fence: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			type outcome struct {
				certificate store.Certificate
				err         error
			}
			results := make(chan outcome, 2)
			for i, in := range []store.Certificate{first, second} {
				go func(i int, in store.Certificate) {
					c, err := orchestrator.NewOrchestrator(log, peers[i], nil).RecordCertificate(ctx, tenantA, in)
					results <- outcome{c, err}
				}(i, in)
			}
			until := time.Now().Add(5 * time.Second)
			blocked := 0
			for time.Now().Before(until) {
				select {
				case got := <-results:
					t.Fatalf("command crossed the held tenant/fingerprint fence before append: %v", got.err)
				default:
				}
				// Only the two explicitly named owned connections are observed.
				//trstctl:system-query — owned integration fixture connection-lock census; no tenant data is selected (AN-1 exemption).
				if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name IN ('first_leaf_recording_peer_0','first_leaf_recording_peer_1') AND wait_event_type='Lock' AND wait_event='advisory'`).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked == 2 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if blocked != 2 {
				t.Fatalf("wanted two actual advisory-lock waiters, got %d", blocked)
			}
			before, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			close(release)
			released = true
			if err := <-gateDone; err != nil {
				t.Fatal(err)
			}
			accepted, conflicted := 0, 0
			var winner store.Certificate
			for range 2 {
				select {
				case got := <-results:
					if got.err == nil {
						accepted++
						if winner.ID != "" && winner.ID != got.certificate.ID {
							t.Fatal("identical retry changed canonical row")
						}
						winner = got.certificate
					} else if errors.Is(got.err, store.ErrIdempotencyConflict) {
						conflicted++
					} else {
						t.Fatal(got.err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if kind == "identical" {
				if accepted != 2 || conflicted != 0 {
					t.Fatalf("identical outcomes %d/%d", accepted, conflicted)
				}
			} else if accepted != 1 || conflicted != 1 {
				t.Fatalf("conflicting outcomes %d/%d", accepted, conflicted)
			}
			if after, err := log.LastSequence(ctx); err != nil || after != before+1 {
				t.Fatalf("expected one canonical immutable event: before=%d after=%d err=%v", before, after, err)
			}
			if err := projector.ProjectCatchUp(ctx, log); err != nil {
				t.Fatal(err)
			}
			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatal(err)
			}
			rebuilt, err := s.GetCertificateByFingerprint(ctx, tenantA, first.Fingerprint)
			if err != nil || rebuilt.ID != winner.ID || !bytes.Equal(rebuilt.CertificatePEM, winner.CertificatePEM) || rebuilt.IssuanceIdempotencyKey != winner.IssuanceIdempotencyKey {
				t.Fatalf("race poisoned replay or changed result: %+v %v", rebuilt, err)
			}
		})
	}
}

func TestCertificateRecordingAppendWonSQLRollbackCannotPoisonNextAppend(t *testing.T) {
	s, log, p := recordingSpine(t)
	in, alternate := recordingCertificates(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	// A real PostgreSQL trigger fails projection after the genuine NATS append.
	// The isolated fixture's own table is restored before any retry.
	_, err := s.SystemPool().Exec(ctx, `CREATE FUNCTION first_leaf_recording_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid THEN RAISE EXCEPTION 'owned recording rollback control'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER first_leaf_recording_fail BEFORE INSERT ON certificates FOR EACH ROW EXECUTE FUNCTION first_leaf_recording_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.SystemPool().Exec(cleanupCtx, `DROP TRIGGER IF EXISTS first_leaf_recording_fail ON certificates; DROP FUNCTION IF EXISTS first_leaf_recording_fail()`); err != nil {
			t.Error(err)
		}
	}
	defer cleanup()
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordCertificate(ctx, tenantA, in); err == nil {
		t.Fatal("injected SQL failure accepted")
	}
	appended, err := log.LastSequence(ctx)
	if err != nil || appended != before+1 {
		t.Fatalf("failure did not exercise append-won/SQL-lost: %d %v", appended, err)
	}
	if _, err := s.GetCertificateByFingerprint(ctx, tenantA, in.Fingerprint); !store.IsNotFound(err) {
		t.Fatalf("SQL projection survived rollback: %v", err)
	}
	cleanup()
	other := in
	other.CertificatePEM = alternate
	if _, err := o.RecordCertificate(ctx, tenantA, other); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("conflicting recovery appended against missing SQL row: %v", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != appended {
		t.Fatalf("conflict polluted immutable tail: %d %v", head, err)
	}
	result, err := o.RecordCertificate(ctx, tenantA, in)
	if err != nil {
		t.Fatal(err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != appended {
		t.Fatalf("exact recovery appended twice: %d %v", head, err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := s.GetCertificateByFingerprint(ctx, tenantA, in.Fingerprint)
	if err != nil || rebuilt.ID != result.ID || !bytes.Equal(rebuilt.CertificatePEM, in.CertificatePEM) {
		t.Fatalf("rollback recovery not replayable: %+v %v", rebuilt, err)
	}
}

func TestCertificateRecordingLegacyCursorRequiresOrderedRebuild(t *testing.T) {
	s, log, p := recordingSpine(t)
	in, _ := recordingCertificates(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	original, err := o.RecordCertificate(ctx, tenantA, in)
	if err != nil {
		t.Fatal(err)
	}
	// Model the actual new-column defaults on an already populated v36 row.
	// Do not permit a filtered old-event replay to overwrite later metadata.
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET recording_event_id='',recording_sequence=0,issuance_event_id='' WHERE tenant_id=$1 AND fingerprint=$2`, tenantA, in.Fingerprint)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordCertificate(ctx, tenantA, in); err == nil || !strings.Contains(err.Error(), "certificate recording requires a full retained read-model rebuild") {
		t.Fatalf("legacy command did not require full rebuild: %v", err)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("legacy admission appended: %d %v", after, err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	recovered, err := o.RecordCertificate(ctx, tenantA, in)
	if err != nil || recovered.ID != original.ID || !bytes.Equal(recovered.CertificatePEM, original.CertificatePEM) {
		t.Fatalf("ordered rebuild failed recovery: %+v %v", recovered, err)
	}
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var origin string
		if err := tx.QueryRow(ctx, `SELECT issuance_event_id FROM certificates WHERE tenant_id=$1 AND fingerprint=$2`, tenantA, in.Fingerprint).Scan(&origin); err != nil {
			return err
		}
		if origin == "" {
			return errors.New("rebuild did not restore immutable issuance origin")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertificateRecordingSnapshotRetainsImportProvenance(t *testing.T) {
	s, log, p := recordingSpine(t)
	in, _ := recordingCertificates(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	original, err := o.RecordCertificate(ctx, tenantA, in)
	if err != nil {
		t.Fatal(err)
	}
	observation := in
	observation.Source = "import"
	observation.CertificateDER = nil
	observation.CertificatePEM = nil
	observation.IssuanceIdempotencyKey = ""
	if _, err := o.RecordCertificate(ctx, tenantA, observation); err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if store.SnapshotFormatVersion < 38 {
		t.Fatal("older snapshot format can skip immutable issuance provenance")
	}
	if count, err := p.Snapshot(ctx); err != nil || count == 0 {
		t.Fatalf("snapshot: %d %v", count, err)
	}
	// Actual cold-restore fixture: remove only this tenant's leaf and reset the
	// owned fixture checkpoint. No warm-boot no-op may stand in for restoration.
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	if err := s.SetTenantGUCTx(ctx, tx, tenantA); err != nil {
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
	if restored, err := p.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("cold restore: %t %v", restored, err)
	}
	current, err := s.GetCertificateByFingerprint(ctx, tenantA, in.Fingerprint)
	if err != nil || current.ID != original.ID || current.Source != "import" || current.IssuanceIdempotencyKey != in.IssuanceIdempotencyKey || !bytes.Equal(current.CertificatePEM, in.CertificatePEM) {
		t.Fatalf("snapshot lost exact result or current provenance: %+v %v", current, err)
	}
	if _, err := o.RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatalf("restored cursor cannot admit exact retry: %v", err)
	}
	current, err = s.GetCertificateByFingerprint(ctx, tenantA, in.Fingerprint)
	if err != nil || current.Source != "import" {
		t.Fatalf("old issuance retry rewound current observation: %+v %v", current, err)
	}
	var origin string
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT issuance_event_id FROM certificates WHERE tenant_id=$1 AND fingerprint=$2`, tenantA, in.Fingerprint).Scan(&origin)
	}); err != nil || origin == "" {
		t.Fatalf("snapshot lost immutable issuance origin: %q %v", origin, err)
	}
}
