// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateRecordingAfterMissingZeroRowMetadataAgreesWithOrderedRebuild(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	// This is an isolated source regression, not a served ingestion claim. Its
	// verification envelope comes from a real TLS request using the test
	// listener's private trust root; no verification or result is fabricated.
	listener := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer listener.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listener.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := listener.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("owned listener did not complete a verified TLS request")
	}
	info, err := certinfo.Inspect(response.TLS.PeerCertificates[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimPrefix(listener.URL, "https://")
	observation, _ := recordingCertificates(t)
	observation.Source, observation.IssuanceIdempotencyKey = "discovery:owned-regression", ""
	observation.CertificateDER, observation.CertificatePEM = nil, nil
	observation.DeploymentLocation = address
	certificate, err := o.RecordCertificate(ctx, tenantA, observation)
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.EndpointVerificationObserved{
		EndpointID: "owned-metadata-gap-listener", Address: address, Vantage: "relay",
		Reached: true, ObservedFingerprint: info.SHA256Fingerprint,
		CheckedSANs: true, CheckedChain: true, ObservedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := log.Append(ctx, events.Event{TenantID: tenantA, Type: projections.EventEndpointVerified, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SystemPool().Exec(ctx, `CREATE FUNCTION recording_zero_row_gap_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid AND NEW.status IS DISTINCT FROM OLD.status THEN
			RAISE EXCEPTION 'owned verification projection rollback';
		END IF; RETURN NEW; END $$;
		CREATE TRIGGER recording_zero_row_gap_fail BEFORE UPDATE ON certificates FOR EACH ROW EXECUTE FUNCTION recording_zero_row_gap_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := s.SystemPool().Exec(cleanupCtx, `DROP TRIGGER IF EXISTS recording_zero_row_gap_fail ON certificates; DROP FUNCTION IF EXISTS recording_zero_row_gap_fail()`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(cleanup)
	if err := projector.Apply(ctx, verification); err == nil {
		t.Fatal("owned verification rollback was not exercised")
	}
	cleanup()
	readStatus := func() string {
		row, err := s.GetCertificate(ctx, tenantA, certificate.ID)
		if err != nil {
			t.Fatal(err)
		}
		return row.Status
	}
	if readStatus() != "active" {
		t.Fatal("failed projection changed certificate status")
	}
	observation.Source, observation.DeploymentLocation = "import", "owned-moved-inventory-location"
	_, err = o.RecordCertificate(ctx, tenantA, observation)
	if errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		if head, headErr := log.LastSequence(ctx); headErr != nil || head != verification.Sequence || readStatus() != "active" {
			t.Fatal("unsafe pre-append refusal")
		}
		if err := projector.Rebuild(ctx, log); err != nil {
			t.Fatal(err)
		}
		if readStatus() != "superseded" {
			t.Fatal("ordered rebuild lost the retained verification")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(ctx)
	if err != nil || head != verification.Sequence+1 {
		t.Fatalf("new recording append: %d %v", head, err)
	}
	catchUpErr := projector.ProjectCatchUp(ctx, log)
	if catchUpErr != nil && !errors.Is(catchUpErr, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatal(catchUpErr)
	}
	incremental := readStatus()
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	rebuilt := readStatus()
	if rebuilt != "superseded" {
		t.Fatal("full ordered rebuild lost the earlier verification effect")
	}
	if catchUpErr == nil && incremental != rebuilt {
		t.Errorf("zero-row incremental status=%s differs from ordered rebuild=%s; missing verification=%d newer recording=%d", incremental, rebuilt, verification.Sequence, head)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != head {
		t.Fatal("recovery appended replacement evidence")
	}
}

func TestCertificateRecordingAfterMissingMetadataAgreesWithOrderedRebuild(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	ownerA, err := o.CreateOwnerRecord(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "observed owner"})
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := o.CreateOwnerRecord(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "assigned owner"})
	if err != nil {
		t.Fatal(err)
	}
	observation, _ := recordingCertificates(t)
	observation.Source, observation.IssuanceIdempotencyKey = "import", ""
	observation.CertificateDER, observation.CertificatePEM = nil, nil
	observation.OwnerID = &ownerA.ID
	certificate, err := o.RecordCertificate(ctx, tenantA, observation)
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// An exact owned database fault makes the real public assignment append
	// win while its SQL transaction rolls back. It never installs fake state.
	_, err = s.SystemPool().Exec(ctx, `CREATE FUNCTION recording_metadata_gap_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid AND NEW.owner_id IS DISTINCT FROM OLD.owner_id THEN
			RAISE EXCEPTION 'owned metadata projection rollback';
		END IF; RETURN NEW; END $$;
		CREATE TRIGGER recording_metadata_gap_fail BEFORE UPDATE ON certificates FOR EACH ROW EXECUTE FUNCTION recording_metadata_gap_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := s.SystemPool().Exec(cleanupCtx, `DROP TRIGGER IF EXISTS recording_metadata_gap_fail ON certificates; DROP FUNCTION IF EXISTS recording_metadata_gap_fail()`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(cleanup)
	if _, err := o.AssignOwnership(ctx, tenantA, ownerB.ID, []string{"certificate/" + certificate.ID}, "explicit reassignment", "fixture operator"); err == nil {
		t.Fatal("owned SQL rollback was not exercised")
	}
	cleanup()
	missing, err := log.LastSequence(ctx)
	if err != nil || missing != before+1 {
		t.Fatalf("assignment append did not win: before=%d after=%d err=%v", before, missing, err)
	}
	readOwner := func() string {
		row, err := s.GetCertificate(ctx, tenantA, certificate.ID)
		if err != nil || row.OwnerID == nil {
			t.Fatalf("read certificate owner: %v", err)
		}
		return *row.OwnerID
	}
	if got := readOwner(); got != ownerA.ID {
		t.Fatalf("failed assignment changed owner: %s", got)
	}
	observation.DeploymentLocation = "owned-observation-after-missing-assignment"
	_, err = o.RecordCertificate(ctx, tenantA, observation)
	if errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
		// Safe refusal before append is also a valid repair: retained history
		// still ends at the actual owner-B assignment and must rebuild to B.
		after, headErr := log.LastSequence(ctx)
		if headErr != nil || after != missing || readOwner() != ownerA.ID {
			t.Fatalf("unsafe refusal: head=%d err=%v", after, headErr)
		}
		if err := projector.Rebuild(ctx, log); err != nil {
			t.Fatal(err)
		}
		if readOwner() != ownerB.ID {
			t.Fatal("rebuild lost the retained assignment")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	latest, err := log.LastSequence(ctx)
	if err != nil || latest != missing+1 {
		t.Fatalf("new recording append: %d %v", latest, err)
	}
	if got := readOwner(); got != ownerA.ID {
		t.Fatalf("new recording did not retain its requested owner: %s", got)
	}
	catchUpErr := projector.ProjectCatchUp(ctx, log)
	if catchUpErr != nil && !errors.Is(catchUpErr, store.ErrCertificateRecordingRebuildRequired) {
		t.Fatal(catchUpErr)
	}
	catchUpOwner := readOwner()
	checkpoint, err := s.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	rebuiltOwner := readOwner()
	if rebuiltOwner != ownerA.ID {
		t.Fatal("full ordered rebuild lost the newer recording")
	}
	if catchUpOwner != rebuiltOwner {
		t.Errorf("incremental owner=%s differs from ordered rebuild=%s; missing metadata=%d newer recording=%d checkpoint=%d catch-up error=%v", catchUpOwner, rebuiltOwner, missing, latest, checkpoint, catchUpErr)
	}
	if after, err := log.LastSequence(ctx); err != nil || after != latest {
		t.Fatalf("recovery appended replacement evidence: %d %v", after, err)
	}
}
