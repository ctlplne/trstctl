// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"encoding/json"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestRollbackEvidenceIndexColdRestartAndUnprojectedStart(t *testing.T) {
	const tenant = "a1000000-0000-4000-8000-000000000001"
	const otherTenant = "b2000000-0000-4000-8000-000000000002"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendType := func(eventType, tenantID string, data []byte) events.Event {
		t.Helper()
		ev, err := log.Append(t.Context(), events.Event{Type: eventType, TenantID: tenantID, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	prior := appendType(EventTLSFindingFailed, tenant, []byte(`{"run_id":"old-run"}`))
	startedData, err := json.Marshal(projections.LicensedCryptoMigrationStarted{RunID: "run-a"})
	if err != nil {
		t.Fatal(err)
	}
	start := appendType(projections.EventLicensedCryptoMigrationStarted, tenant, startedData)
	wantedTypes := []string{
		projections.EventLicensedCryptoMigrationStarted,
		projections.EventLicensedCryptoMigrationAssetCompleted,
		EventCertificateFindingApplied,
		EventCertificateFindingRolledBack,
		projections.EventLicensedCryptoMigrationRollbackCompleted,
		EventTLSFindingCompleted,
		EventTLSFindingPrepared,
		EventTLSFindingRollbackCompleted,
		EventTLSFindingFailed,
	}
	wantedSequences := []uint64{start.Sequence}
	for _, eventType := range wantedTypes[1:] {
		appendType("test.unrelated", tenant, []byte(`{}`))
		appendType(eventType, otherTenant, []byte(`{}`))
		wantedSequences = append(wantedSequences, appendType(eventType, tenant, []byte(`{}`)).Sequence)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	retainedStart, found, err := log.EventAtSequence(t.Context(), start.Sequence)
	if err != nil || !found {
		t.Fatalf("cold run start found=%v err=%v", found, err)
	}
	progress := NewProgressProjection(nil)
	if err := progress.Apply(t.Context(), retainedStart); err != nil {
		t.Fatal(err)
	}
	service := &pqcMigrationService{log: log, progress: progress}
	var got []uint64
	if err := service.replayRollbackEvidence(t.Context(), tenant, "run-a", func(ev events.Event) error {
		got = append(got, ev.Sequence)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, wantedSequences) {
		t.Fatalf("cold indexed rollback evidence = %v, want %v", got, wantedSequences)
	}
	// A start appended by another replica can precede this process's progress
	// tail. Zero cursor still discovers it without admitting another tenant.
	service.progress = NewProgressProjection(nil)
	got = nil
	if err := service.replayRollbackEvidence(t.Context(), tenant, "run-a", func(ev events.Event) error {
		got = append(got, ev.Sequence)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, append([]uint64{prior.Sequence}, wantedSequences...)) {
		t.Fatalf("unprojected-start rollback evidence = %v, want prior selected fact and run events", got)
	}
}
