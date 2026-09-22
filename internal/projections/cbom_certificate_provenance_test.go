// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Use wire payloads so the same regression compiles on the baseline that drops
// the fingerprint. The absence of a historical field must remain unknown.
func certificateObservationPayload(t *testing.T, id, fingerprint string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(observedPQCAsset("ECDSA"))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload["id"] = id
	if fingerprint != "" {
		payload["certificate_fingerprint"] = fingerprint
	}
	return payload
}

func requireObservedFingerprint(t *testing.T, st *store.Store, tenant, expected string) {
	t.Helper()
	assets, err := st.ListCryptoAssets(t.Context(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 {
		t.Fatalf("tenant %s assets=%d, want one", tenant, len(assets))
	}
	raw, err := json.Marshal(assets[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	actual, _ := fields["CertificateFingerprint"].(string)
	if actual != expected {
		t.Fatalf("tenant %s observed fingerprint=%q, want %q", tenant, actual, expected)
	}
}

func TestCBOMObservedLeafSurvivesOrderingTenantIsolationAndRebuild(t *testing.T) {
	st, log := newStore(t), openLog(t)
	projector := projections.New(st)
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendPQCObservationEvent(t, log, tenantA, "tenant.registered", map[string]string{"name": "owner"})
	appendPQCObservationEvent(t, log, tenantB, "tenant.registered", map[string]string{"name": "other owner"})
	if err := projector.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendObserved := func(tenant, id, fingerprint string) events.Event {
		t.Helper()
		data, err := json.Marshal(certificateObservationPayload(t, id, fingerprint))
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(t.Context(), events.Event{TenantID: tenant, Type: projections.EventCBOMAssetObserved, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	old := appendObserved(tenantA, observedPQCAssetID, strings.Repeat("a", 64))
	latest := appendObserved(tenantA, observedPQCAssetID, strings.Repeat("b", 64))
	// The asset UUID is global, but both tenants may observe the same endpoint.
	foreign := appendObserved(tenantB, "f2020000-0000-4000-8000-000000000002", strings.Repeat("c", 64))
	for _, event := range []events.Event{latest, foreign, old, latest} {
		if err := projector.Apply(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	requireObservedFingerprint(t, st, tenantA, strings.Repeat("b", 64))
	requireObservedFingerprint(t, st, tenantB, strings.Repeat("c", 64))
	// A foreign-tenant observation cannot take over the owner's asset UUID.
	forgedPayload := certificateObservationPayload(t, observedPQCAssetID, strings.Repeat("d", 64))
	forgedPayload["location"] = "forged.example.test:443"
	forged, err := json.Marshal(forgedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(t.Context(), events.Event{TenantID: tenantB, Type: projections.EventCBOMAssetObserved, Sequence: 500, Data: forged}); err == nil {
		t.Fatal("foreign observation accepted another tenant's asset UUID")
	}
	requireObservedFingerprint(t, st, tenantA, strings.Repeat("b", 64))
	requireObservedFingerprint(t, st, tenantB, strings.Repeat("c", 64))
	// Issuance and a metadata-only rollback are not new TLS observations.
	appendPQCObservationEvent(t, log, tenantA, projections.EventLicensedCryptoMigrationAssetCompleted, historicalPQCIssuance())
	appendPQCObservationEvent(t, log, tenantA, projections.EventLicensedCryptoMigrationRollbackCompleted, historicalPQCRollback())
	if err := projector.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedFingerprint(t, st, tenantA, strings.Repeat("b", 64))
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedFingerprint(t, st, tenantA, strings.Repeat("b", 64))
	requireObservedFingerprint(t, st, tenantB, strings.Repeat("c", 64))
	// A cold restore must retain exact leaf identity for both tenants.
	if count, err := projector.Snapshot(t.Context()); err != nil || count != 2 {
		t.Fatalf("snapshot count=%d err=%v", count, err)
	}
	truncateReadModelAndCheckpoint(t, st)
	if restored, err := projector.RestoreFromSnapshot(t.Context(), log); err != nil || !restored {
		t.Fatalf("restore=%v err=%v", restored, err)
	}
	requireObservedFingerprint(t, st, tenantA, strings.Repeat("b", 64))
	requireObservedFingerprint(t, st, tenantB, strings.Repeat("c", 64))
	// A later source without a leaf fingerprint cannot claim the previous leaf.
	unknown := appendObserved(tenantA, observedPQCAssetID, "")
	if err := projector.Apply(t.Context(), unknown); err != nil {
		t.Fatal(err)
	}
	requireObservedFingerprint(t, st, tenantA, "")
	if err := projector.Apply(t.Context(), latest); err != nil {
		t.Fatal(err)
	}
	requireObservedFingerprint(t, st, tenantA, "")
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedFingerprint(t, st, tenantA, "")
	requireObservedFingerprint(t, st, tenantB, strings.Repeat("c", 64))
}

func TestCBOMRejectsInvalidObservedCertificateFingerprint(t *testing.T) {
	st, log := newStore(t), openLog(t)
	projector := projections.New(st)
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendPQCObservationEvent(t, log, tenantA, "tenant.registered", map[string]string{"name": "owner"})
	if err := projector.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, kind, fingerprint string }{
		{"short", "certificate-key", "abcd"},
		{"nonhex", "certificate-key", strings.Repeat("g", 64)},
		{"uppercase", "certificate-key", strings.Repeat("A", 64)},
		{"wrong-kind", "tls-endpoint", strings.Repeat("a", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := certificateObservationPayload(t, observedPQCAssetID, test.fingerprint)
			payload["kind"] = test.kind
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			// Do not poison the immutable log with intentionally malformed input.
			err = projector.Apply(t.Context(), events.Event{TenantID: tenantA, Type: projections.EventCBOMAssetObserved, Sequence: 100, Data: data})
			if err == nil {
				t.Fatal("invalid observed leaf identity was admitted")
			}
			assets, err := st.ListCryptoAssets(t.Context(), tenantA)
			if err != nil || len(assets) != 0 {
				t.Fatalf("rejected observation changed inventory: assets=%+v err=%v", assets, err)
			}
		})
	}
}

func TestCBOMV42SnapshotCannotSkipObservedLeafIdentity(t *testing.T) {
	st, log := newStore(t), openLog(t)
	projector := projections.New(st)
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendPQCObservationEvent(t, log, tenantA, "tenant.registered", map[string]string{"name": "snapshot owner"})
	expected := strings.Repeat("e", 64)
	appendPQCObservationEvent(t, log, tenantA, projections.EventCBOMAssetObserved, certificateObservationPayload(t, observedPQCAssetID, expected))
	if err := projector.ProjectCatchUp(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Snapshot(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Model an externally restored older database in this disposable fixture.
	// Normal startup already rejects old-format writes via the version floor;
	// remove only this fixture's floor so restore must also reject stale bytes.
	if _, err := st.SystemPool().Exec(t.Context(), `ALTER TABLE read_model_snapshots DROP CONSTRAINT read_model_snapshots_format_floor_v22`); err != nil {
		t.Fatal(err)
	}
	// Reproduce the bytes an older binary captured before the new column existed.
	if _, err := st.SystemPool().Exec(t.Context(), `UPDATE read_model_snapshots SET format_version = 42,
  payload = jsonb_set(payload, '{crypto_assets}',
   (SELECT jsonb_agg(item - 'certificate_fingerprint') FROM jsonb_array_elements(payload->'crypto_assets') AS item))
  WHERE tenant_id = $1`, tenantA); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, st)
	if offset, err := st.LatestSnapshotOffset(t.Context()); !errors.Is(err, store.ErrNoSnapshot) || offset != 0 {
		t.Fatalf("old snapshot accepted: offset=%d err=%v", offset, err)
	}
	if restored, err := projector.RestoreFromSnapshot(t.Context(), log); err != nil || restored {
		t.Fatalf("old snapshot should request replay: restored=%v err=%v", restored, err)
	}
	if err := projector.ProjectCatchUp(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedFingerprint(t, st, tenantA, expected)
}
