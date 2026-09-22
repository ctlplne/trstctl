// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const observedPQCAssetID = "f2020000-0000-4000-8000-000000000001"

func appendPQCObservationEvent(t *testing.T, log *events.Log, tenant, kind string, payload any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(t.Context(), events.Event{TenantID: tenant, Type: kind, Data: data}); err != nil {
		t.Fatal(err)
	}
}

func observedPQCAsset(algorithm string) projections.CBOMAssetObserved {
	bits := 0
	if algorithm == "ECDSA" {
		bits = 256
	}
	return projections.CBOMAssetObserved{ID: observedPQCAssetID, Kind: string(cbom.AssetCertKey), Location: "api.example.test:443", Algorithm: algorithm, KeyBits: bits, Strength: "strong", QuantumVulnerable: algorithm == "ECDSA", Reasons: []string{"independent observation fixture"}}
}

func historicalPQCIssuance() projections.LicensedCryptoMigrationAssetCompleted {
	return projections.LicensedCryptoMigrationAssetCompleted{RunID: "pqc-issuance-run", AssetID: observedPQCAssetID, Kind: string(cbom.AssetCertKey), Location: "api.example.test:443", OriginalAlgorithm: "ECDSA", OriginalKeyBits: 256, OriginalQuantumVulnerable: true, TargetAlgorithm: "ML-DSA-65", EffectiveAlgorithm: "hybrid-ML-DSA-44-ECDSA-P256", EffectiveKeyBits: 256, Protocol: "acme", CertificateFingerprint: "issued-but-not-observed"}
}

func historicalPQCRollback() projections.LicensedCryptoMigrationRollbackCompleted {
	return projections.LicensedCryptoMigrationRollbackCompleted{RunID: "pqc-issuance-run", AssetID: observedPQCAssetID, Kind: string(cbom.AssetCertKey), Location: "api.example.test:443", Algorithm: "ECDSA", KeyBits: 256, Strength: "strong", QuantumVulnerable: true, Reasons: []string{"historical rollback requested"}}
}

func requireObservedAlgorithm(t *testing.T, st *store.Store, tenant, algorithm string) {
	t.Helper()
	expectedID := observedPQCAssetID
	if tenant == tenantB {
		expectedID = "f2020000-0000-4000-8000-000000000002"
	}
	assets, err := st.ListCryptoAssets(t.Context(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].ID != expectedID || assets[0].Algorithm != algorithm || assets[0].QuantumVulnerable != (algorithm == "ECDSA") || len(assets[0].Reasons) != 1 || assets[0].Reasons[0] != "independent observation fixture" {
		t.Fatalf("unobserved certificate operation changed endpoint inventory: %+v; want observed %s", assets, algorithm)
	}
}

func TestPQCIssuanceDoesNotReplaceObservedInventory(t *testing.T) {
	st, log := newStore(t), openLog(t)
	projector := projections.New(st)
	// Rebuild the isolated test read model from its own empty log first.
	// newStore does not reset crypto_assets, which has no tenant foreign key.
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendPQCObservationEvent(t, log, tenantA, "tenant.registered", map[string]string{"name": "native endpoint owner"})
	appendPQCObservationEvent(t, log, tenantB, "tenant.registered", map[string]string{"name": "separate endpoint owner"})
	appendPQCObservationEvent(t, log, tenantA, projections.EventCBOMAssetObserved, observedPQCAsset("ECDSA"))
	foreign := observedPQCAsset("ML-DSA-87")
	foreign.ID = "f2020000-0000-4000-8000-000000000002"
	appendPQCObservationEvent(t, log, tenantB, projections.EventCBOMAssetObserved, foreign)
	appendPQCObservationEvent(t, log, tenantA, projections.EventLicensedCryptoMigrationAssetCompleted, historicalPQCIssuance())
	if err := projector.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedAlgorithm(t, st, tenantA, "ECDSA")
	requireObservedAlgorithm(t, st, tenantB, "ML-DSA-87")
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedAlgorithm(t, st, tenantA, "ECDSA")
	requireObservedAlgorithm(t, st, tenantB, "ML-DSA-87")
}

func TestPQCRollbackCannotOverwriteActualObservation(t *testing.T) {
	st, log := newStore(t), openLog(t)
	projector := projections.New(st)
	// Rebuild the isolated test read model from its own empty log first.
	// newStore does not reset crypto_assets, which has no tenant foreign key.
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendPQCObservationEvent(t, log, tenantA, "tenant.registered", map[string]string{"name": "endpoint owner"})
	appendPQCObservationEvent(t, log, tenantA, projections.EventCBOMAssetObserved, observedPQCAsset("ECDSA"))
	appendPQCObservationEvent(t, log, tenantA, projections.EventCBOMAssetObserved, observedPQCAsset("ML-DSA-65"))
	appendPQCObservationEvent(t, log, tenantA, projections.EventLicensedCryptoMigrationRollbackCompleted, historicalPQCRollback())
	if err := projector.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedAlgorithm(t, st, tenantA, "ML-DSA-65")
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedAlgorithm(t, st, tenantA, "ML-DSA-65")
	// A real later observation of the old certificate still changes inventory.
	appendPQCObservationEvent(t, log, tenantA, projections.EventCBOMAssetObserved, observedPQCAsset("ECDSA"))
	if err := projector.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	requireObservedAlgorithm(t, st, tenantA, "ECDSA")
}

func TestPQCHistoricalRollbackDoesNotInventAnAsset(t *testing.T) {
	st, log := newStore(t), openLog(t)
	projector := projections.New(st)
	// Rebuild the isolated test read model from its own empty log first.
	// newStore does not reset crypto_assets, which has no tenant foreign key.
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendPQCObservationEvent(t, log, tenantA, "tenant.registered", map[string]string{"name": "endpoint owner"})
	appendPQCObservationEvent(t, log, tenantA, projections.EventLicensedCryptoMigrationRollbackCompleted, historicalPQCRollback())
	if err := projector.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	assets, err := st.ListCryptoAssets(t.Context(), tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 0 {
		t.Fatalf("historical rollback invented an unobserved asset: %+v", assets)
	}
	if err := projector.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	assets, err = st.ListCryptoAssets(t.Context(), tenantA)
	if err != nil || len(assets) != 0 {
		t.Fatal("rebuild invented an unobserved rollback asset")
	}
}
