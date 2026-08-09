// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"context"
	"testing"

	coreorch "trstctl.com/trstctl/internal/orchestrator"
)

type outboxFeatureRecord struct {
	feature string
	action  string
	outcome string
}

func TestLicensedOutboxFeatureObserver(t *testing.T) {
	ctx := context.Background()
	var records []outboxFeatureRecord
	observer := func(feature, action, outcome string, _ float64) {
		records = append(records, outboxFeatureRecord{feature: feature, action: action, outcome: outcome})
	}

	h := &licensedOutboxHandler{observer: observer}
	handled, err := h.DeliverLicensed(ctx, coreorch.Message{Destination: PublishDestination})
	if !handled || err != nil {
		t.Fatalf("publish destination handled=%v err=%v, want true,nil", handled, err)
	}
	assertOutboxFeatureRecord(t, records, outboxFeatureRecord{feature: "pcas_succession", action: "publish", outcome: "success"})

	records = nil
	handled, err = h.DeliverLicensed(ctx, coreorch.Message{Destination: RequestDestination})
	if !handled || err == nil {
		t.Fatalf("request without minter handled=%v err=%v, want true,error", handled, err)
	}
	assertOutboxFeatureRecord(t, records, outboxFeatureRecord{feature: "pcas_succession", action: "mint", outcome: "error"})

	records = nil
	handled, err = h.DeliverLicensed(ctx, coreorch.Message{Destination: KEMRewrapDestination})
	if !handled || err == nil {
		t.Fatalf("rewrap without KEM custody handled=%v err=%v, want true,error", handled, err)
	}
	assertOutboxFeatureRecord(t, records, outboxFeatureRecord{feature: "pcas_kem", action: "rewrap", outcome: "error"})

	records = nil
	handled, err = h.DeliverLicensed(ctx, coreorch.Message{Destination: "other.destination"})
	if handled || err != nil {
		t.Fatalf("foreign destination handled=%v err=%v, want false,nil", handled, err)
	}
	if len(records) != 0 {
		t.Fatalf("foreign destination emitted %d feature records, want 0", len(records))
	}
}

func TestPCASOutboxFeatureActionLabels(t *testing.T) {
	tests := []struct {
		destination string
		feature     string
		action      string
		ok          bool
	}{
		{destination: RequestDestination, feature: "pcas_succession", action: "mint", ok: true},
		{destination: PublishDestination, feature: "pcas_succession", action: "publish", ok: true},
		{destination: KEMRewrapDestination, feature: "pcas_kem", action: "rewrap", ok: true},
		{destination: RecoveryRequestDestination, feature: "pcas_recovery", action: "mint", ok: true},
		{destination: FederationImportDestination, feature: "pcas_federation", action: "import", ok: true},
		{destination: "foreign", ok: false},
	}
	h := &licensedOutboxHandler{}
	for _, tt := range tests {
		feature, action, ok := h.featureAction(tt.destination)
		if feature != tt.feature || action != tt.action || ok != tt.ok {
			t.Errorf("featureAction(%q)=(%q,%q,%v), want (%q,%q,%v)",
				tt.destination, feature, action, ok, tt.feature, tt.action, tt.ok)
		}
	}

	// A configured topic maps to the same feature family as its canonical
	// constant (AUD-7): observability follows the family, not the literal.
	configured := &licensedOutboxHandler{topics: BreadthTopics{KEM: "acme.kem"}.resolved()}
	if feature, action, ok := configured.featureAction("acme.kem"); feature != "pcas_kem" || action != "rewrap" || !ok {
		t.Errorf("featureAction(configured topic)=(%q,%q,%v), want (pcas_kem, rewrap, true)", feature, action, ok)
	}
}

func assertOutboxFeatureRecord(t *testing.T, got []outboxFeatureRecord, want outboxFeatureRecord) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("feature records = %#v, want one %#v", got, want)
	}
	if got[0] != want {
		t.Fatalf("feature record = %#v, want %#v", got[0], want)
	}
}
