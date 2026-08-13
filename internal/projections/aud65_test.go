// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cryptoreadiness"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestAUD65ReadinessActionsSurviveRestartColdReplayAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	authorityA := aud64AuthorityEvents(t, tenantA, false)
	authorityB := aud64AuthorityEvents(t, tenantB, true)

	first := newStore(t)
	aud64Project(t, first, tenantA, "Acme", authorityA)
	aud64Project(t, first, tenantB, "Beta", authorityB)
	actionA := aud65BoundActionEvent(t, first, tenantA, aud64AssetID, "payments-team", "66500000-0000-4000-8000-000000000001")
	actionB := aud65BoundActionEvent(t, first, tenantB, "65000000-0000-4000-8000-000000000005", "foreign-payments-team", "66500000-0000-4000-8000-000000000002")
	projector := projections.New(first)
	for _, event := range []struct {
		tenant string
		value  projections.PQCMigrationCampaignStarted
	}{
		{tenantA, actionA}, {tenantB, actionB},
	} {
		if err := projector.Apply(ctx, aud64Event(t, event.tenant, projections.EventPQCMigrationCampaignStarted, 9, event.value)); err != nil {
			t.Fatalf("project graph-bound action for %s: %v", event.tenant, err)
		}
	}
	beforeRestart, err := cryptoreadiness.Build(ctx, first, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeRestart.Items) != 1 || len(beforeRestart.Items[0].Actions) != 1 || beforeRestart.Items[0].Actions[0].CampaignID != actionA.ID {
		t.Fatalf("tenant A canonical actions = %+v", beforeRestart.Items)
	}
	first.Close()

	restarted, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	afterRestart, err := cryptoreadiness.Build(ctx, restarted, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Close()
	if !reflect.DeepEqual(beforeRestart, afterRestart) {
		t.Fatalf("readiness action changed across DB close/open:\nbefore=%+v\nafter=%+v", beforeRestart, afterRestart)
	}

	// newStore erases the derived read model. Applying the exact immutable
	// authority/action events reconstructs byte-for-byte identical workflow.
	rebuilt := newStore(t)
	aud64Project(t, rebuilt, tenantA, "Acme", authorityA)
	aud64Project(t, rebuilt, tenantB, "Beta", authorityB)
	projector = projections.New(rebuilt)
	if err := projector.Apply(ctx, aud64Event(t, tenantA, projections.EventPQCMigrationCampaignStarted, 9, actionA)); err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, aud64Event(t, tenantB, projections.EventPQCMigrationCampaignStarted, 9, actionB)); err != nil {
		t.Fatal(err)
	}
	afterReplay, err := cryptoreadiness.Build(ctx, rebuilt, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeRestart, afterReplay) {
		t.Fatalf("readiness action changed across cold replay:\nbefore=%+v\nreplay=%+v", beforeRestart, afterReplay)
	}
	if strings.Contains(afterReplay.Items[0].Actions[0].Name, "foreign") || len(afterReplay.Items[0].Actions) != 1 {
		t.Fatalf("foreign tenant action leaked into tenant A: %+v", afterReplay.Items[0].Actions)
	}
}

func aud65BoundActionEvent(t *testing.T, st *store.Store, tenantID, findingID, owner, campaignID string) projections.PQCMigrationCampaignStarted {
	t.Helper()
	g, err := graph.Build(context.Background(), st, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	var row graph.CryptoReadinessRow
	for _, candidate := range g.CryptoReadiness() {
		if candidate.Asset.ID == "crypto:"+findingID {
			row = candidate
			break
		}
	}
	if row.Asset.ID == "" {
		t.Fatalf("no readiness row for %s/%s", tenantID, findingID)
	}
	digest, err := cryptoreadiness.RowDigest(tenantID, row)
	if err != nil {
		t.Fatal(err)
	}
	return projections.PQCMigrationCampaignStarted{
		ID: campaignID, Name: owner + " blocker", OwnerRef: owner,
		Deadline: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC), Wave: "wave-1",
		ReadinessCriteria: []string{"owner approved", "rollback documented"},
		Findings: []projections.PQCMigrationCampaignFinding{{
			FindingID: findingID, FindingDigest: "sha256:" + strings.Repeat("a", 64),
			ReadinessDigest: digest, Kind: "public-key", Location: "lb-edge", Algorithm: "RSA", KeyBits: 1024,
		}},
	}
}
