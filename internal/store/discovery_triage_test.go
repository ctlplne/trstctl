package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/store"
)

func TestDiscoveryFindingTriageProjectionAndTenantScope(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	findingID := uuid(tenantA, 101)
	seedDiscoveryFinding(t, s, tenantA, findingID)

	got, err := s.GetDiscoveryFinding(ctx, tenantA, findingID)
	if err != nil {
		t.Fatalf("GetDiscoveryFinding tenant A: %v", err)
	}
	if got.TriageStatus != string(discovery.TriageUnmanaged) {
		t.Fatalf("initial triage status = %q, want unmanaged", got.TriageStatus)
	}
	if _, err := s.GetDiscoveryFinding(ctx, tenantB, findingID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-tenant GetDiscoveryFinding = %v, want pgx.ErrNoRows", err)
	}

	managedID := uuid(tenantA, 202)
	changedAt := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDiscoveryFindingTriageChangedTx(ctx, tx, store.DiscoveryFindingTriageChange{
			TenantID: tenantA, FindingID: findingID, Status: string(discovery.TriageManaged),
			Actor: "alice@example.test", Reason: "owned by platform team",
			ManagedIdentityID: &managedID, ChangedAt: changedAt,
			MetadataPatch: []byte(`{"owner":"platform","team":"certops","tags":["internet","tls"]}`),
		})
	}); err != nil {
		t.Fatalf("project managed triage: %v", err)
	}
	got, err = s.GetDiscoveryFinding(ctx, tenantA, findingID)
	if err != nil {
		t.Fatalf("GetDiscoveryFinding after triage: %v", err)
	}
	if got.TriageStatus != string(discovery.TriageManaged) {
		t.Fatalf("triage status = %q, want managed", got.TriageStatus)
	}
	if got.ManagedIdentityID == nil || *got.ManagedIdentityID != managedID {
		t.Fatalf("managed identity = %v, want %q", got.ManagedIdentityID, managedID)
	}
	if got.TriageActor != "alice@example.test" || got.TriageReason != "owned by platform team" {
		t.Fatalf("triage actor/reason = %q/%q", got.TriageActor, got.TriageReason)
	}
	if got.TriagedAt == nil || !got.TriagedAt.Equal(changedAt) {
		t.Fatalf("triaged_at = %v, want %v", got.TriagedAt, changedAt)
	}
	var metadata struct {
		Owner string   `json:"owner"`
		Team  string   `json:"team"`
		Tags  []string `json:"tags"`
	}
	if err := json.Unmarshal(got.Metadata, &metadata); err != nil {
		t.Fatalf("metadata decode after triage: %v", err)
	}
	if metadata.Owner != "platform" || metadata.Team != "certops" || !reflect.DeepEqual(metadata.Tags, []string{"internet", "tls"}) {
		t.Fatalf("metadata after triage = %+v, want owner/team/tags", metadata)
	}

	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return s.ApplyDiscoveryFindingTriageChangedTx(ctx, tx, store.DiscoveryFindingTriageChange{
			TenantID: tenantB, FindingID: findingID, Status: string(discovery.TriageDismissed),
			Actor: "mallory@example.test", ChangedAt: changedAt,
		})
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-tenant triage projection = %v, want pgx.ErrNoRows", err)
	}
}

func seedDiscoveryFinding(t *testing.T, s *store.Store, tenantID, findingID string) {
	t.Helper()
	ctx := context.Background()
	sourceID := uuid(tenantID, 102)
	runID := uuid(tenantID, 103)
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantID, Kind: "network", Name: "edge-net",
			Config: []byte(`{}`), CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: tenantID, SourceID: sourceID, Status: "queued", CreatedAt: time.Now(),
		}); err != nil {
			return err
		}
		return s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
			ID: findingID, TenantID: tenantID, RunID: runID, SourceID: sourceID,
			Kind: "certificate", Ref: "edge.example.test:443", Provenance: "netscan",
			Fingerprint: "fp-" + findingID, RiskScore: 40, Metadata: []byte(`{}`),
			DiscoveredAt: time.Now(),
		})
	}); err != nil {
		t.Fatalf("seed discovery finding: %v", err)
	}
}
