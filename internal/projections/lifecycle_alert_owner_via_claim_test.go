// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/lifecycle"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A certificate discovery observed at a listener carries no owner of its own. Once
// an operator claims its finding into a managed identity owned by a team, the
// expiry alert for that certificate must name that team, not "no owner" (DP2-020).
func TestExpiryAlertNamesTheOwnerOfTheClaimedIdentity(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	m, _ := newLifecycleManager(t, s, lifecycle.Config{RenewBefore: time.Hour, AlertBefore: 7 * 24 * time.Hour, TTL: 90 * 24 * time.Hour})
	now := time.Now().UTC().Truncate(time.Microsecond)
	const (
		ownerID    = "72727272-0000-4000-8000-000000000001"
		identityID = "72727272-0000-4000-8000-000000000002"
		sourceID   = "72727272-0000-4000-8000-000000000003"
		runID      = "72727272-0000-4000-8000-000000000004"
		findingID  = "72727272-0000-4000-8000-000000000005"
		certID     = "72727272-0000-4000-8000-000000000006"
		fp         = "fp-observed-apache-baseline"
	)
	soon := now.Add(24 * time.Hour)
	managed := identityID
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyOwnerCreatedTx(ctx, tx, store.Owner{ID: ownerID, TenantID: tenantA, Kind: "team", Name: "Partner Lab Web Team", Email: "web-team@partner-lab.example.com", CreatedAt: now}); err != nil {
			return err
		}
		if err := s.ApplyIdentityCreatedTx(ctx, tx, store.Identity{ID: identityID, TenantID: tenantA, Kind: store.KindX509Certificate, Name: "apache.partner-lab.example.com", OwnerID: ownerID, Status: "draft", CreatedAt: now}); err != nil {
			return err
		}
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{ID: sourceID, TenantID: tenantA, Kind: "network", Name: "lab-listeners", Config: []byte(`{"targets":["127.0.0.1:10443"]}`), CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: tenantA, SourceID: sourceID, Status: "queued", RequestedBy: "test", CreatedAt: now}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{ID: findingID, TenantID: tenantA, RunID: runID, SourceID: sourceID, Kind: "certificate", Ref: "127.0.0.1:10443", Provenance: "network", Fingerprint: fp, Metadata: []byte(`{}`), DiscoveredAt: now}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryFindingTriageChangedTx(ctx, tx, store.DiscoveryFindingTriageChange{TenantID: tenantA, FindingID: findingID, Status: "managed", ManagedIdentityID: &managed, Actor: "operator", Reason: "take the listener under management", ChangedAt: now}); err != nil {
			return err
		}
		// The observed certificate itself: no owner column of its own.
		return s.ApplyCertificateRecordedTx(ctx, tx, store.Certificate{
			ID: certID, TenantID: tenantA, Subject: "CN=apache.partner-lab.example.com", SANs: []string{"apache.partner-lab.example.com"},
			Issuer: "CN=Old Vendor CA", Serial: "01", Fingerprint: fp, KeyAlgorithm: "RSA-2048",
			NotBefore: &now, NotAfter: &soon, DeploymentLocation: "127.0.0.1:10443", Source: "discovery:network",
			CertificateDER: []byte("der"), CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nZGVy\n-----END CERTIFICATE-----\n"),
			Status: "active", CreatedAt: now,
		})
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	n, err := m.AlertExpiring(ctx, tenantA)
	if err != nil {
		t.Fatalf("AlertExpiring: %v", err)
	}
	if n != 1 {
		t.Fatalf("alerted %d certificates, want 1", n)
	}
	pending, err := orchestrator.NewOutbox(s).Pending(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	var alerted notify.Alert
	found := false
	for _, e := range pending {
		if e.Destination == notify.DestinationExpiry {
			if err := json.Unmarshal(e.Payload, &alerted); err != nil {
				t.Fatalf("decode alert: %v", err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no expiry alert was queued")
	}
	if alerted.OwnerName != "Partner Lab Web Team" || alerted.OwnerEmail != "web-team@partner-lab.example.com" {
		t.Fatalf("alert owner = %q <%s>, want the claimed identity's owner Partner Lab Web Team <web-team@partner-lab.example.com>", alerted.OwnerName, alerted.OwnerEmail)
	}
}
