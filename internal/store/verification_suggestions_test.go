// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A214: a scan that saw, at host:port, a leaf trstctl delivered to a target
// suggests that address with the finding as evidence; a leaf delivered
// elsewhere, a purged leaf, a non-address ref and another tenant's finding
// suggest nothing.
func TestVerificationAddressSuggestionsComeFromScansThatSawTheDeliveredLeaf(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	now := time.Date(2026, 10, 28, 7, 0, 0, 0, time.UTC)
	delivered, elsewhere, purged := strings.Repeat("a1", 32), strings.Repeat("b2", 32), strings.Repeat("c3", 32)
	receipt := func(tenant string, n int, target, fingerprint, destination, status string, at time.Time) {
		t.Helper()
		outbox := int64(2140 + n)
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: uuid(tenant, 2140+n), TenantID: tenant, OutboxID: &outbox, Destination: destination,
				Connector: "nginx", Target: target, Fingerprint: fingerprint, Status: status,
				IdempotencyKey: "a214-" + target + "-" + status, CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	receipt(tenantA, 1, "web-1", delivered, "connector.deploy", "delivered", now)
	receipt(tenantA, 2, "web-2", elsewhere, "connector.deploy", "delivered", now)
	receipt(tenantA, 3, "web-1", purged, "connector.deploy", "verified", now)
	receipt(tenantA, 4, "web-1", purged, "endpoint.purge", "purged", now.Add(time.Minute))

	// Each sighting is its own sweep run: one run records an address and leaf
	// once.
	finding := func(tenant string, n int, ref, fingerprint string) {
		t.Helper()
		sourceID, runID := uuid(tenant, 2150), uuid(tenant, 2170+n)
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if n == 0 {
				if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
					ID: sourceID, TenantID: tenant, Kind: "network", Name: "a214-sweep", Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					return err
				}
			}
			if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: tenant, SourceID: sourceID, Status: "queued", CreatedAt: now}); err != nil {
				return err
			}
			return s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
				ID: uuid(tenant, 2160+n), TenantID: tenant, RunID: runID, SourceID: sourceID, Kind: "x509_certificate",
				Ref: ref, Provenance: "a214", Fingerprint: fingerprint, Metadata: []byte(`{}`),
				DiscoveredAt: now.Add(time.Duration(n) * time.Minute),
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	finding(tenantA, 0, "10.0.0.5:8443", delivered)
	finding(tenantA, 1, "10.0.0.6:443", elsewhere)
	finding(tenantA, 2, "10.0.0.7:443", purged)
	finding(tenantA, 3, "/etc/nginx/a.crt", delivered)
	finding(tenantA, 4, "10.0.0.5:8443", delivered)
	finding(tenantB, 0, "10.0.0.9:443", delivered)

	got, err := s.VerificationAddressSuggestions(ctx, tenantA, "nginx", "web-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Address != "10.0.0.5:8443" || len(got[0].Evidence) != 2 ||
		got[0].Evidence[0].FindingID != uuid(tenantA, 2164) || got[0].Evidence[0].Fingerprint != delivered {
		t.Fatalf("suggestions = %+v; want 10.0.0.5:8443 with its two findings, newest first", got)
	}
	if other, err := s.VerificationAddressSuggestions(ctx, tenantB, "nginx", "web-1"); err != nil || len(other) != 0 {
		t.Fatalf("tenant B suggestions = %+v (%v); want none", other, err)
	}
}
