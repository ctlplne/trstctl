// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

// A91: the gauge meters reconcile against records independent of the counter
// that produced them. agents recounts from agent lifecycle receipts (first
// heartbeat, offboarding), secrets_stored from application-secret mutation
// receipts, tenants from the core tenant registration projection. A meter with
// no such record says so by name; a checked gauge that disagrees blocks the
// signature exactly as certificates_issued always has.
func TestGaugeMetersReconcileAgainstIndependentRecordsA91(t *testing.T) {
	store, cs := newBillingStoreOn(t, "billing_gauge_reconcile_a91")
	billingHistory(t, cs)
	ctx := context.Background()
	at := time.Date(2026, 10, 23, 6, 0, 0, 0, time.UTC)
	before, after := at.Add(-time.Hour), at.Add(time.Hour)

	// Two agents seen before the period end, one of them offboarded before it;
	// a third is only seen afterwards. The agents table itself is never read.
	if err := cs.WithTenant(ctx, quotaTenant, func(tx pgx.Tx) error {
		seenBefore, seenAfter := before, after
		for _, a := range []corestore.Agent{
			{ID: "aaaaaaaa-0000-4000-8000-000000000001", TenantID: quotaTenant, Name: "live", Status: "active", LastSeenAt: &seenBefore, CreatedAt: before},
			{ID: "aaaaaaaa-0000-4000-8000-000000000002", TenantID: quotaTenant, Name: "gone", Status: "active", LastSeenAt: &seenBefore, CreatedAt: before},
			{ID: "aaaaaaaa-0000-4000-8000-000000000003", TenantID: quotaTenant, Name: "later", Status: "active", LastSeenAt: &seenAfter, CreatedAt: after},
		} {
			if err := cs.ApplyAgentHeartbeatTx(ctx, tx, a); err != nil {
				return err
			}
		}
		gone := before.Add(30 * time.Minute)
		return cs.ApplyAgentOffboardedTx(ctx, tx, corestore.Agent{ID: "aaaaaaaa-0000-4000-8000-000000000002", TenantID: quotaTenant, Name: "gone", OffboardedAt: &gone, OffboardedBy: "operator", OffboardReason: "decommissioned"})
	}); err != nil {
		t.Fatal(err)
	}
	agents, err := store.GaugeAt(ctx, quotaTenant, usage.MeterAgents, at)
	if err != nil || !agents.Checked || agents.Count != 1 {
		t.Fatalf("agents recount = %+v %v, want 1 checked (live before, gone offboarded, later not yet seen)", agents, err)
	}

	// Application secrets: created a and b, deleted b, all before the period
	// end; one created after. Receipts, not the secret_store table.
	if err := cs.WithTenant(ctx, quotaTenant, func(tx pgx.Tx) error {
		for i, r := range []struct {
			name, action string
			version      int
			at           time.Time
		}{
			{"a", "create", 1, before}, {"b", "create", 1, before}, {"b", "delete", 0, before.Add(10 * time.Minute)}, {"c", "create", 1, after},
		} {
			if _, err := tx.Exec(ctx, `INSERT INTO application_secret_mutation_receipts
				(tenant_id, event_id, semantic_sha256, request_binding, secret_name, action, result_version, result_created_at, result_updated_at, applied_at)
				VALUES ($1, gen_random_uuid(), repeat('a', 64), repeat('b', 64), $2, $3, $4, $5, $5, $5)`,
				quotaTenant, r.name, r.action, r.version, r.at.Add(time.Duration(i)*time.Second)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	secrets, err := store.GaugeAt(ctx, quotaTenant, usage.MeterSecretsStored, at)
	if err != nil || !secrets.Checked || secrets.Count != 1 {
		t.Fatalf("secrets recount = %+v %v, want 1 checked (a live, b deleted, c later)", secrets, err)
	}
	// A connector credential has no mutation receipt: the recount still names
	// the number but the line is no longer vouched for as independent.
	if err := cs.WithTenant(ctx, quotaTenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO credentials (id, tenant_id, scope, ref, name, sealed) VALUES (gen_random_uuid(), $1, 'connector', 'f5-1', 'password', '\x00')`, quotaTenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	secrets, err = store.GaugeAt(ctx, quotaTenant, usage.MeterSecretsStored, at)
	if err != nil || secrets.Checked || secrets.Count != 2 || !strings.Contains(secrets.Note, "credential") {
		t.Fatalf("secrets recount with a connector credential = %+v %v, want unchecked with both halves named", secrets, err)
	}

	tenants, err := store.GaugeAt(ctx, quotaTenant, usage.MeterTenants, at)
	if err != nil || !tenants.Checked || tenants.Count != 1 {
		t.Fatalf("tenants recount = %+v %v, want 1 from the core registration", tenants, err)
	}
	if absent, err := store.GaugeAt(ctx, "44444444-4444-4444-8444-444444444444", usage.MeterTenants, at); err != nil || !absent.Checked || absent.Count != 0 {
		t.Fatalf("unregistered tenant recount = %+v %v, want 0 checked", absent, err)
	}
	certs, err := store.GaugeAt(ctx, quotaTenant, usage.MeterCertificatesStored, at)
	if err != nil || certs.Checked || !strings.Contains(certs.Note, "revocation") {
		t.Fatalf("certificates_stored recount = %+v %v, want unchecked with the missing-record reason", certs, err)
	}

	// The document lines: a matching checked gauge, a diverging one, and the
	// unchecked meter, through the same reconciliation the evidence route uses.
	period := billing.EvidencePeriod{CustomerID: quotaTenant, Start: before, End: at}
	lines := []billing.EvidenceLine{
		{Meter: usage.MeterCertificatesIssued, Value: 0},
		{Meter: usage.MeterAgents, Value: 1},
		{Meter: usage.MeterTenants, Value: 2},
		{Meter: usage.MeterCertificatesStored, Value: 7},
	}
	recon, err := billing.ReconcileEvidence(ctx, store, period, lines)
	if err != nil {
		t.Fatal(err)
	}
	byMeter := map[string]billing.ReconciliationLine{}
	for _, line := range recon {
		byMeter[line.Meter] = line
	}
	if l := byMeter[usage.MeterAgents]; !l.Checked || !l.Matches || l.EventHistory != 1 || l.Source == "" {
		t.Fatalf("agents line = %+v, want checked and matching from the receipts source", l)
	}
	if l := byMeter[usage.MeterTenants]; !l.Checked || l.Matches || l.EventHistory != 1 || l.Metered != 2 {
		t.Fatalf("tenants line = %+v, want checked and diverging (metered 2, registry 1)", l)
	}
	if l := byMeter[usage.MeterCertificatesStored]; l.Checked || !strings.Contains(l.Note, "revocation") {
		t.Fatalf("certificates_stored line = %+v, want unchecked with its reason", l)
	}
}
