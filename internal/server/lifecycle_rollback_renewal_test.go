// SPDX-License-Identifier: MPL-2.0

package server

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// Restoring a ten-minute leaf after renewal exposed a real Caddy outage: the
// scheduler kept the successor's deadline until the restored leaf had expired.
func TestLifecycleSchedulerUsesTheRestoredCertificateDeadline(t *testing.T) {
	ctx := t.Context()
	h := newIssuanceDispatcherHarness(t)
	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: "Rollback owner"})
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.store.CreateIdentity(ctx, store.Identity{TenantID: h.tenant, Kind: store.KindX509Certificate, Name: "restore.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	ident.Status = "deployed"
	if err := h.store.UpsertIdentity(ctx, ident); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	issuedAt := now.Add(-10 * time.Minute)
	var restored store.Certificate
	for i, lifetime := range []time.Duration{time.Hour, 2 * time.Minute} {
		end := now.Add(lifetime)
		fingerprint := strings.Repeat([]string{"a", "b"}[i], 64)
		cert, err := h.store.UpsertCertificate(ctx, store.Certificate{TenantID: h.tenant, OwnerID: &owner.ID,
			SANs: []string{ident.Name}, Serial: fingerprint[:16], Fingerprint: fingerprint,
			Source: "issued", Status: "active", NotBefore: &issuedAt, NotAfter: &end})
		if err != nil {
			t.Fatal(err)
		}
		destination, status := "connector.deploy", "verified"
		if i == 1 {
			destination, status, restored = "connector.rollback", "rolled_back", cert
		}
		if _, err := h.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
			IdentityID: &ident.ID, Destination: destination, Status: status, Connector: "caddy", Target: "restore-target",
			Fingerprint: fingerprint, IdempotencyKey: destination,
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := &Server{store: h.store, orch: h.orch, lifecycleRenewBefore: 5 * time.Minute}
	plan, err := srv.LifecycleAutomationPlan(ctx, h.tenant, now)
	if err != nil || len(plan.Items) != 1 || plan.Items[0].CertificateID != restored.ID || !plan.Items[0].Due {
		t.Fatalf("restored certificate is not due in plan: %+v error=%v", plan, err)
	}
	if queued, err := srv.runLifecycleOnceAt(ctx, now); err != nil || queued != 1 {
		t.Fatalf("restored leaf must renew before expiry: queued=%d error=%v", queued, err)
	}
	if queued, err := srv.runLifecycleOnceAt(ctx, now.Add(time.Second)); err != nil || queued != 0 {
		t.Fatalf("duplicate renewal after restore: queued=%d error=%v", queued, err)
	}
}
