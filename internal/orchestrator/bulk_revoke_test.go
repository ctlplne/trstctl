package orchestrator_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestBulkRevokeMixedSetIsIdempotentAndTenantScoped(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	ctx := context.Background()
	mustRegisterTenant(t, st, tenantA)
	mustRegisterTenant(t, st, tenantB)

	ownerA, err := orch.CreateOwner(ctx, tenantA, "team", "payments", "payments@example.test")
	if err != nil {
		t.Fatal(err)
	}
	ownerB, err := orch.CreateOwner(ctx, tenantB, "team", "platform", "platform@example.test")
	if err != nil {
		t.Fatal(err)
	}

	revokeMe := issuedIdentity(t, ctx, st, orch, tenantA, ownerA.ID, "svc-a")
	alreadyRevoked := issuedIdentity(t, ctx, st, orch, tenantA, ownerA.ID, "svc-b")
	if err := orch.Transition(ctx, tenantA, alreadyRevoked.ID, orchestrator.StateRevoked, string(crypto.RevocationReasonKeyCompromise)); err != nil {
		t.Fatal(err)
	}
	otherTenant := issuedIdentity(t, ctx, st, orch, tenantB, ownerB.ID, "svc-c")
	missingID := uuid.NewString()

	result, err := orch.BulkRevoke(ctx, tenantA, orchestrator.BulkRevokeRequest{
		IDs:    []string{revokeMe.ID, alreadyRevoked.ID, otherTenant.ID, missingID},
		Reason: string(crypto.RevocationReasonKeyCompromise),
	})
	if err != nil {
		t.Fatalf("BulkRevoke: %v", err)
	}
	if result.TotalMatched != 2 || result.TotalRevoked != 1 || result.TotalSkipped != 1 || result.TotalFailed != 2 {
		t.Fatalf("bulk result = %+v, want matched=2 revoked=1 skipped=1 failed=2", result)
	}
	assertBulkItem(t, result.Items, revokeMe.ID, "revoked")
	assertBulkItem(t, result.Items, alreadyRevoked.ID, "skipped")
	assertBulkItem(t, result.Items, otherTenant.ID, "failed")
	assertBulkItem(t, result.Items, missingID, "failed")

	gotA, err := st.GetIdentity(ctx, tenantA, revokeMe.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotA.Status != string(orchestrator.StateRevoked) {
		t.Fatalf("tenant A identity status = %q, want revoked", gotA.Status)
	}
	gotB, err := st.GetIdentity(ctx, tenantB, otherTenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotB.Status != string(orchestrator.StateIssued) {
		t.Fatalf("cross-tenant identity status = %q, want still issued", gotB.Status)
	}
	before := countOutboxDestination(t, st, tenantA, "revocation.publish")
	if before != 2 {
		t.Fatalf("tenant A revocation outbox rows = %d, want 2 (one pre-revoked, one bulk-revoked)", before)
	}

	replay, err := orch.BulkRevoke(ctx, tenantA, orchestrator.BulkRevokeRequest{
		IDs:    []string{revokeMe.ID, alreadyRevoked.ID, otherTenant.ID, missingID},
		Reason: string(crypto.RevocationReasonKeyCompromise),
	})
	if err != nil {
		t.Fatalf("BulkRevoke replay: %v", err)
	}
	if replay.TotalRevoked != 0 {
		t.Fatalf("replay revoked %d identities, want 0 new effects", replay.TotalRevoked)
	}
	after := countOutboxDestination(t, st, tenantA, "revocation.publish")
	if after != before {
		t.Fatalf("replay outbox rows = %d, want still %d", after, before)
	}
}

func issuedIdentity(t *testing.T, ctx context.Context, st *store.Store, orch *orchestrator.Orchestrator, tenantID, ownerID, name string) store.Identity {
	t.Helper()
	it, err := orch.CreateIdentity(ctx, tenantID, store.Identity{
		Kind:    store.KindX509Certificate,
		Name:    name,
		OwnerID: ownerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantID, it.ID, orchestrator.StateIssued, "test issue"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetIdentity(ctx, tenantID, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assertBulkItem(t *testing.T, items []orchestrator.BulkRevokeItem, id, status string) {
	t.Helper()
	for _, item := range items {
		if item.ID == id {
			if item.Status != status {
				t.Fatalf("bulk item %s status = %q, want %q (item %+v)", id, item.Status, status, item)
			}
			return
		}
	}
	t.Fatalf("bulk result missing item %s: %+v", id, items)
}

func countOutboxDestination(t *testing.T, st *store.Store, tenantID, destination string) int {
	t.Helper()
	var n int
	if err := st.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		tenantID, destination).Scan(&n); err != nil {
		t.Fatalf("count outbox destination: %v", err)
	}
	return n
}
