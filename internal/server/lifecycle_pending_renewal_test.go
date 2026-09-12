// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A real Caddy CA outage left an endpoint.renew retry queued. The next sweep
// created a second rotation; both installed new leaves seconds apart on recovery.
func TestLifecycleSchedulerDoesNotOverlapHostRenewalRetry(t *testing.T) {
	ctx := t.Context()
	h := newIssuanceDispatcherHarness(t)
	owner, err := h.orch.CreateOwnerRecord(ctx, store.Owner{
		TenantID: h.tenant, Kind: store.OwnerTeam, Name: "Caddy recovery owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	target := agentExecutedTarget(t)
	target.TenantID = h.tenant
	legacy := target
	legacy.Config = json.RawMessage(`{"cert_path":"/etc/nginx/tls.crt"}`)
	if err := h.store.UpsertDeploymentTarget(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	attrs, err := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name})
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "retry.example.test", OwnerID: owner.ID, Attributes: attrs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	cert := dispatcherCertificates(t, h)[0]
	if current, err := h.store.GetIdentity(ctx, h.tenant, ident.ID); err != nil || current.Status != string(orchestrator.StateDeployed) {
		t.Fatalf("initial issuance did not reach deployed: status=%s err=%v", current.Status, err)
	}
	dispatchOutbox(t, h, 1)
	if err := h.store.UpsertDeploymentTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: h.store, orch: h.orch, lifecycleRenewBefore: 24 * time.Hour}
	due := cert.NotAfter.Add(-12 * time.Hour)
	if n, err := srv.runLifecycleOnceAt(ctx, due); err != nil || n != 1 {
		t.Fatalf("first renewal queued=%d error=%v", n, err)
	}
	dispatchOutbox(t, h, 1)
	payload, _ := queuedHostRenewal(t, ctx, h)
	if err := srv.completeHostRenewal(ctx, h.tenant, payload, transport.JobOutcomeFailed); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"pending", "processing"} {
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET status=$2 WHERE tenant_id=$1 AND destination='endpoint.renew'`, h.tenant, status)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if n, err := srv.runLifecycleOnceAt(ctx, due.Add(time.Minute)); err != nil || n != 0 {
			t.Fatalf("%s retry overlapped: queued=%d error=%v", status, n, err)
		}
		plan, err := srv.LifecycleAutomationPlan(ctx, h.tenant, due)
		if err != nil || len(plan.Items) != 1 || plan.Items[0].IdentityID != ident.ID ||
			plan.Items[0].Due || plan.Items[0].RenewalSource != "in_flight" || len(plan.Items[0].Blockers) == 0 {
			t.Fatalf("%s retry is not explained as in-flight work: %+v error=%v", status, plan, err)
		}
		// Other lifecycle work (for example expiry notification) may remain
		// pending. The host job must contribute to its actual status bucket.
		if (status == "pending" && plan.Summary.OutboxPending < 1) || (status == "processing" && plan.Summary.OutboxProcessing != 1) {
			t.Fatalf("%s host retry is absent from queue counts: %+v", status, plan.Summary)
		}
		if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "manual retry"); !errors.Is(err, orchestrator.ErrRenewalWorkPending) {
			t.Fatalf("manual renewal guard for %s retry: %v", status, err)
		}
	}
	// Exhausting a job releases the guard. A recorded failure must remain
	// recoverable through a new scheduled attempt once no earlier job can run.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='failed' WHERE tenant_id=$1 AND destination='endpoint.renew'`, h.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := srv.runLifecycleOnceAt(ctx, due.Add(2*time.Minute)); err != nil || n != 1 {
		t.Fatalf("terminal failure prevented a fresh attempt: queued=%d error=%v", n, err)
	}
}
