// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// countIdentityTransitions reads the identity_transitions read model directly:
// D1/V1's whole point is that the previous tests asserted in-memory maps and
// constant strings while the DATABASE stayed wrong.
func countIdentityTransitions(t *testing.T, st *store.Store, tenantID, identityID, eventType string) int {
	t.Helper()
	var n int
	if err := st.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM identity_transitions WHERE tenant_id = $1 AND identity_id = $2 AND event_type = $3`,
		tenantID, identityID, eventType).Scan(&n); err != nil {
		t.Fatalf("count identity transitions: %v", err)
	}
	return n
}

func mustStatus(t *testing.T, st *store.Store, tenantID, identityID, want string) {
	t.Helper()
	got, err := st.GetIdentity(context.Background(), tenantID, identityID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != want {
		t.Fatalf("identities.status = %q, want %q (the read model diverged from the served answer)", got.Status, want)
	}
}

// TestRenewalFailureProjectsIntoTheReadModel is the regression guard for
// AUD-201 follow-up D1/V1. The commit added identity.renewal_failed /
// identity.renewal_recovered and emitted them from the lifecycle table, but
// never registered them in the projector's lifecycleEventTypes — so ApplyTx
// fell through to nil and a served renewing -> renewal_failed transition
// REPORTED SUCCESS while identities.status stayed 'renewing'. Every
// downstream behaviour then broke: retry edges never fired (from is read off
// the projected status), and accepting the standing certificate computed as
// renewing -> deployed, re-pushing a certificate that was never renewed.
func TestRenewalFailureProjectsIntoTheReadModel(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	ctx := context.Background()
	mustRegisterTenant(t, st, tenantA)

	owner, err := orch.CreateOwner(ctx, tenantA, "team", "payments", "payments@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity := issuedIdentity(t, ctx, st, orch, tenantA, owner.ID, "svc-renewal")
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateDeployed, "deploy"); err != nil {
		t.Fatal(err)
	}
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateRenewing, "renew window"); err != nil {
		t.Fatal(err)
	}
	deploysBefore := countOutboxDestination(t, st, tenantA, "connector.deploy")

	// The failed renewal: served success MUST mean the read model moved.
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateRenewalFailed, "CA unreachable"); err != nil {
		t.Fatalf("renewing -> renewal_failed: %v", err)
	}
	mustStatus(t, st, tenantA, identity.ID, "renewal_failed")
	if n := countIdentityTransitions(t, st, tenantA, identity.ID, "identity.renewal_failed"); n != 1 {
		t.Fatalf("identity_transitions rows for identity.renewal_failed = %d, want 1", n)
	}
	if n := countOutboxDestination(t, st, tenantA, "connector.deploy"); n != deploysBefore {
		t.Fatalf("a failed renewal enqueued connector.deploy (%d -> %d); the previous certificate must not be re-pushed", deploysBefore, n)
	}

	// The RETRY edge exists only if the projected status really moved.
	renewsBefore := countOutboxDestination(t, st, tenantA, "ca.renew")
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateRenewing, "retry"); err != nil {
		t.Fatalf("renewal_failed -> renewing retry edge: %v", err)
	}
	mustStatus(t, st, tenantA, identity.ID, "renewing")
	if n := countOutboxDestination(t, st, tenantA, "ca.renew"); n != renewsBefore+1 {
		t.Fatalf("retry edge enqueued %d ca.renew rows, want exactly one more than %d", n, renewsBefore)
	}

	// Fail again, then ACCEPT THE STANDING CERTIFICATE. This is the edge that
	// used to be impossible: with the projection stuck on 'renewing' the accept
	// computed as renewing -> deployed, emitting identity.renewed WITH the
	// connector.deploy side effect.
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateRenewalFailed, "CA unreachable again"); err != nil {
		t.Fatal(err)
	}
	deploysBefore = countOutboxDestination(t, st, tenantA, "connector.deploy")
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateDeployed, "accept standing certificate"); err != nil {
		t.Fatalf("renewal_failed -> deployed recovery edge: %v", err)
	}
	mustStatus(t, st, tenantA, identity.ID, "deployed")
	if n := countIdentityTransitions(t, st, tenantA, identity.ID, "identity.renewal_recovered"); n != 1 {
		t.Fatalf("identity_transitions rows for identity.renewal_recovered = %d, want 1", n)
	}
	if n := countIdentityTransitions(t, st, tenantA, identity.ID, "identity.renewed"); n != 0 {
		t.Fatalf("accepting the standing certificate recorded identity.renewed %d times; nothing was renewed", n)
	}
	if n := countOutboxDestination(t, st, tenantA, "connector.deploy"); n != deploysBefore {
		t.Fatalf("accepting the standing certificate enqueued connector.deploy (%d -> %d); it must re-push nothing", deploysBefore, n)
	}
}

// TestProjectorDecodesEveryLifecycleEvent is the completeness guard — the
// MECHANISM that failed in D1/V1, not just the two strings. The orchestrator's
// transition table is the source of truth for what can be emitted; every one
// of those event types must be registered with the projector, or a served
// transition reports success while the read model silently stays put.
func TestProjectorDecodesEveryLifecycleEvent(t *testing.T) {
	for eventType := range orchestrator.LifecycleEventTypes() {
		if !projections.LifecycleEventRegistered(eventType) {
			t.Errorf("the lifecycle table emits %q but the projector does not decode it; "+
				"a served transition emitting it will report success while identities.status stays unchanged", eventType)
		}
	}
}
