// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestHostAssignmentSurvivesLifecycleCrashRecovery(t *testing.T) {
	s, log := newStore(t), openLog(t)
	ctx := t.Context()
	const identityID = "44444444-4444-4444-8444-44444444a079"
	const hostID = "44444444-4444-4444-8444-44444444a001"
	seedLifecycleIdentity(t, s, tenantA, identityID, orchestrator.StateIssued)
	if err := s.UpsertAgent(ctx, store.Agent{ID: hostID, TenantID: tenantA, Name: "application-host", Status: "active", Roles: []string{"host"}}); err != nil {
		t.Fatal(err)
	}
	ob := orchestrator.NewOutbox(s)
	orch := orchestrator.NewOrchestrator(log, s, ob, orchestrator.WithSideEffectRoleClassifier(func(string, []byte) string { return "host" }))
	raw := []byte(`{"connector":"nginx","target_config":{"required_agent_id":"` + hostID + `"}}`)
	if err := orch.TransitionWithSideEffectPayloadTransform(ctx, tenantA, identityID, orchestrator.StateDeployed, "deploy to assigned host", raw,
		func(context.Context, orchestrator.SideEffectPayloadContext) ([]byte, error) {
			return []byte(`{"sealed":"opaque fixture"}`), nil
		}); err != nil {
		t.Fatal(err)
	}
	var key string
	if err := log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.Type != "identity.deployed" {
			return nil
		}
		var event struct {
			SideEffect struct {
				AgentID string `json:"required_agent_id"`
				Key     string `json:"idempotency_key"`
			} `json:"side_effect"`
		}
		if err := json.Unmarshal(ev.Data, &event); err != nil {
			return err
		}
		if event.SideEffect.AgentID != hostID {
			t.Fatalf("event lost host assignment: %q", event.SideEffect.AgentID)
		}
		key = event.SideEffect.Key
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if key == "" {
		t.Fatal("deployment event missing")
	}
	if _, err := s.SystemPool().Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key); err != nil {
		t.Fatal(err)
	}
	// Recovery has no classifier. It must use the immutable event, even when
	// the transformed payload no longer exposes any routing configuration.
	restarted := orchestrator.NewOrchestrator(log, s, ob)
	if count, err := restarted.ReconcileOutbox(ctx, log); err != nil || count != 1 {
		t.Fatalf("reconcile = %d, %v", count, err)
	}
	var got string
	if err := s.SystemPool().QueryRow(ctx, `SELECT required_agent_id::text FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, tenantA, key).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != hostID {
		t.Fatalf("recovery rerouted to %q", got)
	}
}
