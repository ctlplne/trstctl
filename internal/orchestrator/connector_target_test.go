package orchestrator_test

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestBindIdentityDeploymentTargetProjectsRoutingAttributes(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))

	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "journey-owner", "")
	if err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "journey.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"environment":"prod"}`),
	})
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{
		Name: "edge/prod/payments", Type: "nginx", Config: json.RawMessage(`{"credential_ref":"secret://connectors/nginx"}`),
	})
	if err != nil {
		t.Fatalf("UpsertDeploymentTarget: %v", err)
	}
	bound, err := orch.BindIdentityDeploymentTarget(ctx, tenantA, identity.ID, target)
	if err != nil {
		t.Fatalf("BindIdentityDeploymentTarget: %v", err)
	}

	var attrs map[string]string
	if err := json.Unmarshal(bound.Attributes, &attrs); err != nil {
		t.Fatalf("decode attributes: %v (%s)", err, bound.Attributes)
	}
	for key, want := range map[string]string{
		"environment":          "prod",
		"connector":            "nginx",
		"deployment_connector": "nginx",
		"target":               "edge/prod/payments",
		"deployment_target":    "edge/prod/payments",
		"deployment_target_id": target.ID,
	} {
		if attrs[key] != want {
			t.Fatalf("attrs[%s] = %q, want %q in %s", key, attrs[key], want, bound.Attributes)
		}
	}
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateIssued, "issue after connector target binding"); err != nil {
		t.Fatalf("Transition issued after binding: %v", err)
	}
}
