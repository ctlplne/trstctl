// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Disabling a destination pauses the agent-claimable work queued for it: a deploy
// stamped with that target's lane is handed to no agent while the target is
// disabled, is never dropped, and is claimable again once the target is enabled.
// A sibling target that stays enabled keeps flowing (DP2-028).
func TestClaimAgentJobsPausesWorkForDisabledDeploymentTarget(t *testing.T) {
	ctx := context.Background()
	st, tenantID := newStore(t), tenantA
	seedAgentJobTenant(t, ctx, st, tenantID)
	const agent = "11111111-1111-1111-1111-111111111111"
	const paused, flowing = "61616161-0000-4000-8000-000000000001", "61616161-0000-4000-8000-000000000002"
	now := time.Now().UTC()
	upsert := func(id string, enabled bool, rev string) {
		t.Helper()
		if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return st.ApplyDeploymentTargetUpsertedTx(ctx, tx, store.DeploymentTarget{
				ID: id, TenantID: tenantID, Name: "edge-" + rev, Type: "apache", Config: []byte(`{}`),
				Enabled: enabled, EnabledSet: true,
			}, rev, now)
		}); err != nil {
			t.Fatalf("upsert target %s: %v", id, err)
		}
	}
	upsert(paused, false, "rev-paused-off")
	upsert(flowing, true, "rev-flowing-on")
	for _, target := range []string{paused, flowing} {
		if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx,
				`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane)
				 VALUES ($1, 'connector.deploy', $2, $3, $4)`,
				tenantID, []byte(`{"target_id":"`+target+`"}`), "deploy:"+target, store.ConnectorTargetLanePrefix+target)
			return err
		}); err != nil {
			t.Fatalf("seed deploy for %s: %v", target, err)
		}
	}

	claimed, err := st.ClaimAgentJobs(ctx, tenantID, agent, []string{"connector.deploy"}, nil, 5, time.Minute, now)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed %d jobs, want only the enabled target's deploy", len(claimed))
	}
	// The paused row is still there, untouched, for when the target comes back.
	var pending int
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox
		  WHERE tenant_id = $1::uuid AND effect_lane = $2 AND status = 'pending' AND claimed_by_agent_id IS NULL`,
		tenantID, store.ConnectorTargetLanePrefix+paused).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("paused deploy rows = %d, want 1 still pending and unclaimed", pending)
	}

	upsert(paused, true, "rev-paused-on")
	resumed, err := st.ClaimAgentJobs(ctx, tenantID, agent, []string{"connector.deploy"}, nil, 5, time.Minute, now.Add(time.Second))
	if err != nil {
		t.Fatalf("claim after enable: %v", err)
	}
	if len(resumed) != 1 {
		t.Fatalf("claimed %d jobs after enabling, want the paused deploy", len(resumed))
	}
}
