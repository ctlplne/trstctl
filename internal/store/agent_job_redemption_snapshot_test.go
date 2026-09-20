// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

// The resolver may run between the initial read and grant. A still-live lease
// cannot release secrets after cancellation, reassignment or target disablement.
func TestHostRedemptionGrantRechecksResolvedJobAndCurrentAuthority(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	tenantID := tenantA
	const agentID = "bbbbbbbb-0000-0000-0000-000000000001"
	const targetID = "bbbbbbbb-0000-0000-0000-000000000002"
	for _, mode := range []string{"unchanged", "cancelled", "different payload", "different destination", "different idempotency key", "different assignment", "disabled target", "reassigned target", "missing target", "expired lease"} {
		t.Run(mode, func(t *testing.T) {
			config := []byte(`{"executor":"agent","required_agent_id":"` + agentID + `"}`)
			if err := st.UpsertDeploymentTarget(ctx, store.DeploymentTarget{ID: targetID, TenantID: tenantID, Name: "java", Type: "java-keystore", Config: config, Enabled: true, EnabledSet: true}); err != nil {
				t.Fatal(err)
			}
			payload := []byte(`{"connector":"java-keystore","target_id":"` + targetID + `"}`)
			var id int64
			if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `INSERT INTO outbox(tenant_id,destination,payload,idempotency_key,required_agent_id,required_agent_role) VALUES($1,'endpoint.renew',$2,$3,$4,'host') RETURNING id`, tenantID, payload, mode, agentID).Scan(&id)
			}); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			jobs, err := st.ClaimAgentJobs(ctx, tenantID, agentID, []string{"endpoint.renew"}, []string{"host"}, 1, time.Minute, now)
			if err != nil || len(jobs) != 1 || jobs[0].ID != id {
				t.Fatalf("claim: %+v %v", jobs, err)
			}
			job, held, err := st.GetAgentJobForRedemption(ctx, tenantID, agentID, id, now)
			if err != nil || !held {
				t.Fatalf("snapshot: %v", err)
			}
			if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				var err error
				switch mode {
				case "cancelled":
					_, err = tx.Exec(ctx, `UPDATE outbox SET status='cancelled' WHERE tenant_id=$1 AND id=$2`, tenantID, id)
				case "different payload":
					_, err = tx.Exec(ctx, `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, id, []byte(`{"changed":true}`))
				case "different destination":
					_, err = tx.Exec(ctx, `UPDATE outbox SET destination='connector.test' WHERE tenant_id=$1 AND id=$2`, tenantID, id)
				case "different idempotency key":
					_, err = tx.Exec(ctx, `UPDATE outbox SET idempotency_key='changed-key' WHERE tenant_id=$1 AND id=$2`, tenantID, id)
				case "different assignment":
					_, err = tx.Exec(ctx, `UPDATE outbox SET required_agent_id=NULL WHERE tenant_id=$1 AND id=$2`, tenantID, id)
				case "disabled target":
					_, err = tx.Exec(ctx, `UPDATE deployment_targets SET enabled=false WHERE tenant_id=$1 AND id=$2`, tenantID, targetID)
				case "reassigned target":
					_, err = tx.Exec(ctx, `UPDATE deployment_targets SET config=$3::jsonb WHERE tenant_id=$1 AND id=$2`, tenantID, targetID, []byte(`{"executor":"agent","required_agent_id":"bbbbbbbb-0000-0000-0000-000000000009"}`))
				case "missing target":
					_, err = tx.Exec(ctx, `DELETE FROM deployment_targets WHERE tenant_id=$1 AND id=$2`, tenantID, targetID)
				case "expired lease":
					now = now.Add(2 * time.Minute)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			_, granted, err := st.RedeemAgentJobCredential(ctx, tenantID, agentID, id, job.ClaimAttempts, job, []byte("test-binding"), now)
			if err != nil || granted != (mode == "unchanged") {
				t.Fatalf("grant=%v err=%v", granted, err)
			}
			var count int
			if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM agent_job_credential_redemptions WHERE tenant_id=$1 AND job_id=$2`, tenantID, id).Scan(&count)
			}); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if granted {
				wantCount = 1
			}
			if count != wantCount {
				t.Fatalf("unexpected grant record count %d", count)
			}
		})
	}
}
