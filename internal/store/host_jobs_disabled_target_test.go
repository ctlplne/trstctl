// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

// Existing endpoint.renew jobs use identity lanes. Disabling the saved target
// must stop them even though their lane predates the connector-target convention.
func TestHostRenewalIdentityLanesRespectDisabledTargetAndResumeUnchanged(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	tenantID := tenantA
	const agentID = "bbbbbbbb-0000-0000-0000-000000000001"
	const pausedID = "bbbbbbbb-0000-0000-0000-000000000002"
	const flowingID = "bbbbbbbb-0000-0000-0000-000000000003"
	var pausedJob int64
	var pausedPayload []byte
	for _, targetID := range []string{pausedID, flowingID} {
		if err := st.UpsertDeploymentTarget(ctx, store.DeploymentTarget{ID: targetID, TenantID: tenantID, Name: targetID, Type: "nginx", Enabled: targetID == flowingID, EnabledSet: true}); err != nil {
			t.Fatal(err)
		}
		payload := []byte(`{"connector":"nginx","target_id":"` + targetID + `","identity_id":"` + targetID + `"}`)
		var id int64
		if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `INSERT INTO outbox(tenant_id,destination,payload,idempotency_key,effect_lane,required_agent_role,required_agent_id) VALUES($1,'endpoint.renew',$2,$3,$4,'host',$5) RETURNING id`, tenantID, payload, targetID, "endpoint.renew:identity:"+targetID, agentID).Scan(&id)
		}); err != nil {
			t.Fatal(err)
		}
		if targetID == pausedID {
			pausedJob = id
			pausedPayload = payload
		}
	}
	now := time.Now().UTC()
	jobs, err := st.ClaimAgentJobs(ctx, tenantID, agentID, []string{"endpoint.renew"}, []string{"host"}, 10, time.Minute, now)
	if err != nil || len(jobs) != 1 || jobs[0].ID == pausedJob {
		t.Fatalf("disabled destination leaked work: jobs=%+v err=%v", jobs, err)
	}
	if err := st.UpsertDeploymentTarget(ctx, store.DeploymentTarget{ID: pausedID, TenantID: tenantID, Name: pausedID, Type: "nginx", Enabled: true, EnabledSet: true}); err != nil {
		t.Fatal(err)
	}
	jobs, err = st.ClaimAgentJobs(ctx, tenantID, agentID, []string{"endpoint.renew"}, []string{"host"}, 10, time.Minute, now.Add(time.Second))
	if err != nil || len(jobs) != 1 || jobs[0].ID != pausedJob || jobs[0].ClaimAttempts != 1 || !bytes.Equal(jobs[0].Payload, pausedPayload) {
		t.Fatalf("resume did not preserve queued work: %+v %v", jobs, err)
	}
}
