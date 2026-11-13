// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A245-L1 Done-when (store): the operations ledger reads host and relay agent
// jobs, ended access and machine sessions, and managed-key operations from the
// tables that record them. An agent job reads its agent's newest signed
// receipt, else its claim; a delivery's job stays a connector_delivery only; a
// gateway session ended without its gateway's report reads unacknowledged.
// Each row is read back by its own id, a job's number and an operation's text
// id included, and a page of each source alone is bounded.
func TestOperationLedgerReadsAgentJobsSessionsAndKeyOperationsA245L1(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantID = "a2451000-0000-4000-8000-000000000001"
	seedTenant(t, s, tenantID)
	if _, err := s.SystemPool().Exec(ctx, `INSERT INTO tenants (tenant_id, name) VALUES ($1, 'a245l1-ledger')`, tenantID); err != nil {
		t.Fatal(err)
	}
	agentID := "a2451000-0000-4000-8000-0000000000a1"
	now := time.Now().UTC().Truncate(time.Microsecond)
	var executed, claimed, deploy int64
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		insertJob := func(destination, key string, claimedAt *time.Time) (int64, error) {
			var id int64
			// A finished job's command is delivered; an unfinished one is still
			// pending under its claim.
			err := tx.QueryRow(ctx, `INSERT INTO outbox(tenant_id,destination,payload,idempotency_key,required_agent_role,
				claimed_by_agent_id,claim_expires_at,claim_completed_at,created_at,status,delivered_at)
				VALUES($1,$2,'\x7b7d',$3,'host',$4,$5,$6,$7,CASE WHEN $6::timestamptz IS NULL THEN 'pending' ELSE 'delivered' END,$6) RETURNING id`,
				tenantID, destination, key, agentID, now.Add(time.Hour), claimedAt, now.Add(-time.Minute)).Scan(&id)
			return id, err
		}
		done := now
		var err error
		if executed, err = insertJob("endpoint.verify", "a245l1-verify", &done); err != nil {
			return err
		}
		if claimed, err = insertJob("discovery.run", "a245l1-discover", nil); err != nil {
			return err
		}
		if deploy, err = insertJob("connector.deploy", "a245l1-deploy", &done); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO connector_delivery_receipts(tenant_id,id,identity_id,connector,target,status,detail,reason,outbox_id,created_at,updated_at)
			VALUES($1,'a2451000-0000-4000-8000-0000000000d1',NULL,'nginx','edge','delivered','','deploy',$2,$3,$3)`, tenantID, deploy, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO pam_sessions(tenant_id,id,target_type,target_id,role,status,subject,requested_by,
			started_at,expires_at,delivery,revocation_requested_by,revocation_reason,revocation_requested_at)
			VALUES($1,'a2451000-0000-4000-8000-0000000000e1','postgresql','orders-db','readonly','revoked','alice','alice',$2,$3,'gateway','bob','left the team',$4)`,
			tenantID, now.Add(-time.Hour), now.Add(time.Hour), now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO machine_sessions(tenant_id,id,principal,method,status,issued_at,expires_at,revoked_at,revoked_by)
			VALUES($1,'a2451000-0000-4000-8000-0000000000f1','system:serviceaccount:payments:api','jwt','revoked',$2,$3,$4,'system:serviceaccount:payments:api')`,
			tenantID, now.Add(-time.Hour), now.Add(time.Hour), now); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO managed_key_operations(tenant_id,operation_id,provider,action,key_id,algorithm,status,outbox_id,created_at,updated_at)
			VALUES($1,'op-a245l1-rotate','aws-kms','rotate','alias/orders','rsa-2048','completed',$2,$3,$3)`, tenantID, deploy, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAgentJobReceipt(ctx, tenantID, store.AgentJobReceipt{JobID: executed, Attempt: 1, Agent: "web-1",
		Kind: "endpoint.verify", Outcome: "executed", State: "verified", ObservedAt: now}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ListOperationLedgerRows(ctx, tenantID, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.OperationLedgerRow{}
	for _, r := range rows {
		got[r.Key()] = r
	}
	for key, want := range map[string]string{
		"agent_job:" + strconv.FormatInt(executed, 10):                    "receipt_executed",
		"agent_job:" + strconv.FormatInt(claimed, 10):                     "claimed",
		"access_session_revocation:a2451000-0000-4000-8000-0000000000e1":  "revoked_unacknowledged",
		"machine_session_revocation:a2451000-0000-4000-8000-0000000000f1": "revoked",
		"managed_key_operation:op-a245l1-rotate":                          "completed",
		"connector_delivery:a2451000-0000-4000-8000-0000000000d1":         "delivered",
	} {
		if r, ok := got[key]; !ok || r.Status != want {
			t.Fatalf("ledger row %s = %+v (found %v), want status %s", key, r, ok, want)
		}
	}
	if _, ok := got["agent_job:"+strconv.FormatInt(deploy, 10)]; ok {
		t.Fatal("a delivery's agent job is listed twice: as a delivery and as a job")
	}
	if r := got["agent_job:"+strconv.FormatInt(executed, 10)]; r.SubjectName != "web-1" || r.Target != "endpoint.verify" || r.OutboxID == nil || *r.OutboxID != executed {
		t.Fatalf("the executed job reads %+v", r)
	}
	if r := got["managed_key_operation:op-a245l1-rotate"]; r.Origin != "requested rotate" || r.Target != "aws-kms" || r.SubjectName != "aws-kms:alias/orders" {
		t.Fatalf("the key operation reads %+v", r)
	}

	for _, ref := range []struct{ source, id string }{
		{"agent_job", strconv.FormatInt(claimed, 10)},
		{"managed_key_operation", "op-a245l1-rotate"},
		{"machine_session_revocation", "a2451000-0000-4000-8000-0000000000f1"},
		{"access_session_revocation", "a2451000-0000-4000-8000-0000000000e1"},
	} {
		r, err := s.GetOperationLedgerRow(ctx, tenantID, ref.source, ref.id)
		if err != nil || r.Source != ref.source || r.ID != ref.id {
			t.Fatalf("read %s:%s back: %+v %v", ref.source, ref.id, r, err)
		}
	}
	// One source alone still pages: a page of one, then the next after it.
	page, err := s.ListOperationLedgerRows(ctx, tenantID, nil, 1)
	if err != nil || len(page) != 1 {
		t.Fatalf("a page of one = %d rows, %v", len(page), err)
	}
	next, err := s.ListOperationLedgerRows(ctx, tenantID, &store.OperationLedgerCursor{UpdatedAt: page[0].UpdatedAt, Key: page[0].Key()}, 50)
	if err != nil || len(next) != len(rows)-1 {
		t.Fatalf("the page after the first holds %d rows (%v), want %d", len(next), err, len(rows)-1)
	}
}
