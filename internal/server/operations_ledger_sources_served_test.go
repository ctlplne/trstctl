// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// A245-L1 Done-when (served): the operations ledger shows a host agent's job,
// an ended machine session and a managed-key operation, each in its normalized
// state and only to a caller who may read its domain. A caller with
// lifecycle:read, agents:read and keys:read sees the job (delivered on its
// agent's signed receipt) and the key rotation (delivered: the provider
// completed it), each readable by its own id with its chain; the machine
// session is hidden from it (404) and shown, verified, to a caller with
// secrets:read. A job id that is not a number is not found.
func TestServedOperationsLedgerShowsJobsSessionsAndKeyOperationsA245L1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	const sessionID = "a245l1-served-machine-session"
	var job int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		// A finished host job: its command delivered, so no worker picks it up.
		if err := tx.QueryRow(ctx, `INSERT INTO outbox(tenant_id,destination,payload,idempotency_key,required_agent_role,
			claimed_by_agent_id,claim_expires_at,claim_completed_at,created_at,status,delivered_at)
			VALUES($1,'endpoint.verify','\x7b7d','a245l1-served-verify','host','a2451000-0000-4000-8000-0000000000a2',$2,$3,$3,'delivered',$3) RETURNING id`,
			h.tenant, now.Add(time.Hour), now).Scan(&job); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO machine_sessions(tenant_id,id,principal,method,status,issued_at,expires_at,revoked_at,revoked_by)
			VALUES($1,$2,'a245l1-workload','token','revoked',$3,$4,$5,'a245l1-operator')`,
			h.tenant, sessionID, now.Add(-time.Hour), now.Add(time.Hour), now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO managed_key_operations(tenant_id,operation_id,provider,action,key_id,algorithm,status,outbox_id,created_at,updated_at)
			VALUES($1,'op-a245l1-served','aws-kms','rotate','alias/a245l1','rsa-2048','completed',$2,$3,$3)`, h.tenant, job, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.store.RecordAgentJobReceipt(ctx, h.tenant, store.AgentJobReceipt{JobID: job, Attempt: 1, Agent: "a245l1-host",
		Kind: "endpoint.verify", Outcome: "executed", State: "verified", ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	reader := seedScopedToken(t, h.store, h.tenant, "lifecycle:read", "agents:read", "keys:read")
	secrets := seedScopedToken(t, h.store, h.tenant, "lifecycle:read", "secrets:read")
	jobID := "agent_job:" + strconv.FormatInt(job, 10)
	const operationID = "op-a245l1-served"
	keyOp := "managed_key_operation:" + operationID
	sessionRow := "machine_session_revocation:" + sessionID
	list := func(tok string) map[string]servedOperation {
		t.Helper()
		out := map[string]servedOperation{}
		cursor := ""
		for page := 0; page < 50; page++ {
			q := url.Values{"limit": {"100"}}
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger?"+q.Encode(), tok, nil)
			var body struct {
				Items      []servedOperation `json:"items"`
				NextCursor string            `json:"next_cursor"`
			}
			if status != http.StatusOK || json.Unmarshal(raw, &body) != nil {
				t.Fatalf("ledger: HTTP %d %s", status, raw)
			}
			for _, item := range body.Items {
				out[item.ID] = item
			}
			if cursor = body.NextCursor; cursor == "" {
				return out
			}
		}
		t.Fatal("the ledger did not end within 50 pages")
		return nil
	}
	seen := list(reader)
	if got := seen[jobID]; got.Source != "agent_job" || got.State != "delivered" || got.SourceStatus != "receipt_executed" {
		t.Fatalf("the agent job reads %+v", got)
	}
	if got := seen[keyOp]; got.Source != "managed_key_operation" || got.State != "delivered" || got.CredentialType != "managed_key" {
		t.Fatalf("the key operation reads %+v", got)
	}
	if _, ok := seen[sessionRow]; ok {
		t.Fatal("the machine session showed to a caller without secrets:read")
	}
	for _, id := range []string{jobID, keyOp} {
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger/"+url.PathEscape(id), reader, nil)
		var detail struct {
			ID    string `json:"id"`
			Chain []struct {
				Step string `json:"step"`
			} `json:"chain"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &detail) != nil || detail.ID != id || len(detail.Chain) < 3 {
			t.Fatalf("read %s: HTTP %d %s", id, status, raw)
		}
	}
	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger/"+url.PathEscape(sessionRow), reader, nil); status != http.StatusNotFound {
		t.Fatalf("the machine session read without secrets:read: HTTP %d %s", status, raw)
	}
	if got := list(secrets)[sessionRow]; got.State != "verified" || got.CredentialType != "machine_session" {
		t.Fatalf("with secrets:read the machine session reads %+v", got)
	}
	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger/agent_job:not-a-number", reader, nil); status != http.StatusNotFound {
		t.Fatalf("a job id that is not a number: HTTP %d %s", status, raw)
	}
	t.Logf("A245L1_LEDGER_SOURCES_OK job=%d", job)
}
