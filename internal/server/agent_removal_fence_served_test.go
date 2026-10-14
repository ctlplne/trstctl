// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
)

// A retained removal event must deny an already-open mTLS connection even if
// the disposable agent's SQL read model cannot project yet.
func TestServedAgentOffboardRetainedEventDeniesOpenChannel(t *testing.T) {
	if testing.Short() {
		t.Skip("served agent fault needs PostgreSQL and embedded JetStream")
	}
	ctx := context.Background()
	h := newRoleHarnessNamedWithEventOptions(t, "ar3-offboard-agent", []string{mtls.AgentRoleNetwork},
		[]string{"endpoint.verify"}, nil)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "ar3-before", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	seedRoleJob(t, ctx, h, "endpoint.verify", "ar3-agent-offboard-claimed")
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim before offboard: %+v %v", claimed, err)
	}
	job := claimed.Jobs[0]
	deleteFault := func() {
		if _, err := h.store.SystemPool().Exec(context.Background(),
			`DROP TRIGGER IF EXISTS qa_ar3_agent_offboard_gap ON agents;
			 DROP FUNCTION IF EXISTS qa_ar3_agent_offboard_gap_fn()`); err != nil {
			t.Errorf("remove owned fault: %v", err)
		}
	}
	defer deleteFault()
	_, err = h.store.SystemPool().Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION qa_ar3_agent_offboard_gap_fn() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.tenant_id = '%s'::uuid AND NEW.id = '%s' AND NEW.status = 'offboarded' THEN
				RAISE EXCEPTION 'owned agent offboard projection gap';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER qa_ar3_agent_offboard_gap BEFORE INSERT OR UPDATE ON agents
		FOR EACH ROW EXECUTE FUNCTION qa_ar3_agent_offboard_gap_fn()`, h.tenant, agentRowID(h.tenant, h.agent)))
	if err != nil {
		t.Fatal(err)
	}
	operator := seedScopedToken(t, h.store, h.tenant, "agents:write")
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/agents/"+agentRowID(h.tenant, h.agent)+"/offboard", operator,
		"qa-ar3-offboard-gap", map[string]any{"reason": "owned AR3 fault"})
	if code < 500 {
		t.Fatalf("faulted offboard = %d body=%s, want retryable 5xx", code, body)
	}
	if !h.hasEvent(t, projections.EventAgentOffboarded) {
		t.Fatal("offboard event was not retained")
	}
	var projectedStatus string
	err = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM agents WHERE tenant_id=$1 AND id=$2`,
			h.tenant, agentRowID(h.tenant, h.agent)).Scan(&projectedStatus)
	})
	if err != nil || projectedStatus != "active" {
		t.Fatalf("fault did not leave stale active SQL: status=%q err=%v", projectedStatus, err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "ar3-after", Status: "active"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("retained offboard admitted open-channel heartbeat: %v", err)
	}
	if _, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("retained offboard admitted job claim: %v", err)
	}
	if _, err := h.client.Renew(ctx, &transport.RenewRequest{CSRDER: newAgentCSR(t, h.agent)}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("retained offboard admitted certificate renewal: %v", err)
	}
	report := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "executor stopped", "")
	if _, err := h.client.ReportJobResult(ctx, report); status.Code(err) != codes.PermissionDenied {
		t.Errorf("retained offboard admitted signed receipt: %v", err)
	}
	deleteFault()
	if healed, err := h.srv.orch.ReconcilePendingAgentRemovals(ctx); err != nil || healed != 1 {
		t.Fatalf("recover exact offboard event: healed=%d err=%v", healed, err)
	}
	if denied, err := h.store.AgentOffboarded(ctx, h.tenant, agentRowID(h.tenant, h.agent)); err != nil || !denied {
		t.Fatalf("recovered offboard projection: denied=%v err=%v", denied, err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "ar3-recovered", Status: "active"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("recovered offboard admitted open-channel heartbeat: %v", err)
	}
}

func TestServedAgentCertRevokeRetainedEventDeniesOpenChannel(t *testing.T) {
	if testing.Short() {
		t.Skip("served agent fault needs PostgreSQL and embedded JetStream")
	}
	ctx := context.Background()
	h := newRoleHarnessNamedWithEventOptions(t, "ar3-cert-agent", []string{mtls.AgentRoleNetwork},
		[]string{"endpoint.verify"}, nil)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "ar3-before", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	seedRoleJob(t, ctx, h, "endpoint.verify", "ar3-cert-revoke-claimed")
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim before revocation: %+v %v", claimed, err)
	}
	job := claimed.Jobs[0]
	serial := h.identity.CertificateSerial()
	agentID := agentRowID(h.tenant, h.agent)
	deleteFault := func() {
		if _, err := h.store.SystemPool().Exec(context.Background(),
			`DROP TRIGGER IF EXISTS qa_ar3_agent_cert_gap ON agent_cert_revocations;
			 DROP FUNCTION IF EXISTS qa_ar3_agent_cert_gap_fn()`); err != nil {
			t.Errorf("remove owned cert fault: %v", err)
		}
	}
	defer deleteFault()
	_, err = h.store.SystemPool().Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION qa_ar3_agent_cert_gap_fn() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.tenant_id = '%s'::uuid AND NEW.agent_id = '%s' AND
			   NEW.selector_type = 'serial' AND NEW.selector = '%s' THEN
				RAISE EXCEPTION 'owned agent cert revocation projection gap';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER qa_ar3_agent_cert_gap BEFORE INSERT OR UPDATE ON agent_cert_revocations
		FOR EACH ROW EXECUTE FUNCTION qa_ar3_agent_cert_gap_fn()`, h.tenant, agentID, serial))
	if err != nil {
		t.Fatal(err)
	}
	operator := seedScopedToken(t, h.store, h.tenant, "agents:write")
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/agents/"+agentID+"/cert-revocations", operator,
		"qa-ar3-cert-revoke-gap", map[string]any{
			"agent": h.agent, "serial": serial, "reason": "owned AR3 fault",
		})
	if code < 500 {
		t.Fatalf("faulted cert revoke = %d body=%s, want retryable 5xx", code, body)
	}
	if !h.hasEvent(t, projections.EventAgentCertRevoked) {
		t.Fatal("certificate revocation event was not retained")
	}
	var projected int
	err = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM agent_cert_revocations
			WHERE tenant_id=$1 AND agent_id=$2 AND selector_type='serial' AND selector=$3`,
			h.tenant, agentID, serial).Scan(&projected)
	})
	if err != nil || projected != 0 {
		t.Fatalf("fault did not leave stale cert SQL: rows=%d err=%v", projected, err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "ar3-after", Status: "active"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("retained cert revoke admitted open-channel heartbeat: %v", err)
	}
	if _, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 1}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("retained cert revoke admitted job claim: %v", err)
	}
	if _, err := h.client.Renew(ctx, &transport.RenewRequest{CSRDER: newAgentCSR(t, h.agent)}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("retained cert revoke admitted certificate renewal: %v", err)
	}
	report := h.report(t, job.JobID, job.Attempt, transport.JobOutcomeFailed, "executor stopped", "")
	if _, err := h.client.ReportJobResult(ctx, report); status.Code(err) != codes.PermissionDenied {
		t.Errorf("retained cert revoke admitted signed receipt: %v", err)
	}
	deleteFault()
	if healed, err := h.srv.orch.ReconcilePendingAgentRemovals(ctx); err != nil || healed != 1 {
		t.Fatalf("recover exact certificate revocation event: healed=%d err=%v", healed, err)
	}
	if denied, err := h.store.AgentCertRevoked(ctx, h.tenant, agentID, serial, ""); err != nil || !denied {
		t.Fatalf("recovered certificate deny-list: denied=%v err=%v", denied, err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "ar3-recovered", Status: "active"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("recovered cert revoked agent admitted open-channel heartbeat: %v", err)
	}
}
