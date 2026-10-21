// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/store"
)

// A45: a re-enrolled host agent's first delivery names as predecessor the
// latest delivery to the same target and identity by the earlier agent, so
// rollback readiness is reachable after one deploy instead of two. The agent
// adopts the installed pair on that first deploy and refuses the restore
// itself if it did not retain it.
func TestServedHostPredecessorFallsBackToTheEarlierAgentsDelivery(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy")
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "owners:write", "identities:write")
	currentAgent := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	const earlierAgent = "45450000-0000-4000-8000-000000000045"
	if err := h.store.UpsertAgent(ctx, store.Agent{ID: earlierAgent, TenantID: h.tenant, Name: "a45-earlier", Status: "retired", Roles: []string{mtls.AgentRoleHost}}); err != nil {
		t.Fatal(err)
	}

	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", token, map[string]any{
		"name": "a45-nginx", "connector": "nginx", "enabled": true,
		"config": map[string]any{
			"executor": "agent", "profile": "default", "cert_path": "/etc/nginx/a45.crt", "key_path": "/etc/nginx/a45.key",
			"required_agent_id": currentAgent, "required_agent_role": mtls.AgentRoleHost,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target = %d %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &target)

	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/owners", token, map[string]any{"kind": "workload", "name": "a45-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner = %d %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &owner)
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities", token, map[string]any{
		"kind": "x509_certificate", "name": "a45.example.test", "owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity = %d %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &ident)

	deliver := func(agentID, key string, at time.Time) string {
		t.Helper()
		leafKey, err := crypto.GenerateHostSubjectKey("a45.example.test", []string{"a45.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer leafKey.Destroy()
		issued, err := h.srv.issueLeafWithValidity(ctx, leafKey.CSRDER, 24*time.Hour, crypto.LeafProfile{ClampTTLToIssuer: true})
		if err != nil {
			t.Fatal(err)
		}
		info, err := certinfo.Inspect(issued.DER)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
			OwnerID: &owner.ID, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
			Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, Source: "issued", CertificateDER: issued.DER,
			NotBefore: &info.NotBefore, NotAfter: &info.NotAfter, ValidityAnchor: &issued.ValidityAnchor,
		})
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := strings.ToLower(cert.Fingerprint)
		payload := `{"connector":"nginx","target":"a45-nginx","target_id":"` + target.ID + `","identity_id":"` + ident.ID + `","fingerprint":"` + fingerprint + `"}`
		var outboxID int64
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role, required_agent_id,
				                     status, delivered_at, claimed_by_agent_id, claim_expires_at, claim_completed_at, claim_attempts)
				 VALUES ($1, 'connector.deploy', $2, $3, $4, 'host', $5::uuid, 'delivered', $6::timestamptz, $5::uuid, $6::timestamptz + interval '1 hour', $6::timestamptz, 1)
				 RETURNING id`,
				h.tenant, []byte(payload), key, store.ConnectorTargetLanePrefix+target.ID, agentID, at).Scan(&outboxID)
		}); err != nil {
			t.Fatalf("seed delivered deploy: %v", err)
		}
		identityID := ident.ID
		if _, err := h.srv.orch.RecordConnectorDeliveryWithEventID(ctx, h.tenant, "a45-delivered:"+key, store.ConnectorDeliveryReceipt{
			ID: evidenceID("connector-delivery", h.tenant, key, outboxID), OutboxID: &outboxID, IdentityID: &identityID,
			Destination: "connector.deploy", Connector: "nginx", Target: "a45-nginx", Fingerprint: fingerprint,
			Status: "delivered", Attempts: 1, Reason: "agent_delivered", IdempotencyKey: key,
		}); err != nil {
			t.Fatalf("record delivered receipt: %v", err)
		}
		return fingerprint
	}
	earlier := deliver(earlierAgent, "a45:deploy:earlier", time.Now().Add(-2*time.Hour))
	current := deliver(currentAgent, "a45:deploy:current", time.Now().Add(-time.Hour))

	evidence, found, err := h.store.LastSuccessfulHostDeployEvidence(ctx, h.tenant, target.ID)
	if err != nil || !found || evidence.AgentID != currentAgent || evidence.Fingerprint != current {
		t.Fatalf("evidence = %+v found=%v err=%v", evidence, found, err)
	}
	if evidence.PredecessorFingerprint != earlier {
		t.Fatalf("predecessor = %q, want the earlier agent's delivery %q", evidence.PredecessorFingerprint, earlier)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/targets/"+target.ID, token, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"ready":true`) || !strings.Contains(string(body), earlier) {
		t.Fatalf("readiness after one deploy by the re-enrolled agent = %d %s; want ready with the earlier delivery as predecessor", status, body)
	}
}

// A45 on the served route: a host agent's first deploy to a target reports the
// pair it found installed there inside its signed receipt. The control plane
// records that leaf as an observed certificate, names it as the target's
// predecessor, and the served rollback queues a restore of exactly it. A
// report whose public leaf does not match the signed fingerprint is refused.
func TestServedFirstHostDeployReportsAdoptedPredecessorAndRollsBackToIt(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy")
	token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "owners:write", "identities:write", "certs:read")
	agentID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", token, map[string]any{
		"name": "a45-adopt", "connector": "nginx", "enabled": true,
		"config": map[string]any{
			"executor": "agent", "profile": "default", "cert_path": "/etc/nginx/adopt.crt", "key_path": "/etc/nginx/adopt.key",
			"required_agent_id": agentID, "required_agent_role": mtls.AgentRoleHost,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create target = %d %s", status, body)
	}
	var target struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &target)
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/owners", token, map[string]any{"kind": "workload", "name": "a45-adopt-owner"})
	if status != http.StatusCreated {
		t.Fatalf("create owner = %d %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &owner)
	status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/identities", token, map[string]any{
		"kind": "x509_certificate", "name": "adopt.example.test", "owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity = %d %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &ident)

	// The leaf trstctl is deploying, recorded as issued.
	leafKey, err := crypto.GenerateHostSubjectKey("adopt.example.test", []string{"adopt.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	issued, err := h.srv.issueLeafWithValidity(ctx, leafKey.CSRDER, 24*time.Hour, crypto.LeafProfile{ClampTTLToIssuer: true})
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(issued.DER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		OwnerID: &owner.ID, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, Source: "issued", CertificateDER: issued.DER,
		NotBefore: &info.NotBefore, NotAfter: &info.NotAfter, ValidityAnchor: &issued.ValidityAnchor,
	}); err != nil {
		t.Fatal(err)
	}
	deployed := strings.ToLower(info.SHA256Fingerprint)
	// The pair the host served before trstctl: issued by someone else, unknown
	// to the inventory until the agent reports it.
	adoptedCert, err := testExternalCACertificate(ca.IssueRequest{
		CSR: serverTestCSR(t, "adopt.example.test", nil), DNSNames: []string{"adopt.example.test"}, TTL: 48 * time.Hour,
	}, "Pre-trstctl Issuer")
	if err != nil {
		t.Fatal(err)
	}
	adoptedInfo, err := certinfo.Inspect(adoptedCert.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	adoptedFP := strings.ToLower(adoptedInfo.SHA256Fingerprint)
	if _, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, adoptedFP); err == nil {
		t.Fatal("the adopted leaf must not be in the inventory before the agent reports it")
	}

	payload := `{"connector":"nginx","target":"a45-adopt","target_id":"` + target.ID + `","identity_id":"` + ident.ID + `","fingerprint":"` + deployed + `"}`
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role, required_agent_id)
			 VALUES ($1, 'connector.deploy', $2, 'a45:adopt:deploy', $3, 'host', $4::uuid)`,
			h.tenant, []byte(payload), store.ConnectorTargetLanePrefix+target.ID, agentID)
		return err
	}); err != nil {
		t.Fatalf("seed deploy job: %v", err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim = %+v err=%v", claimed, err)
	}
	job := claimed.Jobs[0]
	id := h.identity.Identity()

	// A leaf that does not match the signed fingerprint is refused outright.
	mismatched, err := transport.SignedReportWithAdoption(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, "", "", "", custody.Record{}, deployed, adoptedCert.CertificatePEM, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.ReportJobResult(ctx, mismatched); err == nil || !strings.Contains(err.Error(), "adopted predecessor") {
		t.Fatalf("mismatched adoption report = %v, want refusal naming the adopted predecessor", err)
	}
	report, err := transport.SignedReportWithAdoption(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		transport.JobOutcomeExecuted, "", "", "", custody.Record{}, adoptedFP, adoptedCert.CertificatePEM, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := h.client.ReportJobResult(ctx, report); err != nil || !accepted.Accepted {
		t.Fatalf("adoption report accepted=%v err=%v", accepted != nil && accepted.Accepted, err)
	}

	// The adopted leaf is now an observed certificate, the first deploy's
	// receipt names it, and the target is rollable to it.
	recorded, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, adoptedFP)
	if err != nil || !strings.HasPrefix(recorded.Source, "host-adopted:") {
		t.Fatalf("adopted leaf in inventory = %+v err=%v; want a host-adopted observation", recorded, err)
	}
	evidence, found, err := h.store.LastSuccessfulHostDeployEvidence(ctx, h.tenant, target.ID)
	if err != nil || !found || evidence.Fingerprint != deployed || evidence.PredecessorFingerprint != adoptedFP {
		t.Fatalf("evidence = %+v found=%v err=%v; want the adopted leaf as predecessor", evidence, found, err)
	}
	status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/targets/"+target.ID, token, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"ready":true`) || !strings.Contains(string(body), adoptedFP) {
		t.Fatalf("readiness after the first deploy = %d %s; want ready with the adopted pair as predecessor", status, body)
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+target.ID+"/rollback", token, "a45-adopt-rollback",
		map[string]any{"identity_id": ident.ID, "reason": "restore the pre-trstctl pair"})
	if status != http.StatusAccepted && status != http.StatusOK {
		t.Fatalf("rollback = %d %s", status, body)
	}
	var queuedPayload string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT convert_from(payload, 'UTF8') FROM outbox WHERE tenant_id=$1 AND destination='connector.rollback' ORDER BY id DESC LIMIT 1`, h.tenant).Scan(&queuedPayload)
	}); err != nil {
		t.Fatalf("queued rollback: %v", err)
	}
	if !strings.Contains(queuedPayload, adoptedFP) {
		t.Fatalf("queued rollback does not name the adopted predecessor: %s", queuedPayload)
	}
}
