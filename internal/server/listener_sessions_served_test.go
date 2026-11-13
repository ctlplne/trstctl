// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/listenersessions"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// A245-L2 Done-when (served, admission): a host agent's verified deploy
// report carries its count of the listener's sessions, and the control plane
// records it only when the signed evidence covers the count: a count the
// receipt does not sign, one on another port, or one whose numbers cannot
// hold together is refused and the claim stays open; the signed one completes
// the claim and is recorded against the identity, target and deployed
// certificate.
func TestServedHostDeployCountsListenerSessionsA245L2(t *testing.T) {
	roles := newRoleHarness(t, []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}, "connector.deploy")
	h := &agentChannelHarness{servedHarness: roles.servedHarness, client: roles.client, agent: roles.identity}
	ctx := t.Context()
	expect, err := certinfo.ExpectationFromChain(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := certinfo.LeafDER(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		Fingerprint: expect.SHA256Fingerprint, CertificateDER: leafDER, CertificatePEM: h.caPEM, Source: "import",
	}); err != nil {
		t.Fatal(err)
	}
	const identityID = "a2452000-0000-4000-8000-000000000001"
	intent := relay.DeployIntent{Connector: "postgresql", Target: "a245l2-db", TargetID: "a245l2-db-target", IdentityID: identityID,
		Fingerprint: expect.SHA256Fingerprint, VerifyAddress: "127.0.0.1:5432", VerifyServerName: "db.example.test",
		TargetConfig: json.RawMessage(`{"verify_address":"127.0.0.1:5432","verify_server_name":"db.example.test"}`)}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES ($1,'connector.deploy',$2,'a245l2-deploy')`, h.tenant, payload)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 1})
	if err != nil || claimed == nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	job := claimed.Jobs[0]
	now := time.Now().Unix()
	tr := transport.ProbeTranscript{Address: intent.VerifyAddress, ServerName: intent.VerifyServerName, Vantage: transport.VantageLocal,
		Reached: true, ExpectedFingerprint: expect.SHA256Fingerprint, ObservedFingerprint: expect.SHA256Fingerprint,
		ExpectedSANDigest: transport.SANSetDigest(expect.DNSNames), ObservedSANDigest: transport.SANSetDigest(expect.DNSNames), CheckedSANs: true,
		NotBeforeUnix: info.NotBefore.Unix(), NotAfterUnix: info.NotAfter.Unix(), ObservedAtUnix: now, HandshakeMillis: 2}
	count := listenersessions.Observation{Port: 5432, Established: 3, HeldByOlder: 1, SinceUnix: now - 30, CheckedAtUnix: now}
	result := func(c listenersessions.Observation) relay.EndpointVerifyResult {
		return relay.EndpointVerifyResult{EndpointID: intent.TargetID, Transcript: tr, Detail: "the listener serves the deployed certificate", Sessions: &c}
	}
	encode := func(r relay.EndpointVerifyResult) string {
		raw, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{r}})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	refused := func(name, detail, digest string) {
		t.Helper()
		accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeVerified, detail, digest))
		if err == nil && accepted != nil && accepted.Accepted {
			t.Fatalf("%s: the report completed the claim", name)
		}
		assertJobNotCompleted(t, ctx, h, job.JobID)
	}
	good := result(count)
	refused("a count the receipt does not sign", encode(good), tr.Digest())
	otherPort := count
	otherPort.Port = 5433
	refused("a count on another port", encode(result(otherPort)), relay.DeploymentEvidenceDigest(result(otherPort)))
	impossible := count
	impossible.HeldByOlder = 4
	refused("counts that cannot hold together", encode(result(impossible)), relay.DeploymentEvidenceDigest(result(impossible)))
	var rows int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM listener_session_observations WHERE tenant_id = $1`, h.tenant).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("a refused count was recorded: %d %v", rows, err)
	}

	accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeVerified, encode(good), relay.DeploymentEvidenceDigest(good)))
	if err != nil || accepted == nil || !accepted.Accepted {
		t.Fatalf("the signed count: %v %v", accepted, err)
	}
	var target, fingerprint, identity string
	var port, established, older, unread int
	var since, checked time.Time
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT target, fingerprint, identity_id::text, port, established, held_by_older, unattributed, since, checked_at
		  FROM listener_session_observations WHERE tenant_id = $1`, h.tenant).Scan(&target, &fingerprint, &identity, &port, &established, &older, &unread, &since, &checked); err != nil {
		t.Fatalf("the signed count was not recorded: %v", err)
	}
	if target != intent.Target || fingerprint != strings.ToLower(expect.SHA256Fingerprint) || identity != identityID || port != 5432 ||
		established != 3 || older != 1 || unread != 0 || since.Unix() != now-30 || checked.Unix() != now {
		t.Fatalf("recorded %s %s %s %d %d/%d/%d %v %v", target, fingerprint, identity, port, established, older, unread, since, checked)
	}
	t.Logf("A245L2_SESSIONS_ADMITTED target=%s established=%d older=%d", target, established, older)
}
