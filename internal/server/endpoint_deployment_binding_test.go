// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

func TestServedDeploymentVerificationBindsTheClaimedIntent(t *testing.T) {
	roles := newRoleHarness(t, []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}, "connector.deploy", "connector.rollback")
	h := &agentChannelHarness{servedHarness: roles.servedHarness, client: roles.client, agent: roles.identity}
	expect, err := certinfo.ExpectationFromChain(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := certinfo.LeafDER(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	// This is a report-admission fixture, not proof of deployment to a listener.
	// Use a real public certificate so the receiver can reconstruct expectations.
	if _, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, store.Certificate{
		Fingerprint: expect.SHA256Fingerprint, CertificateDER: leafDER, CertificatePEM: h.caPEM, Source: "import",
	}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"connector.deploy", "connector.rollback"} {
		for _, mutation := range []string{"malformed", "other-endpoint", "other-address", "other-leaf", "relay-vantage", "wrong-digest", "false-verified"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				ctx := t.Context()
				intent := relay.DeployIntent{Connector: "postgresql", Target: "owned-db", TargetID: kind + "-" + mutation, Fingerprint: expect.SHA256Fingerprint, VerifyAddress: "127.0.0.1:5432", VerifyServerName: "db.example.test", TargetConfig: json.RawMessage(`{"verify_address":"127.0.0.1:5432","verify_server_name":"db.example.test"}`)}
				var queued any = intent
				if kind == "connector.rollback" {
					queued = relay.RollbackIntent{Connector: intent.Connector, Target: intent.Target, TargetID: intent.TargetID, PredecessorFingerprint: intent.Fingerprint, TargetConfig: intent.TargetConfig, VerifyAddress: intent.VerifyAddress, VerifyServerName: intent.VerifyServerName}
				}
				payload, err := json.Marshal(queued)
				if err != nil {
					t.Fatal(err)
				}
				if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES ($1,$2,$3,$4)`, h.tenant, kind, payload, "deployment-bound:"+intent.TargetID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{kind}, Limit: 1})
				if err != nil || claimed == nil || len(claimed.Jobs) != 1 {
					t.Fatalf("claim exact deployment: response=%v error=%v", claimed, err)
				}
				job := claimed.Jobs[0]
				projected, _ := deployIntentForVerificationReceipt(job.Payload)
				if projected.TargetID != intent.TargetID || projected.Fingerprint != intent.Fingerprint || projected.VerifyAddress != intent.VerifyAddress || projected.VerifyServerName != intent.VerifyServerName {
					t.Fatalf("claimed routing differs from queued routing: %+v", projected)
				}
				valid := relay.EndpointVerifyResult{EndpointID: intent.TargetID, Transcript: transport.ProbeTranscript{
					Address: intent.VerifyAddress, ServerName: intent.VerifyServerName, Vantage: transport.VantageLocal,
					ExpectedFingerprint: intent.Fingerprint, ExpectedSANDigest: transport.SANSetDigest(expect.DNSNames), ExpectedChainDigest: transport.ChainDigest(expect.ChainFingerprints),
					Error: "controlled connection refusal", ObservedAtUnix: time.Now().Unix(),
				}, Detail: "controlled connection refusal"}
				bad := valid
				outcome := transport.JobOutcomeVerifyFailed
				switch mutation {
				case "other-endpoint":
					bad.EndpointID += "-unclaimed"
				case "other-address":
					bad.Transcript.Address = "127.0.0.1:5433"
				case "other-leaf":
					bad.Transcript.ExpectedFingerprint = strings.Repeat("b", 64)
				case "relay-vantage":
					bad.Transcript.Vantage = transport.VantageRelay
				case "false-verified":
					outcome = transport.JobOutcomeVerified
				}
				badDetail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{bad}})
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "malformed" {
					badDetail = []byte("{")
				}
				digest := bad.Transcript.Digest()
				if mutation == "wrong-digest" {
					digest = strings.Repeat("c", 64)
				}
				accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, outcome, string(badDetail), digest))
				if err == nil && accepted != nil && accepted.Accepted {
					t.Fatal("signed but unbound deployment observation completed the claim")
				}
				assertJobNotCompleted(t, ctx, h, job.JobID)
				if _, err := h.store.GetEndpointVerification(ctx, h.tenant, intent.TargetID, string(transport.VantageLocal)); !store.IsNotFound(err) {
					t.Fatalf("rejected observation changed endpoint health: %v", err)
				}
				goodDetail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{valid}})
				if err != nil {
					t.Fatal(err)
				}
				accepted, err = h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeVerifyFailed, string(goodDetail), valid.Transcript.Digest()))
				if err != nil || accepted == nil || !accepted.Accepted {
					t.Fatalf("corrected same-claim failure: response=%v error=%v", accepted, err)
				}
				observed, err := h.store.GetEndpointVerification(ctx, h.tenant, intent.TargetID, string(transport.VantageLocal))
				if err != nil || observed.Reached || observed.ExpectedFingerprint != intent.Fingerprint || observed.EvidenceDigest != valid.Transcript.Digest() {
					t.Fatalf("corrected deployment observation lost or rebound: %+v error=%v", observed, err)
				}
			})
		}
	}
}
