// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
)

func TestServedRenewalVerificationBindsItsIssuedSuccessor(t *testing.T) {
	roles := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	ctx := t.Context()
	owner, err := roles.srv.orch.CreateOwner(ctx, roles.tenant, string(store.OwnerTeam), "QA", "qa@example.test")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := roles.srv.orch.CreateIdentity(ctx, roles.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "rotation.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	intent := relay.DeployIntent{Connector: "nginx", Target: "owned-host", TargetID: "renewal-bound-target", IdentityID: identity.ID, SubjectCommonName: "rotation.example.test", SubjectDNSNames: []string{"rotation.example.test"}, VerifyAddress: "rotation.example.test:443", VerifyServerName: "rotation.example.test"}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := roles.store.WithTenant(ctx, roles.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key,required_agent_id) VALUES ($1,$2,$3,$4,$5)`, roles.tenant, agentJobKindEndpointRenew, payload, "renewal-bound", agentRowID(roles.tenant, roles.agent))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	job := claimOneRenewal(t, ctx, roles)
	f := &hostRotationResultFixture{h: roles, job: job, fingerprint: signHostRotationFixtureJob(t, roles, job)}
	cert, err := f.h.store.GetCertificateByFingerprint(ctx, f.h.tenant, f.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	expect, err := certinfo.ExpectationFromChain(cert.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	result := relay.EndpointVerifyResult{EndpointID: intent.TargetID, Transcript: transport.ProbeTranscript{
		Address: intent.VerifyAddress, ServerName: intent.VerifyServerName, Vantage: transport.VantageLocal,
		ExpectedFingerprint: f.fingerprint, ExpectedSANDigest: transport.SANSetDigest(expect.DNSNames), ExpectedChainDigest: transport.ChainDigest(expect.ChainFingerprints),
		Error: "controlled connection refusal", ObservedAtUnix: time.Now().Unix(),
	}, Detail: "controlled connection refusal"}
	sign := func(r relay.EndpointVerifyResult) *transport.ReportJobResultRequest {
		detail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{r}})
		if err != nil {
			t.Fatal(err)
		}
		id := f.h.identity.Identity()
		record := custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable, GeneratedBy: id.CommonName()}
		req, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), f.job.JobID, f.job.Attempt, transport.JobOutcomeVerifyFailed, string(detail), r.Transcript.Digest(), f.fingerprint, record, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	bad := result
	bad.EndpointID += "-unclaimed"
	accepted, err := f.h.client.ReportJobResult(ctx, sign(bad))
	if err == nil && accepted != nil && accepted.Accepted {
		t.Fatal("renewal report changed its target and completed the claim")
	}
	h := &agentChannelHarness{servedHarness: f.h.servedHarness, client: f.h.client, agent: f.h.identity}
	assertJobNotCompleted(t, ctx, h, f.job.JobID)
	accepted, err = f.h.client.ReportJobResult(ctx, sign(result))
	if err != nil || accepted == nil || !accepted.Accepted {
		t.Fatalf("same-claim issued successor verification: response=%v error=%v", accepted, err)
	}
	observed, err := f.h.store.GetEndpointVerification(ctx, f.h.tenant, intent.TargetID, string(transport.VantageLocal))
	if err != nil || observed.ExpectedFingerprint != f.fingerprint || observed.Reached || observed.EvidenceDigest != result.Transcript.Digest() {
		t.Fatalf("renewal expectation did not use issued successor: %+v error=%v", observed, err)
	}
}
