// SPDX-License-Identifier: BUSL-1.1

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
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// B10-L1 (owner decision): deploy and rollback verification share one rule.
// A listener serving the deployed leaf with other issuers than were written
// passes, the receipt names the chain mismatch and a posture finding records
// it; a target with strict_chain fails it instead. A chain-only report must
// still establish the leaf, its names and its validity.
func TestServedChainOnlyMismatchPassesNamedUnlessStrict(t *testing.T) {
	roles := newRoleHarness(t, []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}, "connector.deploy", "connector.rollback")
	h := &agentChannelHarness{servedHarness: roles.servedHarness, client: roles.client, agent: roles.identity}
	expect, err := certinfo.ExpectationFromChain(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := certinfo.LeafDER(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, store.Certificate{
		Fingerprint: expect.SHA256Fingerprint, CertificateDER: leafDER, CertificatePEM: h.caPEM, Source: "import",
	}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"connector.deploy", "connector.rollback"} {
		for _, mode := range []string{"default", "strict", "chain-without-difference"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				ctx := t.Context()
				targetID := kind + "-chain-" + mode
				config := `{"verify_address":"127.0.0.1:8443","verify_server_name":"edge.example.test"}`
				if mode == "strict" {
					config = `{"verify_address":"127.0.0.1:8443","verify_server_name":"edge.example.test","strict_chain":true}`
				}
				intent := relay.DeployIntent{Connector: "nginx", Target: "edge", TargetID: targetID, Fingerprint: expect.SHA256Fingerprint,
					VerifyAddress: "127.0.0.1:8443", VerifyServerName: "edge.example.test", TargetConfig: json.RawMessage(config)}
				var queued any = intent
				if kind == "connector.rollback" {
					queued = relay.RollbackIntent{Connector: intent.Connector, Target: intent.Target, TargetID: intent.TargetID,
						PredecessorFingerprint: intent.Fingerprint, PredecessorSerial: "01", TargetConfig: intent.TargetConfig,
						VerifyAddress: intent.VerifyAddress, VerifyServerName: intent.VerifyServerName}
				}
				payload, err := json.Marshal(queued)
				if err != nil {
					t.Fatal(err)
				}
				if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id,destination,payload,idempotency_key) VALUES ($1,$2,$3,$4)`,
						h.tenant, kind, payload, "chain-only:"+targetID)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{kind}, Limit: 1})
				if err != nil || claimed == nil || len(claimed.Jobs) != 1 {
					t.Fatalf("claim: %v %v", claimed, err)
				}
				job := claimed.Jobs[0]
				served := transport.ChainDigest([]string{strings.Repeat("e", 64)})
				if mode == "chain-without-difference" {
					served = transport.ChainDigest([]string{strings.Repeat("d", 64)})
				}
				tr := transport.ProbeTranscript{
					Address: intent.VerifyAddress, ServerName: intent.VerifyServerName, Vantage: transport.VantageLocal, Reached: true,
					HandshakeMillis: 3, ChainBytes: 900,
					ExpectedFingerprint: intent.Fingerprint, ObservedFingerprint: intent.Fingerprint,
					ExpectedSANDigest: transport.SANSetDigest(expect.DNSNames), ObservedSANDigest: transport.SANSetDigest(expect.DNSNames), CheckedSANs: true,
					ExpectedChainDigest: transport.ChainDigest([]string{strings.Repeat("d", 64)}), ObservedChainDigest: served, CheckedChain: true,
					Mismatch:      certinfo.MismatchChain,
					NotBeforeUnix: info.NotBefore.Unix(), NotAfterUnix: info.NotAfter.Unix(), ObservedAtUnix: time.Now().Unix(),
				}
				detail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: targetID, Transcript: tr,
					Detail: "chain mismatch (0 issuer(s) served, 1 expected)"}}})
				if err != nil {
					t.Fatal(err)
				}
				verified, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeVerified, string(detail), tr.Digest()))
				findings := func() int {
					var n int
					if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM discovery_findings WHERE tenant_id=$1 AND kind=$2 AND ref=$3 AND provenance=$4`,
						h.tenant, orchestrator.EndpointChainFindingKind, intent.VerifyAddress, "endpoint-verification:"+targetID).Scan(&n); err != nil {
						t.Fatal(err)
					}
					return n
				}
				if mode != "default" {
					if err == nil && verified != nil && verified.Accepted {
						t.Fatalf("%s: a verified chain-only report was accepted", mode)
					}
					assertJobNotCompleted(t, ctx, h, job.JobID)
					if mode == "strict" {
						failed, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeVerifyFailed, string(detail), tr.Digest()))
						if err != nil || failed == nil || !failed.Accepted {
							t.Fatalf("strict verify_failed report: %v %v", failed, err)
						}
					}
					if n := findings(); n != 0 {
						t.Fatalf("%s recorded %d chain findings", mode, n)
					}
					return
				}
				if err != nil || verified == nil || !verified.Accepted {
					t.Fatalf("chain-only verified report: %v %v", verified, err)
				}
				var reason, receiptDetail string
				want := "endpoint_serving_deployed_identity_chain_mismatch"
				query := `SELECT reason, detail FROM connector_delivery_receipts WHERE tenant_id=$1 AND idempotency_key=$2`
				key := "chain-only:" + targetID + ":verified"
				if kind == "connector.rollback" {
					want, query, key = "rolled_back_and_reverified_chain_mismatch",
						`SELECT reason, detail FROM connector_delivery_receipts WHERE tenant_id=$1 AND outbox_id=$2::bigint`, ""
				}
				arg := any(key)
				if key == "" {
					arg = job.JobID
				}
				if err := h.store.SystemPool().QueryRow(ctx, query, h.tenant, arg).Scan(&reason, &receiptDetail); err != nil {
					t.Fatal(err)
				}
				if reason != want || !strings.Contains(receiptDetail, "strict_chain") {
					t.Fatalf("receipt reason=%q detail=%q; want %q naming the chain mismatch", reason, receiptDetail, want)
				}
				if n := findings(); n != 1 {
					t.Fatalf("chain findings = %d, want 1", n)
				}
			})
		}
	}
}
