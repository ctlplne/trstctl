// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A legitimate signature proves who made the report; the queued intent must
// still decide which endpoint and expected identity that report may describe.
func TestServedEndpointVerificationReceiptBindsTheClaimedIntent(t *testing.T) {
	roles := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	h := &agentChannelHarness{servedHarness: roles.servedHarness, client: roles.client, agent: roles.identity}
	for _, tc := range []struct {
		name      string
		malformed bool
		mutate    func(*relay.EndpointVerifyResult)
	}{
		{name: "malformed", malformed: true},
		{name: "other-endpoint", mutate: func(r *relay.EndpointVerifyResult) { r.EndpointID += "-unclaimed" }},
		{name: "other-address", mutate: func(r *relay.EndpointVerifyResult) { r.Transcript.Address = "127.0.0.1:5433" }},
		{name: "other-expected-leaf", mutate: func(r *relay.EndpointVerifyResult) { r.Transcript.ExpectedFingerprint = strings.Repeat("b", 64) }},
		{name: "host-vantage", mutate: func(r *relay.EndpointVerifyResult) { r.Transcript.Vantage = transport.VantageLocal }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			want := relay.EndpointExpectation{EndpointID: "bound-" + tc.name, Address: "127.0.0.1:5432", ServerName: "db.example.test", Connector: "postgresql", Fingerprint: strings.Repeat("a", 64)}
			payload, err := json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{want}})
			if err != nil {
				t.Fatal(err)
			}
			if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key) VALUES ($1,$2,$3,$4)`, h.tenant, relay.KindEndpointVerify, payload, "bound-report:"+tc.name)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 1})
			if err != nil || len(claimed.Jobs) != 1 {
				t.Fatalf("claim exact verification work: response=%v error=%v", claimed, err)
			}
			job := claimed.Jobs[0]
			if !bytes.Equal(job.Payload, payload) {
				t.Fatal("claimed payload differs from the exact seeded endpoint intent")
			}
			valid := relay.EndpointVerifyResult{EndpointID: want.EndpointID, Transcript: transport.ProbeTranscript{Address: want.Address, ServerName: want.ServerName, Vantage: transport.VantageRelay, ExpectedFingerprint: want.Fingerprint, Reached: false, Error: "controlled connection refusal", ObservedAtUnix: time.Now().UTC().Unix()}, Detail: "controlled connection refusal"}
			bad := valid
			if tc.mutate != nil {
				tc.mutate(&bad)
			}
			badDetail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{bad}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.malformed {
				badDetail = []byte("{")
			}
			digest := transport.SweepDigest(append(bad.Transcript.Canonical(), '\n'))
			accepted, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(badDetail), digest))
			if err == nil && accepted != nil && accepted.Accepted {
				t.Fatal("correctly signed but unbound verification report completed the claim")
			}
			assertJobNotCompleted(t, ctx, h, job.JobID)
			observations, err := h.store.ListEndpointVerifications(ctx, h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			for _, observed := range observations {
				if observed.EndpointID == want.EndpointID || observed.EndpointID == bad.EndpointID {
					t.Fatal("rejected report still changed endpoint health")
				}
			}

			// A corrected observation retries the same still-owned claim. Its
			// failed handshake must persist without invented certificate dates.
			goodDetail, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{valid}})
			if err != nil {
				t.Fatal(err)
			}
			digest = transport.SweepDigest(append(valid.Transcript.Canonical(), '\n'))
			accepted, err = h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(goodDetail), digest))
			if err != nil || accepted == nil || !accepted.Accepted {
				t.Fatalf("corrected same-claim observation: response=%v error=%v", accepted, err)
			}
			observed, err := h.store.GetEndpointVerification(ctx, h.tenant, want.EndpointID, string(transport.VantageRelay))
			if err != nil || observed.Reached || observed.Address != want.Address || observed.ExpectedFingerprint != want.Fingerprint || !observed.NotAfter.IsZero() || observed.LastCheckedAt.IsZero() {
				t.Fatalf("corrected failed observation was lost or rebound: %+v error=%v", observed, err)
			}
		})
	}
}
