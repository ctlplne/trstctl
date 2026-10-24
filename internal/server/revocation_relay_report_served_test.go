// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// B13-7, found proving A112 on the lab: the relay reported every revocation
// probe with an empty evidence digest, and the control plane, which requires
// one, rejected every real report — revocation health never recorded a real
// relay's observation; the served tests had built the digest themselves. The
// rejection was an internal error, so the agent kept its signed report and
// refused to claim any other work until the report was accepted, which it
// never would be. Now the relay digests its report, and a report that can
// never validate is refused once and for all, so the relay moves on.
func TestServedRealRelayRevocationReportsAreRecorded(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindRevocationProbe)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "b13-7-test", Status: "active"}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "B13-7 Revocation CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var crlDER, ocspDER []byte
	responders := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crl":
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(crlDER)
		case "/ocsp":
			w.Header().Set("Content-Type", "application/ocsp-response")
			_, _ = w.Write(ocspDER)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(responders.Close)
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "b13-7.example"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, crypto.LeafProfile{
		CRLDistributionPoints: []string{responders.URL + "/crl"}, OCSPServers: []string{responders.URL + "/ocsp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if crlDER, err = crypto.CreateCRL(caDER, caKey, nil, 7, now.Add(-time.Minute), now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ocspDER, err = crypto.SignOCSPResponse(caDER, caKey, crypto.OCSPGood, leafInfo.SerialNumber, now.Add(-time.Minute), now.Add(48*time.Hour), time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	caInfo, err := certinfo.Inspect(caDER)
	if err != nil {
		t.Fatal(err)
	}
	recordInventoryCertificateAUD38(t, h, caDER, caInfo)
	recordInventoryCertificateAUD38(t, h, leafDER, leafInfo)
	if n, err := h.srv.RunRevocationHealthOnce(ctx); err != nil || n != 2 {
		t.Fatalf("scheduler queued %d endpoints (%v), want CRL and OCSP", n, err)
	}
	_, intent := revocationProbeOutboxAUD38(t, ctx, h)

	// The shipped relay code claims, probes and reports; the control plane records it.
	channel := &servedHostRelayChannel{client: h.client, identity: h.identity}
	processed, err := relay.RunOnce(ctx, channel, responders.Client(), 5, 60)
	if err != nil || processed != 1 || channel.lastOutcome != relay.OutcomeExecuted || !channel.lastAccepted || channel.lastReportErr != nil {
		t.Fatalf("real relay probe: processed=%d outcome=%q accepted=%t err=%v report_err=%v",
			processed, channel.lastOutcome, channel.lastAccepted, err, channel.lastReportErr)
	}
	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/health", token, nil)
	var health struct {
		Observed bool `json:"observed"`
		Items    []struct {
			Status            string `json:"status"`
			SignatureVerified bool   `json:"signature_verified"`
			EvidenceDigest    string `json:"evidence_digest"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &health) != nil || !health.Observed || len(health.Items) != 2 {
		t.Fatalf("revocation health after a real relay report = %d %s", status, body)
	}
	for _, item := range health.Items {
		if item.Status != "fresh" || !item.SignatureVerified || item.EvidenceDigest != crypto.SHA256Hex([]byte(channel.lastDetail)) {
			t.Fatalf("observation = %+v, want fresh, verified, evidence digest of the signed report", item)
		}
	}

	// A report that can never validate (an older relay's, with no digest) is
	// refused once: the job fails terminally and the agent may claim again.
	next := intent
	next.ID, next.Bucket = uuid.NewString(), now.Truncate(time.Hour).Add(time.Hour).Format(time.RFC3339)
	if _, inserted, err := h.srv.orch.QueueRevocationProbe(ctx, h.tenant, next); err != nil || !inserted {
		t.Fatalf("queue the next hour's probe: inserted=%t %v", inserted, err)
	}
	jobs, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindRevocationProbe}, Limit: 5, LeaseSeconds: 60})
	if err != nil || len(jobs.Jobs) != 1 {
		t.Fatalf("claim next probe = %+v (%v)", jobs, err)
	}
	job := jobs.Jobs[0]
	resp, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, channel.lastDetail, ""))
	if err != nil || !resp.Accepted {
		t.Fatalf("report without a digest = %+v (%v), want refused once and closed", resp, err)
	}
	var jobStatus string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM outbox WHERE tenant_id = $1 AND id = $2`, h.tenant, job.JobID).Scan(&jobStatus)
	}); err != nil || jobStatus != "dead" && jobStatus != "failed" {
		t.Fatalf("refused probe job status = %q (%v), want terminally failed", jobStatus, err)
	}
}
