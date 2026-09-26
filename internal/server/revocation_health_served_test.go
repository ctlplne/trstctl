// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/revocationhealth"
	"trstctl.com/trstctl/internal/store"
)

// TestServedRevocationHealthSchedulesRelayAndProjectsSignedCRLOCSPAUD38
// proves R1 from inventory to controlled responders to signed ingestion, API,
// notification, cold rebuild, and tenant isolation.
func TestServedRevocationHealthSchedulesRelayAndProjectsSignedCRLOCSPAUD38(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindRevocationProbe)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "aud38-test", Status: "active",
	}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "AUD-38 Revocation CA", 24*time.Hour)
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
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
				t.Errorf("OCSP request = %s %q", r.Method, r.Header.Get("Content-Type"))
			}
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
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "aud38.example"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		CRLDistributionPoints: []string{responders.URL + "/crl"},
		OCSPServers:           []string{responders.URL + "/ocsp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	crlDER, err = crypto.CreateCRL(caDER, caKey, nil, 38, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ocspDER, err = crypto.SignOCSPResponse(caDER, caKey, crypto.OCSPGood,
		leafInfo.SerialNumber, now.Add(-time.Minute), now.Add(48*time.Hour), time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	caInfo, err := certinfo.Inspect(caDER)
	if err != nil {
		t.Fatal(err)
	}
	recordInventoryCertificateAUD38(t, h, caDER, caInfo)
	recordInventoryCertificateAUD38(t, h, leafDER, leafInfo)

	// Two leader replicas racing one database-time bucket append/queue one
	// command. The losing caller reports zero newly queued endpoints.
	queued := make(chan int, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			n, queueErr := h.srv.RunRevocationHealthOnce(ctx)
			queued <- n
			errs <- queueErr
		}()
	}
	queuedTotal := 0
	for range 2 {
		queuedTotal += <-queued
		if err := <-errs; err != nil {
			t.Fatalf("scheduler race: %v", err)
		}
	}
	if queuedTotal != 2 {
		t.Fatalf("concurrent scheduler queued %d endpoints, want exactly CRL+OCSP", queuedTotal)
	}

	payload, intent := revocationProbeOutboxAUD38(t, ctx, h)
	if len(intent.Targets) != 2 || intent.Targets[0].Protocol == intent.Targets[1].Protocol {
		t.Fatalf("scheduled targets = %+v, want distinct CRL and OCSP", intent.Targets)
	}
	for _, target := range intent.Targets {
		if target.IssuerFingerprint != caInfo.SHA256Fingerprint || len(target.IssuerDER) == 0 ||
			target.CertificateID == "" || target.CertificateSerial != leafInfo.SerialNumber || len(target.CertificateDER) == 0 {
			t.Fatalf("target lost issuer/certificate context: %+v", target)
		}
	}

	// Delete the derived outbox row to model append-ACK followed by SQL loss.
	// Boot reconciliation must restore byte-identical network-role work.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND destination = $2`, h.tenant, relay.KindRevocationProbe)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if healed, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || healed != 1 {
		t.Fatalf("reconcile revocation probe: healed=%d err=%v", healed, err)
	}
	healedPayload, _ := revocationProbeOutboxAUD38(t, ctx, h)
	if !bytes.Equal(payload, healedPayload) {
		t.Fatalf("reconciled probe changed bytes: got %s want %s", healedPayload, payload)
	}

	relayID := agentRowID(h.tenant, h.agent)
	wrongRole, err := h.store.ClaimAgentJobs(ctx, h.tenant, relayID,
		[]string{relay.KindRevocationProbe}, []string{mtls.AgentRoleHost}, 1, time.Minute, time.Now().UTC())
	if err != nil || len(wrongRole) != 0 {
		t.Fatalf("host role claimed network revocation job: jobs=%d err=%v", len(wrongRole), err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindRevocationProbe}, Limit: 1})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("network relay claim: jobs=%d err=%v", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	var claimedIntent revocationhealth.Intent
	if !bytes.Equal(job.Payload, payload) || json.Unmarshal(job.Payload, &claimedIntent) != nil {
		t.Fatalf("claimed probe changed: %s", job.Payload)
	}
	report, err := relay.ProbeRevocation(ctx, responders.Client(), claimedIntent)
	if err != nil {
		t.Fatalf("execute real CRL/OCSP probe: %v", err)
	}
	if report.Healthy || len(report.Findings) != 2 {
		t.Fatalf("controlled responder report = %+v", report)
	}
	var staleCRL, freshOCSP bool
	for _, finding := range report.Findings {
		staleCRL = staleCRL || finding.Protocol == revocationhealth.ProtocolCRL && finding.Status == revocationhealth.StatusStale && finding.SignatureVerified
		freshOCSP = freshOCSP || finding.Protocol == revocationhealth.ProtocolOCSP && finding.Status == revocationhealth.StatusFresh && finding.SignatureVerified && finding.ResponseStatus == crypto.OCSPGood
	}
	if !staleCRL || !freshOCSP {
		t.Fatalf("real signature/status/freshness verdicts = %+v", report.Findings)
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	evidenceDigest := crypto.SHA256Hex(reportJSON)
	requests := []*transport.ReportJobResultRequest{
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportJSON), evidenceDigest),
		h.report(t, job.JobID, job.Attempt, transport.JobOutcomeExecuted, string(reportJSON), evidenceDigest),
	}
	accepted := make(chan bool, 2)
	reportErrs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Add(1)
		go func(request *transport.ReportJobResultRequest) {
			defer wg.Done()
			response, reportErr := h.client.ReportJobResult(ctx, request)
			accepted <- response != nil && response.Accepted
			reportErrs <- reportErr
		}(request)
	}
	wg.Wait()
	close(accepted)
	close(reportErrs)
	acceptedCount := 0
	for value := range accepted {
		if value {
			acceptedCount++
		}
	}
	for err := range reportErrs {
		if err != nil {
			t.Fatalf("signed revocation report: %v", err)
		}
	}
	if acceptedCount != 1 {
		t.Fatalf("concurrent signed reports accepted=%d, want one", acceptedCount)
	}

	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	assertRevocationHealthAPIAUD38(t, h, token, evidenceDigest)
	alerts := outboxPayloadsForDestination(t, ctx, h.store, h.tenant, notify.DestinationRevocation)
	if len(alerts) != 1 || !bytes.Contains(alerts[0], []byte(`"mismatch":"stale"`)) {
		t.Fatalf("revocation alerts = %q, want one stale CRL alert", alerts)
	}
	if !h.hasEvent(t, projections.EventRevocationProbeQueued) || !h.hasEvent(t, projections.EventRevocationHealthObserved) {
		t.Fatal("revocation job did not append queue and observation events")
	}
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type == projections.EventRevocationHealthObserved && bytes.Contains(event.Data, []byte("nextUpdate passed")) {
			t.Fatal("agent-controlled prose entered the immutable observation event")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold rebuild revocation health: %v", err)
	}
	assertRevocationHealthAPIAUD38(t, h, token, evidenceDigest)

	otherTenant := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, otherTenant, "Other revocation tenant")
	otherToken := seedScopedToken(t, h.store, otherTenant, "certs:read")
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/health", otherToken, nil)
	if code != http.StatusOK || bytes.Contains(body, []byte(responders.URL)) || !bytes.Contains(body, []byte(`"observed":false`)) {
		t.Fatalf("cross-tenant revocation health = %d %s", code, body)
	}
}

func TestRevocationProbeIdentityIncludesRepresentativeCertificateContext(t *testing.T) {
	base := revocationhealth.Target{
		Key:                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CertificateFingerprint: "leaf-one", CertificateSerial: "01",
	}
	replaced := base
	replaced.CertificateFingerprint = "leaf-two"
	replaced.CertificateSerial = "02"
	first := revocationTargetIdentities([]revocationhealth.Target{base})
	second := revocationTargetIdentities([]revocationhealth.Target{replaced})
	if len(first) != 1 || len(second) != 1 || first[0] == second[0] {
		t.Fatalf("representative leaf replacement reused scheduler identity: first=%v second=%v", first, second)
	}
}

func recordInventoryCertificateAUD38(t *testing.T, h *roleHarness, der []byte, info certinfo.Info) {
	t.Helper()
	notBefore, notAfter := info.NotBefore, info.NotAfter
	if _, err := h.srv.orch.RecordCertificate(context.Background(), h.tenant, store.Certificate{
		Subject: info.Subject, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
		NotBefore: &notBefore, NotAfter: &notAfter, Source: "aud38-controlled-inventory",
		CertificateDER: der, Status: "active",
	}); err != nil {
		t.Fatalf("record inventory certificate: %v", err)
	}
}

func revocationProbeOutboxAUD38(t *testing.T, ctx context.Context, h *roleHarness) ([]byte, revocationhealth.Intent) {
	t.Helper()
	var payload []byte
	var role string
	var count int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, relay.KindRevocationProbe).Scan(&count); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT payload, required_agent_role FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, relay.KindRevocationProbe).Scan(&payload, &role)
	}); err != nil {
		t.Fatalf("read produced revocation job: %v", err)
	}
	if count != 1 || role != mtls.AgentRoleNetwork {
		t.Fatalf("revocation outbox count=%d role=%q", count, role)
	}
	var intent revocationhealth.Intent
	if err := json.Unmarshal(payload, &intent); err != nil {
		t.Fatal(err)
	}
	return payload, intent
}

func assertRevocationHealthAPIAUD38(t *testing.T, h *roleHarness, token, evidenceDigest string) {
	t.Helper()
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/revocation/health", token, nil)
	if code != http.StatusOK {
		t.Fatalf("get revocation health: %d %s", code, body)
	}
	var response struct {
		Observed bool `json:"observed"`
		Summary  struct {
			Endpoints int `json:"endpoints"`
			Fresh     int `json:"fresh"`
			Stale     int `json:"stale"`
		} `json:"summary"`
		Items []struct {
			Protocol            string `json:"protocol"`
			Status              string `json:"status"`
			SignatureVerified   bool   `json:"signature_verified"`
			ResponseStatus      string `json:"response_status"`
			EvidenceDigest      string `json:"evidence_digest"`
			ObservedByAgentName string `json:"observed_by_agent_name"`
		} `json:"items"`
		Guidance string `json:"guidance"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode revocation health: %v (%s)", err, body)
	}
	if !response.Observed || response.Summary.Endpoints != 2 || response.Summary.Fresh != 1 || response.Summary.Stale != 1 || len(response.Items) != 2 {
		t.Fatalf("revocation summary = %+v items=%+v", response.Summary, response.Items)
	}
	for _, item := range response.Items {
		if !item.SignatureVerified || item.EvidenceDigest != evidenceDigest || item.ObservedByAgentName != h.agent {
			t.Fatalf("served evidence lost signature/relay binding: %+v", item)
		}
	}
	guidance := strings.ToLower(response.Guidance)
	if !strings.Contains(guidance, "crl") || !strings.Contains(guidance, "ocsp") || !strings.Contains(guidance, "soft-fail") {
		t.Fatalf("client-context guidance is incomplete: %q", response.Guidance)
	}
}
