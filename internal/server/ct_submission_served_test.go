package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/events"
)

func TestServedCTSubmissionQueuesPrecertAndCertificateCAPREV06(t *testing.T) {
	certDER, _, err := ctlogtest.IssueCert("ct-submit", "ct-submit.example.com")
	if err != nil {
		t.Fatalf("issue CT submission fixture certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	logSrv := ctlogtest.NewServer()
	t.Cleanup(logSrv.Close)

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read", string(authz.PrivateEgress))
	body := map[string]any{
		"certificate_pem":        certPEM,
		"precertificate_pem":     certPEM,
		"logs":                   []string{logSrv.URL()},
		"allow_private_endpoint": true,
		"private_egress_cidrs":   []string{serviceNowSinkCIDR(t, logSrv.URL())},
	}

	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/revocation/ct-submissions", tok, "cap-rev-06-ct-submit", body)
	if status != http.StatusAccepted {
		t.Fatalf("queue CT submission: status %d body %s", status, raw)
	}
	var queued struct {
		Capability string `json:"capability"`
		Queued     int    `json:"queued"`
		Logs       []struct {
			LogURL                     string `json:"log_url"`
			PrecertificateQueued       bool   `json:"precertificate_queued"`
			CertificateQueued          bool   `json:"certificate_queued"`
			PrecertificateSubmissionID string `json:"precertificate_submission_id"`
			CertificateSubmissionID    string `json:"certificate_submission_id"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(raw, &queued); err != nil {
		t.Fatalf("decode CT submission response: %v body=%s", err, raw)
	}
	if queued.Capability != "CAP-REV-06" || queued.Queued != 2 || len(queued.Logs) != 1 {
		t.Fatalf("bad CT submission response: %+v", queued)
	}
	if got := queued.Logs[0]; got.LogURL != logSrv.URL() || !got.PrecertificateQueued || !got.CertificateQueued || got.PrecertificateSubmissionID == "" || got.CertificateSubmissionID == "" {
		t.Fatalf("bad CT log queue status: %+v", got)
	}

	status, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/revocation/ct-submissions", tok, "cap-rev-06-ct-submit", body)
	if status != http.StatusAccepted || string(replay) != string(raw) {
		t.Fatalf("CT submission idempotency replay = (%d, %s), want same 202 body %s", status, replay, raw)
	}

	rows, err := h.srv.outbox.Pending(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("pending outbox: %v", err)
	}
	ctRows := 0
	for _, row := range rows {
		if row.Destination == "ct.submit" {
			ctRows++
		}
	}
	if ctRows != 2 {
		t.Fatalf("ct.submit outbox rows = %d, want 2; rows=%+v", ctRows, rows)
	}
	var queuedEvent struct {
		Capability string `json:"capability"`
		Payloads   []struct {
			SubmissionID         string `json:"submission_id"`
			EntryType            string `json:"entry_type"`
			LeafDER              []byte `json:"leaf_der"`
			IdempotencyKey       string `json:"idempotency_key"`
			AllowPrivateEndpoint bool   `json:"allow_private_endpoint,omitempty"`
		} `json:"payloads"`
	}
	foundQueuedEvent := false
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == "ct.submission.queued" {
			foundQueuedEvent = true
			return json.Unmarshal(e.Data, &queuedEvent)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay CT queued event: %v", err)
	}
	if !foundQueuedEvent || queuedEvent.Capability != "CAP-REV-06" || len(queuedEvent.Payloads) != 2 {
		t.Fatalf("CT queued event = found %v %+v, want replayable event with two payloads", foundQueuedEvent, queuedEvent)
	}
	for _, p := range queuedEvent.Payloads {
		if p.SubmissionID == "" || p.EntryType == "" || len(p.LeafDER) == 0 || p.IdempotencyKey != "cap-rev-06-ct-submit" || !p.AllowPrivateEndpoint {
			t.Fatalf("CT queued event payload is not replayable: %+v", p)
		}
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain CT submission outbox: %v", err)
	}
	if got := len(logSrv.PrecertSubmissions()); got != 1 {
		t.Fatalf("precertificate submissions = %d, want 1", got)
	}
	if got := len(logSrv.CertSubmissions()); got != 1 {
		t.Fatalf("certificate submissions = %d, want 1", got)
	}
	if !h.hasEvent(t, "ct.submission.queued") || !h.hasEvent(t, "ct.submission.delivered") {
		t.Fatal("served CT submission did not record queued and delivered audit events")
	}
}
