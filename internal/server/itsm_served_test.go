package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestServedServiceNowITSMTicketCAPDEP04EndToEnd(t *testing.T) {
	sink := newServiceNowSink(t)
	t.Setenv("TRSTCTL_SERVICENOW_TOKEN", "servicenow-test-token")
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "incidents:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/itsm/servicenow/tickets", tok, "itsm-servicenow-cap-dep-04", map[string]any{
		"instance_url":           sink.URL(),
		"table":                  "incident",
		"token_ref":              "env:TRSTCTL_SERVICENOW_TOKEN",
		"short_description":      "Rotate exposed TLS private key",
		"description":            "trstctl detected a compromised non-human identity and opened the ITSM workflow.",
		"category":               "security",
		"urgency":                "1",
		"impact":                 "2",
		"correlation_id":         "cred-incident-42",
		"allow_private_endpoint": true,
	})
	if status != http.StatusAccepted {
		t.Fatalf("create ServiceNow ticket: status %d body %s", status, body)
	}
	var queued struct {
		ID             string `json:"id"`
		Provider       string `json:"provider"`
		Destination    string `json:"destination"`
		Table          string `json:"table"`
		Status         string `json:"status"`
		OutboxID       int64  `json:"outbox_id"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued ticket: %v", err)
	}
	if queued.Provider != "servicenow" || queued.Destination != orchestrator.DestinationITSMServiceNow || queued.Table != "incident" || queued.Status != "queued" || queued.OutboxID == 0 || queued.IdempotencyKey == "" {
		t.Fatalf("bad queued response: %+v", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain ServiceNow outbox: %v", err)
	}

	req := sink.Last()
	if req.Path != "/api/now/table/incident" {
		t.Fatalf("ServiceNow path = %q, want Table API incident path", req.Path)
	}
	if got, want := req.Authorization, "Bearer servicenow-test-token"; got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
	if req.IdempotencyKey != queued.IdempotencyKey || req.TrstctlIdempotencyKey != queued.IdempotencyKey {
		t.Fatalf("idempotency headers = %q/%q, want %q", req.IdempotencyKey, req.TrstctlIdempotencyKey, queued.IdempotencyKey)
	}
	if got := req.Body["short_description"]; got != "Rotate exposed TLS private key" {
		t.Fatalf("short_description = %q", got)
	}
	if got := req.Body["correlation_id"]; got != "cred-incident-42" {
		t.Fatalf("correlation_id = %q", got)
	}
	if got := req.Body["u_trstctl_ticket"]; got != queued.ID {
		t.Fatalf("u_trstctl_ticket = %q, want %q", got, queued.ID)
	}
	var outboxStatus string
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT status
		   FROM outbox
		  WHERE tenant_id = $1
		    AND id = $2
		    AND destination = $3`,
		h.tenant, queued.OutboxID, orchestrator.DestinationITSMServiceNow).Scan(&outboxStatus); err != nil {
		t.Fatalf("load ServiceNow outbox row: %v", err)
	}
	if outboxStatus != "delivered" {
		t.Fatalf("ServiceNow outbox status = %q, want delivered", outboxStatus)
	}
	if !h.hasEvent(t, orchestrator.EventITSMTicketRequested) {
		t.Fatal("missing itsm.ticket.requested event")
	}
}

func TestServedServiceNowTicketRejectsInlineToken(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "incidents:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/itsm/servicenow/tickets", tok, "itsm-servicenow-inline-token", map[string]any{
		"instance_url":      "https://example.service-now.com",
		"table":             "incident",
		"token":             "inline-secret-must-not-enter-event-log",
		"short_description": "bad",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("inline token status = %d body %s", status, body)
	}
}

type serviceNowRequest struct {
	Path                  string
	Authorization         string
	IdempotencyKey        string
	TrstctlIdempotencyKey string
	TrstctlCorrelationID  string
	Body                  map[string]string
}

type serviceNowSink struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	last   serviceNowRequest
}

func newServiceNowSink(t *testing.T) *serviceNowSink {
	t.Helper()
	sink := &serviceNowSink{t: t}
	sink.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode ServiceNow body: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		sink.mu.Lock()
		sink.last = serviceNowRequest{
			Path:                  r.URL.Path,
			Authorization:         r.Header.Get("Authorization"),
			IdempotencyKey:        r.Header.Get("Idempotency-Key"),
			TrstctlIdempotencyKey: r.Header.Get("X-Trstctl-Idempotency-Key"),
			TrstctlCorrelationID:  r.Header.Get("X-Trstctl-Correlation-ID"),
			Body:                  body,
		}
		sink.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":{"sys_id":"incident-123"}}`))
	}))
	t.Cleanup(sink.server.Close)
	return sink
}

func (s *serviceNowSink) URL() string {
	return s.server.URL
}

func (s *serviceNowSink) Last() serviceNowRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}
