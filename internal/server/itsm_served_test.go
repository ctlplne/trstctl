package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestServedServiceNowITSMTicketCAPDEP04EndToEnd(t *testing.T) {
	sink := newServiceNowSink(t)
	t.Setenv("TRSTCTL_SERVICENOW_TOKEN", "servicenow-test-token")
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{
			InstanceURL:          sink.URL(),
			TokenRef:             "env:TRSTCTL_SERVICENOW_TOKEN",
			AllowPrivateEndpoint: true,
			PrivateEgressCIDRs:   []string{serviceNowSinkCIDR(t, sink.URL())},
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "incidents:write", string(authz.PrivateEgress))

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

func TestServedServiceNowTicketRejectsUnapprovedSecretBackedEgress(t *testing.T) {
	approved := newServiceNowSink(t)
	unapproved := newServiceNowSink(t)
	t.Setenv("TRSTCTL_SERVICENOW_TOKEN", "servicenow-test-token")
	t.Setenv("TRSTCTL_AWS_SECRET_ACCESS_KEY", "do-not-send-this-to-servicenow")
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{
			InstanceURL:          approved.URL(),
			TokenRef:             "env:TRSTCTL_SERVICENOW_TOKEN",
			AllowPrivateEndpoint: true,
			PrivateEgressCIDRs:   []string{serviceNowSinkCIDR(t, approved.URL())},
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "incidents:write", string(authz.PrivateEgress))

	base := map[string]any{
		"instance_url":           approved.URL(),
		"table":                  "incident",
		"token_ref":              "env:TRSTCTL_SERVICENOW_TOKEN",
		"short_description":      "bad egress",
		"allow_private_endpoint": true,
	}
	for _, tc := range []struct {
		name  string
		patch map[string]any
	}{
		{
			name:  "arbitrary_token_ref",
			patch: map[string]any{"token_ref": "env:TRSTCTL_AWS_SECRET_ACCESS_KEY"},
		},
		{
			name:  "unapproved_instance_url",
			patch: map[string]any{"instance_url": "https://attacker.example.test"},
		},
		{
			name: "unapproved_private_endpoint",
			patch: map[string]any{
				"instance_url":           unapproved.URL(),
				"allow_private_endpoint": true,
			},
		},
	} {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		for k, v := range tc.patch {
			body[k] = v
		}
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/itsm/servicenow/tickets", tok, "itsm-servicenow-red-002-"+tc.name, body)
		if status != http.StatusBadRequest {
			t.Fatalf("%s status = %d body %s", tc.name, status, raw)
		}
	}

	if got := serviceNowOutboxCount(t, h); got != 0 {
		t.Fatalf("rejected ServiceNow requests queued %d outbox row(s)", got)
	}
}

func TestServedServiceNowPrivateEndpointRequiresPrivateEgressPermission(t *testing.T) {
	sink := newServiceNowSink(t)
	t.Setenv("TRSTCTL_SERVICENOW_TOKEN", "servicenow-test-token")
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{
			InstanceURL:          sink.URL(),
			TokenRef:             "env:TRSTCTL_SERVICENOW_TOKEN",
			AllowPrivateEndpoint: true,
			PrivateEgressCIDRs:   []string{serviceNowSinkCIDR(t, sink.URL())},
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "incidents:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/itsm/servicenow/tickets", tok, "itsm-private-egress-denied", map[string]any{
		"instance_url":           sink.URL(),
		"table":                  "incident",
		"token_ref":              "env:TRSTCTL_SERVICENOW_TOKEN",
		"short_description":      "private egress needs a separate grant",
		"allow_private_endpoint": true,
	})
	if status != http.StatusForbidden {
		t.Fatalf("private ServiceNow egress without %s = %d body %s", authz.PrivateEgress, status, body)
	}
	if got := serviceNowOutboxCount(t, h); got != 0 {
		t.Fatalf("denied private ServiceNow request queued %d outbox row(s)", got)
	}
}

func TestServedServiceNowPrivateEndpointRequiresCIDRGrant(t *testing.T) {
	sink := newServiceNowSink(t)
	t.Setenv("TRSTCTL_SERVICENOW_TOKEN", "servicenow-test-token")
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ServiceNowBindings = []api.ServiceNowBinding{{
			InstanceURL:          sink.URL(),
			TokenRef:             "env:TRSTCTL_SERVICENOW_TOKEN",
			AllowPrivateEndpoint: true,
		}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "incidents:write", string(authz.PrivateEgress))

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/itsm/servicenow/tickets", tok, "itsm-private-egress-missing-cidr", map[string]any{
		"instance_url":           sink.URL(),
		"table":                  "incident",
		"token_ref":              "env:TRSTCTL_SERVICENOW_TOKEN",
		"short_description":      "private egress needs an operator CIDR grant",
		"allow_private_endpoint": true,
	})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("private ServiceNow egress without CIDR grant = %d body %s", status, body)
	}
	if got := serviceNowOutboxCount(t, h); got != 0 {
		t.Fatalf("misconfigured private ServiceNow request queued %d outbox row(s)", got)
	}
}

func serviceNowOutboxCount(t *testing.T, h *servedHarness) int {
	t.Helper()
	var count int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*)
		   FROM outbox
		  WHERE tenant_id = $1
		    AND destination = $2`,
		h.tenant, orchestrator.DestinationITSMServiceNow).Scan(&count); err != nil {
		t.Fatalf("count ServiceNow outbox rows: %v", err)
	}
	return count
}

func allowOutboundEnvCredentialRefs(refs ...string) func(*Deps) {
	return func(d *Deps) {
		d.OutboundEnvCredentialRefs = append(d.OutboundEnvCredentialRefs, refs...)
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

func serviceNowSinkCIDR(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse ServiceNow sink URL: %v", err)
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		t.Fatalf("parse ServiceNow sink host %q as IP: %v", u.Hostname(), err)
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).String()
}
