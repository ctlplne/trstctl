package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/slack"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedResponseIntegrationsCAPREM03EndToEnd(t *testing.T) {
	httpSink := newResponseIntegrationHTTPSink(t)
	serviceNowSink := newServiceNowSink(t)
	t.Setenv("TRSTCTL_SPLUNK_TOKEN", "splunk-response-token")
	t.Setenv("TRSTCTL_JIRA_TOKEN", "jira-response-token")
	t.Setenv("TRSTCTL_SERVICENOW_TOKEN", "servicenow-response-token")

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_SPLUNK_TOKEN", "env:TRSTCTL_JIRA_TOKEN"}
		d.EnableRemediation = true
		d.ServiceNowBindings = []api.ServiceNowBinding{{
			InstanceURL:          serviceNowSink.URL(),
			TokenRef:             "env:TRSTCTL_SERVICENOW_TOKEN",
			AllowPrivateEndpoint: true,
			PrivateEgressCIDRs:   []string{serviceNowSinkCIDR(t, serviceNowSink.URL())},
		}}
		d.NotificationChannels = []notify.Notifier{
			slack.New(httpSink.URL("/slack"), slack.WithHTTPClient(httpSink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "incidents:write", string(authz.PrivateEgress))

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/incidents/response-integrations/dispatch", tok, "cap-rem-03-response-dispatch", map[string]any{
		"incident_id":    "incident-42",
		"title":          "Contain compromised payments credential",
		"summary":        "Replacement issued, old identity revoked, playbook evidence attached.",
		"severity":       "critical",
		"correlation_id": "incident-42",
		"evidence_refs":  []string{"incident.execution/incident-42", "remediation.playbook/run-42"},
		"destinations": []map[string]any{
			{"id": "splunk-hec", "provider": "splunk", "endpoint_url": httpSink.URL("/splunk"), "token_ref": "env:TRSTCTL_SPLUNK_TOKEN", "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, httpSink.URL("/splunk"))}},
			{"id": "jira-sec", "provider": "jira", "endpoint_url": httpSink.URL("/jira"), "token_ref": "env:TRSTCTL_JIRA_TOKEN", "project_key": "NHI", "issue_type": "Incident", "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, httpSink.URL("/jira"))}},
			{"id": "slack-war-room", "provider": "slack"},
			{"id": "servicenow-ir", "provider": "servicenow", "instance_url": serviceNowSink.URL(), "table": "incident", "token_ref": "env:TRSTCTL_SERVICENOW_TOKEN", "allow_private_endpoint": true},
		},
	})
	if status != http.StatusAccepted {
		t.Fatalf("dispatch response integrations: status %d body %s", status, body)
	}
	var queued struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		Destinations []struct {
			Provider    string `json:"provider"`
			Destination string `json:"destination"`
			OutboxID    int64  `json:"outbox_id"`
			Status      string `json:"status"`
		} `json:"destinations"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued response integrations: %v body=%s", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" || len(queued.Destinations) != 4 {
		t.Fatalf("bad queued response integration receipt: %+v", queued)
	}
	wantDestinations := map[string]string{
		"splunk":     orchestrator.DestinationResponseSplunk,
		"jira":       orchestrator.DestinationResponseJira,
		"slack":      notify.DestinationResponse,
		"servicenow": orchestrator.DestinationITSMServiceNow,
	}
	for _, dst := range queued.Destinations {
		if dst.OutboxID == 0 || dst.Status != "queued" || wantDestinations[dst.Provider] != dst.Destination {
			t.Fatalf("bad queued destination: %+v", dst)
		}
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain response integration outbox: %v", err)
	}

	splunk := httpSink.Last("/splunk")
	if splunk.Authorization != "Splunk splunk-response-token" || splunk.IdempotencyKey == "" {
		t.Fatalf("bad Splunk request headers: %+v", splunk)
	}
	if event, ok := splunk.Body["event"].(map[string]any); !ok || event["kind"] != "trstctl.response.integration" || event["title"] != "Contain compromised payments credential" {
		t.Fatalf("bad Splunk event body: %+v", splunk.Body)
	}
	jira := httpSink.Last("/jira/rest/api/3/issue")
	if jira.Authorization != "Bearer jira-response-token" || jira.IdempotencyKey == "" {
		t.Fatalf("bad Jira request headers: %+v", jira)
	}
	fields, _ := jira.Body["fields"].(map[string]any)
	project, _ := fields["project"].(map[string]any)
	if project["key"] != "NHI" || fields["summary"] != "Contain compromised payments credential" {
		t.Fatalf("bad Jira body: %+v", jira.Body)
	}
	if httpSink.Count("/slack") != 1 {
		t.Fatalf("Slack response notifications delivered = %d, want 1", httpSink.Count("/slack"))
	}
	serviceNow := serviceNowSink.Last()
	if serviceNow.Path != "/api/now/table/incident" || serviceNow.Authorization != "Bearer servicenow-response-token" || serviceNow.Body["short_description"] != "Contain compromised payments credential" {
		t.Fatalf("bad ServiceNow response request: %+v", serviceNow)
	}
	for provider, destination := range wantDestinations {
		var delivered int
		if err := h.store.SystemPool().QueryRow(t.Context(),
			`SELECT count(*)
			   FROM outbox
			  WHERE tenant_id = $1
			    AND destination = $2
			    AND status = 'delivered'`,
			h.tenant, destination).Scan(&delivered); err != nil {
			t.Fatalf("count delivered %s outbox rows: %v", provider, err)
		}
		if delivered != 1 {
			t.Fatalf("%s delivered outbox rows = %d, want 1", provider, delivered)
		}
	}
	if !h.hasEvent(t, projections.EventResponseIntegrationDispatched) {
		t.Fatal("missing response.integration.dispatched event")
	}
}

type responseIntegrationHTTPRecord struct {
	Path           string
	Authorization  string
	IdempotencyKey string
	Body           map[string]any
}

type responseIntegrationHTTPSink struct {
	srv     *httptest.Server
	mu      sync.Mutex
	records map[string][]responseIntegrationHTTPRecord
}

func newResponseIntegrationHTTPSink(t *testing.T) *responseIntegrationHTTPSink {
	t.Helper()
	s := &responseIntegrationHTTPSink{records: map[string][]responseIntegrationHTTPRecord{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var body map[string]any
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("decode response integration body: %v body=%s", err, raw)
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
		}
		rec := responseIntegrationHTTPRecord{
			Path: r.URL.Path, Authorization: r.Header.Get("Authorization"),
			IdempotencyKey: r.Header.Get("Idempotency-Key"), Body: body,
		}
		s.mu.Lock()
		s.records[r.URL.Path] = append(s.records[r.URL.Path], rec)
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *responseIntegrationHTTPSink) URL(path string) string { return s.srv.URL + path }
func (s *responseIntegrationHTTPSink) Client() *http.Client   { return s.srv.Client() }

func (s *responseIntegrationHTTPSink) Count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records[path])
}

func (s *responseIntegrationHTTPSink) Last(path string) responseIntegrationHTTPRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := s.records[path]
	if len(items) == 0 {
		return responseIntegrationHTTPRecord{}
	}
	return items[len(items)-1]
}
