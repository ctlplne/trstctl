// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// familySink records every request a tenant-authored channel delivers, per
// path: the exact body bytes and the headers, so the test can prove the wire
// shape each family expects and the credential the tenant referenced.
type familySink struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  map[string][][]byte
	headers map[string][]http.Header
}

func newFamilySink(t *testing.T) *familySink {
	t.Helper()
	s := &familySink{bodies: map[string][][]byte{}, headers: map[string][]http.Header{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies[r.URL.Path] = append(s.bodies[r.URL.Path], body)
		s.headers[r.URL.Path] = append(s.headers[r.URL.Path], r.Header.Clone())
		s.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *familySink) one(t *testing.T, path string) ([]byte, http.Header) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bodies[path]) != 1 {
		t.Fatalf("deliveries to %s = %d, want exactly 1", path, len(s.bodies[path]))
	}
	return s.bodies[path][0], s.headers[path][0]
}

// A98: a tenant authors channels of a family (Slack, PagerDuty, a signed
// webhook, ...) with a credential reference into its own secret store. The
// outbox dispatcher used to POST the raw alert JSON to every tenant endpoint
// regardless of family and never read the credential, so a tenant Slack or
// PagerDuty channel could not work. Now each tenant channel delivers in its
// family's own wire shape, with the referenced tenant secret as its
// credential, held only for the delivery and released afterwards.
func TestServedTenantChannelsDeliverByFamilyWithTenantCredentialsA98(t *testing.T) {
	sink := newFamilySink(t)
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	if h.srv.notificationTenantChannels == nil {
		t.Fatal("the served dispatcher has no tenant channel resolver")
	}
	// The public URI stays the product-facing contract; only this injected
	// client maps the host to the owned local sink.
	h.srv.notificationTenantChannels.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Hostname() != "notifications.example.test" {
			return nil, errors.New("unexpected tenant notification host " + req.URL.Hostname())
		}
		localURL, err := url.Parse(sink.srv.URL + req.URL.Path)
		if err != nil {
			return nil, err
		}
		local := req.Clone(req.Context())
		local.URL = localURL
		local.Host = localURL.Host
		return sink.srv.Client().Do(local)
	})})
	tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write", "secrets:write")

	const (
		routingKey = "a98-routing-key-0123456789abcdef" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
		hmacKey    = "a98-webhook-hmac-key"             // #nosec G101 -- fabricated fixture credential (CWE-798)
	)
	for name, value := range map[string]string{"notifications/pagerduty/routing-key": routingKey, "notifications/webhook/hmac": hmacKey} {
		if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{"name": name, "value": value}); status != http.StatusCreated {
			t.Fatalf("store tenant secret %s: status %d body %s", name, status, body)
		}
	}

	create := func(id, credentialRef string) {
		t.Helper()
		req := map[string]any{"id": id, "channel_type": id, "label": "Tenant " + id, "endpoint_url": "https://notifications.example.test/" + id, "enabled": true}
		if credentialRef != "" {
			req["credential_ref"] = credentialRef
		}
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels", tok, "a98-create-"+id, req)
		if status != http.StatusCreated {
			t.Fatalf("create tenant %s channel: status %d body %s", id, status, body)
		}
	}
	create("slack", "")
	create("pagerduty", "secret://notifications/pagerduty/routing-key")
	create("webhook", "secret://notifications/webhook/hmac")

	// Email and SMS cannot be tenant-authored: their delivery needs SMTP or
	// gateway wiring the tenant record cannot carry, so the API says so
	// instead of accepting a channel that can never deliver.
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels", tok, "a98-create-email", map[string]any{
		"id": "email", "channel_type": "email", "endpoint_url": "https://notifications.example.test/email", "enabled": true,
	})
	if status != http.StatusBadRequest || !strings.Contains(string(body), "operator-configured") {
		t.Fatalf("tenant email channel = %d %s, want 400 naming the operator-configured families", status, body)
	}

	for _, id := range []string{"slack", "pagerduty", "webhook"} {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels/"+id+"/test", tok, "a98-test-"+id, map[string]any{
			"subject": "A98 tenant " + id, "severity": "critical",
		})
		if status != http.StatusAccepted {
			t.Fatalf("test tenant %s channel: status %d body %s", id, status, body)
		}
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain tenant channel tests: %v", err)
	}

	// Slack: the incoming-webhook shape, one text line, not the raw alert.
	slackBody, _ := sink.one(t, "/slack")
	var slack map[string]any
	if err := json.Unmarshal(slackBody, &slack); err != nil {
		t.Fatalf("slack body: %v (%s)", err, slackBody)
	}
	if text, _ := slack["text"].(string); !strings.Contains(text, "A98 tenant slack") || slack["kind"] != nil || slack["tenant_id"] != nil {
		t.Fatalf("slack delivery = %s, want {\"text\": ...} and no raw alert fields", slackBody)
	}

	// PagerDuty: an Events API v2 trigger carrying the tenant's routing key
	// read from its own secret store.
	pdBody, _ := sink.one(t, "/pagerduty")
	var pd struct {
		RoutingKey  string `json:"routing_key"`
		EventAction string `json:"event_action"`
		Payload     struct {
			Summary string `json:"summary"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(pdBody, &pd); err != nil {
		t.Fatalf("pagerduty body: %v", err)
	}
	if pd.RoutingKey != routingKey || pd.EventAction != "trigger" || !strings.Contains(pd.Payload.Summary, "A98 tenant pagerduty") {
		t.Fatalf("pagerduty delivery = action %q key-matches %v summary %q", pd.EventAction, pd.RoutingKey == routingKey, pd.Payload.Summary)
	}

	// Webhook: the alert JSON signed under the tenant's HMAC key.
	whBody, whHeaders := sink.one(t, "/webhook")
	want := "sha256=" + hex.EncodeToString(crypto.HMACSHA256([]byte(hmacKey), whBody))
	if got := whHeaders.Get("X-Trstctl-Signature"); got != want {
		t.Fatalf("webhook signature = %q, want the HMAC under the tenant's referenced key", got)
	}
	var wh map[string]any
	if err := json.Unmarshal(whBody, &wh); err != nil || wh["kind"] != "notification.channel_test" {
		t.Fatalf("webhook body = %s (%v), want the alert JSON", whBody, err)
	}

	// The channel list says how each tenant row delivers, per family.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/notification-channels", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("channel list = %d %s", status, body)
	}
	var list struct {
		Items []struct {
			ID       string `json:"id"`
			Source   string `json:"source"`
			Delivery string `json:"delivery"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode channel list: %v", err)
	}
	delivery := map[string]string{}
	for _, item := range list.Items {
		if item.Source == "tenant" {
			delivery[item.ID] = item.Delivery
		}
	}
	if !strings.Contains(delivery["slack"], "Slack incoming-webhook") || !strings.Contains(delivery["pagerduty"], "routing key") || !strings.Contains(delivery["webhook"], "HMAC-signed") {
		t.Fatalf("tenant channel delivery descriptions = %v, want per-family wording", delivery)
	}
	if strings.Contains(string(body), routingKey) || strings.Contains(string(body), hmacKey) {
		t.Fatal("channel list leaked a tenant credential value")
	}
}
