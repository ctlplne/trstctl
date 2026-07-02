package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/notify"
	notifyemail "trstctl.com/trstctl/internal/notify/email"
	"trstctl.com/trstctl/internal/notify/siem"
	"trstctl.com/trstctl/internal/notify/slack"
	"trstctl.com/trstctl/internal/notify/sms"
	"trstctl.com/trstctl/internal/notify/teams"
	"trstctl.com/trstctl/internal/notify/webhook"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestServedLifecycleSchedulerDispatchesExpiryWebhookNotification(t *testing.T) {
	secret := []byte("served-expiry-webhook-test-secret")
	sink := newServedWebhookSink(t, secret)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleAlertBefore = 7 * 24 * time.Hour
		d.NotificationChannels = []notify.Notifier{
			webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "notif-01-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	const name = "notif-01-expiring.served.test"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     name,
		"owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to":     "issued",
		"reason": "NOTIF-01 initial issue",
	})
	if status != http.StatusOK {
		t.Fatalf("issue transition: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue: %v", err)
	}

	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, name)
	if err != nil {
		t.Fatalf("load issued cert: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("issued certs = %d, want 1", len(certs))
	}
	cert := certs[0]
	now := time.Now().UTC()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(72 * time.Hour)
	cert.NotBefore = &notBefore
	cert.NotAfter = &notAfter
	if _, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, cert); err != nil {
		t.Fatalf("record near-expiry certificate: %v", err)
	}

	queued, err := h.srv.RunLifecycleOnce(t.Context())
	if err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if queued != 0 {
		t.Fatalf("renewals queued = %d, want 0; this test only enables expiry alerting", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain notification outbox: %v", err)
	}

	alert := sink.LastAlert()
	if sink.Accepted() != 1 {
		t.Fatalf("webhook accepted %d expiry notifications, want 1", sink.Accepted())
	}
	if alert.Kind != notify.KindCertificateExpiry || alert.TenantID != h.tenant || alert.CertificateID != cert.ID || alert.Subject != cert.Subject || alert.Serial != cert.Serial {
		t.Fatalf("bad webhook alert: %+v, cert=%+v", alert, cert)
	}
	if !alert.NotAfter.Equal(notAfter) {
		t.Fatalf("alert not_after = %s, want %s", alert.NotAfter.Format(time.RFC3339), notAfter.Format(time.RFC3339))
	}
	got, err := h.store.GetCertificate(t.Context(), h.tenant, cert.ID)
	if err != nil {
		t.Fatalf("reload cert: %v", err)
	}
	if got.AlertedAt == nil {
		t.Fatal("certificate was not stamped alerted_at after served expiry notification enqueue")
	}
	var outboxStatus string
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT status
		   FROM outbox
		  WHERE tenant_id = $1
		    AND destination = $2
		    AND idempotency_key = $3`,
		h.tenant, notify.DestinationExpiry, "expiry:"+cert.ID).Scan(&outboxStatus); err != nil {
		t.Fatalf("load notification outbox row: %v", err)
	}
	if outboxStatus != "delivered" {
		t.Fatalf("notification outbox status = %q, want delivered", outboxStatus)
	}
	if !h.hasEvent(t, "certificate.expiring") {
		t.Fatal("missing certificate.expiring event")
	}
}

func TestServedMultiChannelAlertingCAPOBS05(t *testing.T) {
	httpSink := newMultiChannelHTTPSink(t)
	emailSink := &capturingEmailSender{}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleAlertBefore = 7 * 24 * time.Hour
		d.NotificationChannels = []notify.Notifier{
			notifyemail.New("smtp.example:587", "alerts@example.test", []string{"oncall@example.test"}, notifyemail.WithSender(emailSink)),
			slack.New(httpSink.URL("/slack"), slack.WithHTTPClient(httpSink.Client())),
			teams.New(httpSink.URL("/teams"), teams.WithHTTPClient(httpSink.Client())),
			sms.New(httpSink.URL("/sms"), "trstctl", []string{"+15550100"}, []byte("sms-token"), sms.WithHTTPClient(httpSink.Client())),
			siem.New(httpSink.URL("/siem"), []byte("siem-token"), siem.WithHTTPClient(httpSink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue",
		"notifications:read",
	)

	cert := seedNearExpiryNotificationCertificate(t, h, tok, "cap-obs-05-multichannel.served.test")
	if _, err := h.srv.RunLifecycleOnce(t.Context()); err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain notification outbox: %v", err)
	}

	if emailSink.deliveries() != 1 {
		t.Fatalf("email deliveries = %d, want 1", emailSink.deliveries())
	}
	for _, path := range []string{"/slack", "/teams", "/sms", "/siem"} {
		if got := httpSink.Count(path); got != 1 {
			t.Fatalf("%s deliveries = %d, want 1", path, got)
		}
	}
	var outboxStatus string
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT status
		   FROM outbox
		  WHERE tenant_id = $1
		    AND destination = $2
		    AND idempotency_key = $3`,
		h.tenant, notify.DestinationExpiry, "expiry:"+cert.ID).Scan(&outboxStatus); err != nil {
		t.Fatalf("load notification outbox row: %v", err)
	}
	if outboxStatus != "delivered" {
		t.Fatalf("notification outbox status = %q, want delivered", outboxStatus)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/notification-channels", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list notification channels: status %d body %s", status, body)
	}
	var channels struct {
		Items []struct {
			ID         string `json:"id"`
			Configured bool   `json:"configured"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &channels); err != nil {
		t.Fatalf("decode channel catalog: %v", err)
	}
	configured := map[string]bool{}
	for _, item := range channels.Items {
		if item.Configured {
			configured[item.ID] = true
		}
	}
	for _, want := range []string{"email", "slack", "msteams", "sms", "siem"} {
		if !configured[want] {
			t.Fatalf("configured channel catalog = %#v, missing %q", configured, want)
		}
	}
}

func TestServedNotificationRoutingPolicyAuthoringAndChannelTestDESIGN003(t *testing.T) {
	httpSink := newMultiChannelHTTPSink(t)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{
			slack.New(httpSink.URL("/slack"), slack.WithHTTPClient(httpSink.Client())),
			webhook.New(httpSink.URL("/webhook"), []byte("webhook-test-secret"), webhook.WithHTTPClient(httpSink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-routing-policies", tok, "design-003-policy-create", map[string]any{
		"name": "Expiry escalation",
		"channels_by_severity": map[string][]string{
			"critical": {"slack", "webhook"},
			"warning":  {"slack"},
		},
		"default_channels":        []string{"webhook"},
		"owner_ref":               "team/platform-security",
		"owner_email":             "platform-security@example.test",
		"digest_interval_seconds": 43200,
		"digest_timezone":         "UTC",
	})
	if status != http.StatusCreated {
		t.Fatalf("create notification routing policy: status %d body %s", status, body)
	}
	var created struct {
		ID                 string              `json:"id"`
		Name               string              `json:"name"`
		ChannelsBySeverity map[string][]string `json:"channels_by_severity"`
		DefaultChannels    []string            `json:"default_channels"`
		OwnerEmail         string              `json:"owner_email"`
		DigestPreview      struct {
			IntervalSeconds int    `json:"interval_seconds"`
			Timezone        string `json:"timezone"`
			NextRunAt       string `json:"next_run_at"`
		} `json:"digest_preview"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created policy: %v (%s)", err, body)
	}
	if created.ID == "" || created.Name != "Expiry escalation" || created.OwnerEmail != "platform-security@example.test" {
		t.Fatalf("bad created policy: %+v", created)
	}
	if got := created.ChannelsBySeverity["critical"]; len(got) != 2 || got[0] != "slack" || got[1] != "webhook" {
		t.Fatalf("critical routes = %#v, want slack + webhook", got)
	}
	if len(created.DefaultChannels) != 1 || created.DefaultChannels[0] != "webhook" {
		t.Fatalf("default routes = %#v, want webhook", created.DefaultChannels)
	}
	if created.DigestPreview.IntervalSeconds != 43200 || created.DigestPreview.Timezone != "UTC" || created.DigestPreview.NextRunAt == "" {
		t.Fatalf("bad digest preview: %+v", created.DigestPreview)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/notification-routing-policies", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list notification routing policies: status %d body %s", status, body)
	}
	if !strings.Contains(string(body), "Expiry escalation") || !strings.Contains(string(body), "platform-security@example.test") {
		t.Fatalf("policy list did not show authored policy: %s", body)
	}

	const rawSlackSecretRef = "secret://notifications/slack/raw-webhook-url"
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels/slack/test", tok, "design-003-slack-test", map[string]any{
		"subject":           "design-003 slack",
		"severity":          "critical",
		"detail":            "routing policy channel test",
		"routing_policy_id": created.ID,
		"credential_ref":    rawSlackSecretRef,
	})
	if status != http.StatusAccepted {
		t.Fatalf("test slack channel: status %d body %s", status, body)
	}
	if strings.Contains(string(body), rawSlackSecretRef) || !strings.Contains(string(body), `"credential_ref":"redacted"`) {
		t.Fatalf("channel test response leaked or failed to redact credential ref: %s", body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain slack channel test: %v", err)
	}
	if got := httpSink.Count("/slack"); got != 1 {
		t.Fatalf("slack test deliveries = %d, want 1", got)
	}
	if got := httpSink.Count("/webhook"); got != 0 {
		t.Fatalf("webhook deliveries after slack test = %d, want 0", got)
	}

	const rawWebhookSecretRef = "secret://notifications/webhook/hmac-key"
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels/webhook/test", tok, "design-003-webhook-test", map[string]any{
		"subject":        "design-003 webhook",
		"severity":       "warning",
		"credential_ref": rawWebhookSecretRef,
	})
	if status != http.StatusAccepted {
		t.Fatalf("test webhook channel: status %d body %s", status, body)
	}
	if strings.Contains(string(body), rawWebhookSecretRef) {
		t.Fatalf("webhook test response leaked credential ref: %s", body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain webhook channel test: %v", err)
	}
	if got := httpSink.Count("/webhook"); got != 1 {
		t.Fatalf("webhook test deliveries = %d, want 1", got)
	}
	if !h.hasEvent(t, "notification.routing_policy.upserted") {
		t.Fatal("missing notification.routing_policy.upserted event")
	}
}

func TestServedTenantNotificationChannelLifecycleTRACE007(t *testing.T) {
	httpSink := newMultiChannelHTTPSink(t)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {})
	resolver := notify.NewStoreChannelResolver(h.store)
	resolver.SetHTTPClient(httpSink.Client())
	h.srv.notifications.SetChannelResolver(resolver)
	tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")

	const rawCredentialRef = "secret://notifications/webhook/hmac-key"
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels", tok, "trace-007-channel-create", map[string]any{
		"id":             "webhook",
		"channel_type":   "webhook",
		"label":          "Tenant webhook",
		"endpoint_url":   httpSink.URL("/tenant-webhook"),
		"credential_ref": rawCredentialRef,
		"enabled":        true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create tenant notification channel: status %d body %s", status, body)
	}
	if strings.Contains(string(body), rawCredentialRef) {
		t.Fatalf("channel create response leaked credential ref: %s", body)
	}
	var created struct {
		ID             string `json:"id"`
		ChannelType    string `json:"channel_type"`
		Configured     bool   `json:"configured"`
		CredentialRef  string `json:"credential_ref"`
		SecretHandling string `json:"secret_handling"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created channel: %v (%s)", err, body)
	}
	if created.ID != "webhook" || created.ChannelType != "webhook" || !created.Configured || created.CredentialRef != "redacted" || created.SecretHandling == "" {
		t.Fatalf("bad created channel response: %+v", created)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/notification-channels", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list tenant notification channels: status %d body %s", status, body)
	}
	if strings.Contains(string(body), rawCredentialRef) || !strings.Contains(string(body), "Tenant webhook") {
		t.Fatalf("channel list leaked credential ref or omitted tenant channel: %s", body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels/webhook/test", tok, "trace-007-channel-test", map[string]any{
		"subject":  "TRACE-007 tenant-authored webhook",
		"severity": "critical",
	})
	if status != http.StatusAccepted {
		t.Fatalf("test tenant notification channel: status %d body %s", status, body)
	}
	if strings.Contains(string(body), rawCredentialRef) {
		t.Fatalf("channel test response leaked credential ref: %s", body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain tenant notification channel test: %v", err)
	}
	if got := httpSink.Count("/tenant-webhook"); got != 1 {
		t.Fatalf("tenant-authored webhook deliveries = %d, want 1", got)
	}
	if !h.hasEvent(t, "notification.channel.upserted") {
		t.Fatal("missing notification.channel.upserted event")
	}
}

func TestServedExpiryEscalatesToOwnerAndApproversCAPLIFE04(t *testing.T) {
	secret := []byte("served-expiry-escalation-test-secret")
	sink := newServedWebhookSink(t, secret)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleAlertBefore = 7 * 24 * time.Hour
		d.NotificationChannels = []notify.Notifier{
			webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write",
		"identities:read", "identities:write",
		"certs:read", "certs:issue",
		"notifications:read",
	)

	if _, err := h.srv.orch.UpsertTenantMember(t.Context(), h.tenant, store.TenantMember{
		Subject: "ra-one@example.test", DisplayName: "RA One", Email: "ra-one@example.test",
		Roles: []string{"operator"}, Source: "test",
	}); err != nil {
		t.Fatalf("seed operator approver: %v", err)
	}
	if _, err := h.srv.orch.UpsertTenantMember(t.Context(), h.tenant, store.TenantMember{
		Subject: "ra-two@example.test", DisplayName: "RA Two", Email: "ra-two@example.test",
		Roles: []string{"admin"}, Source: "test",
	}); err != nil {
		t.Fatalf("seed admin approver: %v", err)
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind":  "team",
		"name":  "Payments owners",
		"email": "payments-owner@example.test",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	const name = "cap-life-04-expiring.served.test"
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     name,
		"owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to":     "issued",
		"reason": "CAP-LIFE-04 initial issue",
	})
	if status != http.StatusOK {
		t.Fatalf("issue transition: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue: %v", err)
	}

	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, name)
	if err != nil {
		t.Fatalf("load issued cert: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("issued certs = %d, want 1", len(certs))
	}
	cert := certs[0]
	now := time.Now().UTC()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(5 * 24 * time.Hour)
	cert.NotBefore = &notBefore
	cert.NotAfter = &notAfter
	if _, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, cert); err != nil {
		t.Fatalf("record near-expiry certificate: %v", err)
	}

	if _, err := h.srv.RunLifecycleOnce(t.Context()); err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain notification outbox: %v", err)
	}

	alert := sink.LastAlert()
	if alert.OwnerID != owner.ID || alert.OwnerName != owner.Name || alert.OwnerEmail != owner.Email {
		t.Fatalf("alert owner fields = id:%q name:%q email:%q, want %+v", alert.OwnerID, alert.OwnerName, alert.OwnerEmail, owner)
	}
	if alert.Severity != notify.AlertSeverityCritical {
		t.Fatalf("alert severity = %q, want %q", alert.Severity, notify.AlertSeverityCritical)
	}
	if alert.ThresholdDays == nil || *alert.ThresholdDays != 5 {
		t.Fatalf("alert threshold_days = %v, want 5", alert.ThresholdDays)
	}
	if !hasAlertRecipient(alert.EscalationRecipients, "owner", owner.ID, owner.Email) {
		t.Fatalf("alert escalation recipients missing owner: %+v", alert.EscalationRecipients)
	}
	if !hasAlertRecipient(alert.EscalationRecipients, "approver", "ra-one@example.test", "ra-one@example.test") ||
		!hasAlertRecipient(alert.EscalationRecipients, "approver", "ra-two@example.test", "ra-two@example.test") {
		t.Fatalf("alert escalation recipients missing approvers: %+v", alert.EscalationRecipients)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/notifications?limit=10", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list notifications: status %d body %s", status, body)
	}
	var listed struct {
		Items []struct {
			OwnerEmail           string                  `json:"owner_email"`
			EscalationRecipients []notify.AlertRecipient `json:"escalation_recipients"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode notifications: %v (%s)", err, body)
	}
	if len(listed.Items) == 0 || listed.Items[0].OwnerEmail != owner.Email {
		t.Fatalf("notification inbox owner email = %+v, want %q", listed.Items, owner.Email)
	}
	if !hasAlertRecipient(listed.Items[0].EscalationRecipients, "approver", "ra-one@example.test", "ra-one@example.test") {
		t.Fatalf("notification inbox missing approver escalation: %+v", listed.Items[0].EscalationRecipients)
	}
}

func TestServedNotificationAPIDeadLetterRequeueAndRead(t *testing.T) {
	ch := &flakyNotificationChannel{err: errors.New("smtp unavailable")}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{ch}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")

	alert := notify.Alert{
		Kind:          notify.KindCertificateExpiry,
		TenantID:      h.tenant,
		CertificateID: "cert-dead-letter-001",
		Subject:       "cn=dead-letter.served.test",
		Severity:      notify.AlertSeverityCritical,
		Detail:        "operator must see this failed dispatch",
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("marshal alert: %v", err)
	}
	var outboxID int64
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		id, err := h.srv.outbox.Enqueue(context.Background(), tx, orchestrator.Entry{
			TenantID:       h.tenant,
			Destination:    notify.DestinationExpiry,
			IdempotencyKey: "notif-c8-3-dead-letter",
			Payload:        payload,
		})
		outboxID = id
		return err
	}); err != nil {
		t.Fatalf("enqueue notification outbox: %v", err)
	}
	if _, err := h.store.SystemPool().Exec(context.Background(),
		`UPDATE outbox
		    SET status = 'failed',
		        attempts = 10,
		        last_error = 'smtp unavailable',
		        next_attempt_at = now()
		  WHERE tenant_id = $1 AND id = $2`,
		h.tenant, outboxID); err != nil {
		t.Fatalf("force failed notification row: %v", err)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/notifications?status=dead", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list dead notifications: status %d body %s", status, body)
	}
	var listed struct {
		Items []struct {
			ID            string `json:"id"`
			Status        string `json:"status"`
			Attempts      int    `json:"attempts"`
			LastError     string `json:"last_error"`
			CertificateID string `json:"certificate_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Items) != 1 {
		t.Fatalf("dead notification count = %d, want 1; body %s", len(listed.Items), body)
	}
	notificationID := listed.Items[0].ID
	if notificationID == "" || listed.Items[0].Status != "dead" || listed.Items[0].LastError == "" || listed.Items[0].CertificateID != alert.CertificateID {
		t.Fatalf("bad dead notification: %+v", listed.Items[0])
	}

	ch.err = nil
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/notifications/"+notificationID+"/requeue", tok, "notif-c8-3-requeue", nil)
	if status != http.StatusOK {
		t.Fatalf("requeue notification: status %d body %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/notifications/"+notificationID+"/requeue", tok, "notif-c8-3-requeue", nil)
	if status != http.StatusOK {
		t.Fatalf("replay requeue notification: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain requeued notification: %v", err)
	}
	if ch.deliveries() != 1 {
		t.Fatalf("requeued notification deliveries = %d, want 1", ch.deliveries())
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/notifications/"+notificationID+"/read", tok, "notif-c8-3-read", nil)
	if status != http.StatusOK {
		t.Fatalf("mark notification read: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/notifications/"+notificationID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get notification: status %d body %s", status, body)
	}
	var got struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		ReadAt string `json:"read_at"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.ID != notificationID || got.Status != "read" || got.ReadAt == "" {
		t.Fatalf("read notification = %+v, want id %s with read status", got, notificationID)
	}
}

type servedWebhookSink struct {
	srv    *httptest.Server
	secret []byte

	mu       sync.Mutex
	accepted int
	last     notify.Alert
}

type flakyNotificationChannel struct {
	mu    sync.Mutex
	err   error
	count int
}

type capturingEmailSender struct {
	mu    sync.Mutex
	count int
}

func (s *capturingEmailSender) Send(context.Context, string, []string, []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return nil
}

func (s *capturingEmailSender) deliveries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

type multiChannelHTTPSink struct {
	srv *httptest.Server

	mu     sync.Mutex
	counts map[string]int
}

func (f *flakyNotificationChannel) Name() string { return "email" }

func (f *flakyNotificationChannel) Notify(context.Context, notify.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.count++
	return nil
}

func (f *flakyNotificationChannel) deliveries() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

func newMultiChannelHTTPSink(t *testing.T) *multiChannelHTTPSink {
	t.Helper()
	s := &multiChannelHTTPSink{counts: make(map[string]int)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.counts[r.URL.Path]++
		s.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *multiChannelHTTPSink) URL(path string) string { return s.srv.URL + path }
func (s *multiChannelHTTPSink) Client() *http.Client   { return s.srv.Client() }

func (s *multiChannelHTTPSink) Count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[path]
}

func seedNearExpiryNotificationCertificate(t *testing.T, h *servedHarness, tok, name string) store.Certificate {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": name + "-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     name,
		"owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create identity: status %d body %s", status, body)
	}
	var ident struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ident); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
		"to":     "issued",
		"reason": "CAP-OBS-05 initial issue",
	})
	if status != http.StatusOK {
		t.Fatalf("issue transition: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain issue: %v", err)
	}

	certs, err := h.store.ListActiveIssuedCertificatesForIdentity(t.Context(), h.tenant, owner.ID, name)
	if err != nil {
		t.Fatalf("load issued cert: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("issued certs = %d, want 1", len(certs))
	}
	cert := certs[0]
	now := time.Now().UTC()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(72 * time.Hour)
	cert.NotBefore = &notBefore
	cert.NotAfter = &notAfter
	if _, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, cert); err != nil {
		t.Fatalf("record near-expiry certificate: %v", err)
	}
	return cert
}

func hasAlertRecipient(recipients []notify.AlertRecipient, kind, subject, email string) bool {
	for _, r := range recipients {
		if r.Kind == kind && r.Subject == subject && r.Email == email {
			return true
		}
	}
	return false
}

func newServedWebhookSink(t *testing.T, secret []byte) *servedWebhookSink {
	t.Helper()
	s := &servedWebhookSink{secret: append([]byte(nil), secret...)}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *servedWebhookSink) URL() string          { return s.srv.URL }
func (s *servedWebhookSink) Client() *http.Client { return s.srv.Client() }

func (s *servedWebhookSink) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

func (s *servedWebhookSink) LastAlert() notify.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *servedWebhookSink) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	want := "sha256=" + hex.EncodeToString(crypto.HMACSHA256(s.secret, body))
	if got := r.Header.Get("X-Trstctl-Signature"); got != want {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}
	var alert notify.Alert
	if err := json.Unmarshal(body, &alert); err != nil {
		http.Error(w, `{"error":"malformed alert"}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.accepted++
	s.last = alert
	s.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}
