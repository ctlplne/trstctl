// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestNotificationResponseRetainsLifecycleEvidence(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	alert := notify.Alert{Kind: notify.KindRenewalFailed, IdentityID: "identity-a", OperationID: "renewal-failure:event-a", CertificateID: "cert-a", CertificateFingerprint: "exact-fingerprint", DeploymentReceiptID: "receipt-a", DeploymentRecordedAt: &at, NotAfter: at.Add(time.Hour), OwnerName: "Platform SRE", OwnerEmail: "sre@example.test", RequestBinding: "private-command-binding"}
	body, err := json.Marshal(alert)
	if err != nil {
		t.Fatal(err)
	}
	response := toNotificationResponse(store.NotificationOutboxRecord{ID: 42, TenantID: "tenant-a", Payload: body})
	if response.IdentityID != alert.IdentityID || response.OperationID != alert.OperationID || response.DeploymentReceiptID != alert.DeploymentReceiptID || response.DeploymentRecordedAt == nil || !response.DeploymentRecordedAt.Equal(at) || response.CertificateFingerprint != alert.CertificateFingerprint || response.NotAfter == nil || !response.NotAfter.Equal(alert.NotAfter) {
		t.Fatalf("notification response lost lifecycle context: %+v", response)
	}
	public, _ := json.Marshal(response)
	if bytes.Contains(public, []byte(alert.RequestBinding)) {
		t.Fatal("private request binding exposed")
	}
	legacy := toNotificationResponse(store.NotificationOutboxRecord{Payload: []byte(`{"kind":"identity.renewal_failed","identity_id":"identity-a"}`)})
	if legacy.NotAfter != nil || legacy.DeploymentRecordedAt != nil || legacy.CertificateID != "" {
		t.Fatal("legacy alert acquired invented deployment evidence")
	}
}

func TestNotificationPaginationAndRoutingNormalization(t *testing.T) {
	cursor := encodeNotificationCursor(42)
	if got, err := decodeNotificationCursor(cursor); err != nil || got != 42 {
		t.Fatalf("notification cursor round trip = %d, %v", got, err)
	}
	for _, invalid := range []string{"%%%", encodeNotificationCursor(-1), "bm90LWEtbnVtYmVy"} {
		if _, err := decodeNotificationCursor(invalid); err == nil {
			t.Fatalf("decodeNotificationCursor(%q) succeeded", invalid)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/notifications?limit=7&cursor="+cursor+"&status=READ", nil)
	limit, after, status, err := notificationPageParams(req)
	if err != nil || limit != 7 || after != 42 || status != "read" {
		t.Fatalf("notificationPageParams = %d, %d, %q, %v", limit, after, status, err)
	}
	for _, target := range []string{
		"/api/v1/notifications?cursor=bad!",
		"/api/v1/notifications?order=invalid",
		"/api/v1/notifications?status=processing",
		"/api/v1/notifications?limit=1000000",
	} {
		if _, _, _, err := notificationPageParams(httptest.NewRequest(http.MethodGet, target, nil)); err == nil {
			t.Fatalf("notificationPageParams(%q) succeeded", target)
		}
	}

	for raw, want := range map[string]string{
		"": "informational", "info": "informational", " LOW ": "low", "warning": "warning", "critical": "critical",
	} {
		got, err := normalizeNotificationSeverity(raw)
		if err != nil || got != want {
			t.Fatalf("normalizeNotificationSeverity(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := normalizeNotificationSeverity("emergency"); err == nil {
		t.Fatal("normalizeNotificationSeverity accepted an unsupported severity")
	}

	supported := map[string]bool{"email": true, "msteams": true}
	channels, err := normalizeRoutingChannels([]string{" email ", "teams", "microsoft-teams", "", "email"}, supported)
	if err != nil || len(channels) != 2 || channels[0] != "email" || channels[1] != "msteams" {
		t.Fatalf("normalizeRoutingChannels = %#v, %v", channels, err)
	}
	if _, err := normalizeRoutingChannels([]string{"pagerduty"}, supported); err == nil {
		t.Fatal("normalizeRoutingChannels accepted an unconfigured channel")
	}
}

func TestNotificationResponseHelpersPreservePublicMetadataAndRedactSecrets(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	channel := toNotificationChannelResponse(store.NotificationChannel{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		TenantID: "tenant-a", ID: " Microsoft Teams ", Label: "", EndpointURL: "https://teams.example/hook",
		CredentialRef: "vault://notifications/teams", Enabled: true,
	})
	if channel.ID != "msteams" || channel.ChannelType != "msteams" || channel.Label != "Microsoft Teams" || !channel.Configured {
		t.Fatalf("channel response = %+v", channel)
	}
	if channel.CredentialRef != "redacted" || !channel.EndpointConfigured {
		t.Fatalf("channel response exposed or lost secret-reference posture: %+v", channel)
	}

	policy := store.NotificationRoutingPolicy{
		ID: "11111111-1111-4111-8111-111111111111", TenantID: "tenant-a", Name: "critical",
		ChannelsBySeverity: map[string][]string{"critical": {"email"}}, DefaultChannels: []string{"msteams"},
		UpdatedAt: now.Add(-2 * time.Hour), DigestInterval: 3600, DigestTimezone: "America/New_York",
	}
	response := toNotificationRoutingPolicyResponse(policy)
	if response.DigestPreview.NextRunAt.Before(now) || response.DigestPreview.IntervalSeconds != 3600 || response.DigestPreview.Timezone != "America/New_York" {
		t.Fatalf("routing policy digest preview = %+v", response.DigestPreview)
	}
	response.ChannelsBySeverity["critical"][0] = "mutated"
	response.DefaultChannels[0] = "mutated"
	if policy.ChannelsBySeverity["critical"][0] != "email" || policy.DefaultChannels[0] != "msteams" {
		t.Fatal("routing response aliases store-owned channel slices")
	}
	defaults := toNotificationRoutingPolicyResponse(store.NotificationRoutingPolicy{UpdatedAt: now.Add(time.Hour)})
	if defaults.DigestInterval != 86400 || defaults.DigestTimezone != "UTC" || !defaults.DigestPreview.NextRunAt.After(now) {
		t.Fatalf("routing policy defaults = %+v", defaults)
	}

	op := store.NotificationTestOperation{ChannelID: "email", Destination: notify.DestinationTest, OutboxID: 9, CredentialConfigured: true, QueuedAt: now}
	testResponse := notificationChannelTestOperationResponse(op, "idem-public")
	if testResponse.CredentialRef != "redacted" || testResponse.IdempotencyKey != "idem-public" || testResponse.QueuedAt != now {
		t.Fatalf("notification test response = %+v", testResponse)
	}
	op.CredentialConfigured = false
	if got := notificationChannelTestOperationResponse(op, "idem-public"); got.CredentialRef != "" {
		t.Fatalf("unconfigured credential reference = %q", got.CredentialRef)
	}

	bindingA, err := notificationChannelTestBinding("operator-a", http.MethodPost, "/api/v1/notification-channels/email/test", "email", "critical", "subject", "detail", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	bindingB, _ := notificationChannelTestBinding("operator-b", http.MethodPost, "/api/v1/notification-channels/email/test", "email", "critical", "subject", "detail", "", "", "")
	if bindingA == "" || bindingA == bindingB {
		t.Fatalf("authenticated notification command bindings = %q and %q", bindingA, bindingB)
	}
}

func TestNotificationCatalogAndPathHelpers(t *testing.T) {
	catalog := notificationChannelCatalog([]string{"teams", "custom-sink", "custom-sink", ""})
	configured := map[string]notificationChannelResponse{}
	for _, item := range catalog {
		if item.Configured {
			configured[item.ID] = item
		}
	}
	if !configured["msteams"].Enabled || configured["custom-sink"].Category != "custom" {
		t.Fatalf("configured notification catalog = %#v", configured)
	}
	if !notificationChannelFamilySupported("pagerduty") || notificationChannelFamilySupported("custom-sink") {
		t.Fatal("notification channel family support classification is wrong")
	}
	if notificationChannelDefaultLabel("email") != "Email" || notificationChannelDefaultLabel("unknown") != "" {
		t.Fatal("notification channel labels are wrong")
	}
	if notificationChannelCategory("unknown") != "custom" || notificationChannelDescription("unknown") != "Tenant-authored notification sink" {
		t.Fatal("custom notification channel metadata is wrong")
	}

	validPolicy := httptest.NewRequest(http.MethodGet, "/", nil)
	validPolicy.SetPathValue("id", "11111111-1111-4111-8111-111111111111")
	if _, err := notificationRoutingPolicyPathID(validPolicy); err != nil {
		t.Fatalf("valid routing policy path: %v", err)
	}
	invalidPolicy := httptest.NewRequest(http.MethodGet, "/", nil)
	invalidPolicy.SetPathValue("id", "not-a-uuid")
	if _, err := notificationRoutingPolicyPathID(invalidPolicy); err == nil {
		t.Fatal("invalid routing policy path succeeded")
	}
	validNotification := httptest.NewRequest(http.MethodGet, "/", nil)
	validNotification.SetPathValue("id", "17")
	if id, err := notificationPathID(validNotification); err != nil || id != 17 {
		t.Fatalf("valid notification path = %d, %v", id, err)
	}
	invalidNotification := httptest.NewRequest(http.MethodGet, "/", nil)
	invalidNotification.SetPathValue("id", "0")
	if _, err := notificationPathID(invalidNotification); err == nil {
		t.Fatal("non-positive notification path succeeded")
	}
}

func TestNotificationRoutesFailClosedWithoutEventedStores(t *testing.T) {
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithInsecureHeaderResolver())
	const policyID = "11111111-1111-4111-8111-111111111111"
	cases := []struct {
		method string
		path   string
		body   string
		want   int
	}{
		{http.MethodPut, "/api/v1/notification-channels/email", `{"channel_type":"email","endpoint_url":"https://mail.example/hook"}`, http.StatusServiceUnavailable},
		{http.MethodDelete, "/api/v1/notification-channels/email", "", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/v1/notification-routing-policies", "", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/v1/notification-routing-policies/" + policyID, "", http.StatusServiceUnavailable},
		{http.MethodPut, "/api/v1/notification-routing-policies/" + policyID, `{"name":"critical","default_channels":["email"]}`, http.StatusServiceUnavailable},
		{http.MethodDelete, "/api/v1/notification-routing-policies/" + policyID, "", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/v1/notifications", "", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/v1/notifications/1", "", http.StatusServiceUnavailable},
		{http.MethodPost, "/api/v1/notifications/1/read", "", http.StatusServiceUnavailable},
		{http.MethodPost, "/api/v1/notifications/1/requeue", "", http.StatusServiceUnavailable},
	}
	for i, tc := range cases {
		t.Run(tc.method+"_"+strings.ReplaceAll(tc.path, "/", "_"), func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
			req.Header.Set("X-Tenant-ID", "11111111-1111-4111-8111-111111111111")
			req.Header.Set("X-Subject", "operator-a")
			req.Header.Set("X-Roles", "admin")
			req.Header.Set("Idempotency-Key", "notification-helper-"+time.Now().Format("150405.000000000")+string(rune('a'+i))) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("%s %s = %d, want %d; body=%s", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
