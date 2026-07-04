// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestListNotificationChannelsReportsConfiguredCAPOBS05(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithNotificationChannels("email", "slack", "teams", "sms", "siem"),
	)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/notification-channels", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []struct {
			ID         string `json:"id"`
			Label      string `json:"label"`
			Configured bool   `json:"configured"`
			Delivery   string `json:"delivery"`
		} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	configured := map[string]bool{}
	for _, item := range body.Items {
		if item.Delivery != "notification.* outbox fanout" {
			t.Fatalf("channel %q delivery = %q", item.ID, item.Delivery)
		}
		if item.Configured {
			configured[item.ID] = true
		}
	}
	for _, want := range []string{"email", "slack", "msteams", "sms", "siem"} {
		if !configured[want] {
			t.Fatalf("configured channels = %#v, missing %q in response %+v", configured, want, body.Items)
		}
	}
}
