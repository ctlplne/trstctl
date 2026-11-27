// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

func TestServedMemberTokenFollowsCurrentRolesAndParentExpiry(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "authority-admin", []string{"*"})
	const subject = "authority-member"
	memberPath := "/api/v1/access/members/" + subject
	if code, _ := doBearer(t, h.ts, http.MethodPut, memberPath, admin, "authority-operator",
		map[string]any{"roles": []string{"operator"}, "source": "manual"}); code != http.StatusOK {
		t.Fatalf("member setup = %d", code)
	}
	initial := seedServedAPIToken(t, context.Background(), h.store, h.tenant, subject,
		[]string{"access:write", "certs:read"})
	wide := seedServedAPIToken(t, context.Background(), h.store, h.tenant, subject, []string{"*"})
	parentExpiry := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/api-tokens", initial, "authority-parent",
		map[string]any{"subject": subject, "scopes": []string{"access:write", "certs:read"}, "expires_at": parentExpiry})
	if code != http.StatusCreated {
		t.Fatalf("parent token creation = %d", code)
	}
	var parent struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &parent); err != nil || parent.Token == "" {
		t.Fatalf("parent token response: %v", err)
	}
	laterExpiry := parentExpiry.Add(time.Minute)
	code, _ = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/api-tokens", parent.Token,
		"authority-successor-late", map[string]any{"subject": subject, "scopes": []string{"certs:read"}, "expires_at": laterExpiry})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("successor beyond parent expiry = %d", code)
	}
	code, raw = doBearer(t, h.ts, http.MethodPost, "/api/v1/access/api-tokens", parent.Token,
		"authority-successor-capped", map[string]any{"subject": subject, "scopes": []string{"certs:read"}})
	if code != http.StatusCreated {
		t.Fatalf("successor with inherited expiry = %d", code)
	}
	var successor struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &successor); err != nil || successor.ExpiresAt.After(parentExpiry) {
		t.Fatalf("successor expiry = %s, decode error = %v", successor.ExpiresAt, err)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPut, memberPath, admin, "authority-viewer",
		map[string]any{"roles": []string{"viewer"}, "source": "manual"}); code != http.StatusOK {
		t.Fatalf("member role update = %d", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/certificates", parent.Token, "", nil); code != http.StatusOK {
		t.Fatalf("current read permission = %d", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/api-tokens", parent.Token,
		"authority-after-role-update", map[string]any{"subject": subject, "scopes": []string{"certs:read"}}); code != http.StatusForbidden {
		t.Fatalf("former write permission = %d", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/certificates", wide, "", nil); code != http.StatusOK {
		t.Fatalf("wide token current read permission = %d", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/api-tokens", wide,
		"authority-wide-after-role-update", map[string]any{"subject": subject, "scopes": []string{"certs:read"}}); code != http.StatusForbidden {
		t.Fatalf("wide token former write permission = %d", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPut, memberPath, admin, "authority-no-roles",
		map[string]any{"roles": []string{}, "source": "manual"}); code != http.StatusOK {
		t.Fatalf("member role removal = %d", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/certificates", parent.Token, "", nil); code != http.StatusForbidden {
		t.Fatalf("member token after role removal = %d", code)
	}
}
