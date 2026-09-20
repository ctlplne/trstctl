// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedMemberUpdatePreservesCreationAndRetryResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const subject = "member-timestamp-reader"
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "timestamp-tenant"}); err != nil {
		t.Fatal(err)
	}
	token := seedServedAPIToken(t, ctx, st, tenantID, "member-admin", []string{string(authz.AccessRead), string(authz.AccessWrite), string(authz.AccessRoleAssign)})
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	var original time.Time
	var previousUpdate time.Time
	for _, step := range []struct{ key, role string }{{"member-create", "viewer"}, {"member-update", "operator"}} {
		body := map[string]any{"display_name": "Timestamp Reader", "roles": []string{step.role}, "source": "manual"}
		code, raw := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+subject, token, step.key, body)
		if code != http.StatusOK {
			t.Fatalf("%s = %d: %s", step.key, code, raw)
		}
		var got struct {
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Roles     []string  `json:"roles"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		stored, err := st.GetTenantMember(ctx, tenantID, subject)
		if err != nil {
			t.Fatal(err)
		}
		if original.IsZero() {
			original = stored.CreatedAt
		}
		if !got.CreatedAt.Equal(original) || !got.CreatedAt.Equal(stored.CreatedAt) {
			t.Errorf("%s response created_at = %s; original/store = %s/%s", step.key, got.CreatedAt, original, stored.CreatedAt)
		}
		if !got.UpdatedAt.Equal(stored.UpdatedAt) || (!previousUpdate.IsZero() && !got.UpdatedAt.After(previousUpdate)) {
			t.Errorf("%s response updated_at = %s; store/previous = %s/%s", step.key, got.UpdatedAt, stored.UpdatedAt, previousUpdate)
		}
		if len(got.Roles) != 1 || got.Roles[0] != step.role {
			t.Errorf("roles = %v, want %s", got.Roles, step.role)
		}
		previousUpdate = got.UpdatedAt
		retryCode, retry := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+subject, token, step.key, body)
		if retryCode != code || !bytes.Equal(retry, raw) {
			t.Errorf("same-key retry changed response: %d %s; original %d %s", retryCode, retry, code, raw)
		}
	}
	count := 0
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID == tenantID && ev.Type == projections.EventTenantMemberUpserted {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("upsert events = %d, want 2 despite retries", count)
	}
}
