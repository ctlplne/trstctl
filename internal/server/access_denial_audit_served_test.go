// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestServedGuardDenialsRetainAuthenticatedTenantEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "guard-denials"}); err != nil {
		t.Fatal(err)
	}
	token := seedServedAPIToken(t, ctx, st, tenantID, "denied-reader", []string{string(authz.AccessRead)})
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
	const bodyCanary = "private-request-canary-not-for-audit"
	for i, step := range []struct {
		method, path, permission, pattern string
		body                              any
	}{
		{http.MethodPut, "/api/v1/access/members/denied-reader", string(authz.AccessWrite), "PUT /api/v1/access/members/{subject}", map[string]any{"roles": []string{"admin"}, "display_name": bodyCanary}},
		{http.MethodPost, "/api/v1/access/api-tokens", string(authz.AccessWrite), "POST /api/v1/access/api-tokens", map[string]any{"subject": "denied-reader", "scopes": []string{"*"}}},
		{http.MethodPost, "/api/v1/owners?private=" + bodyCanary, string(authz.OwnersWrite), "POST /api/v1/owners", map[string]any{"kind": "team", "name": bodyCanary}},
	} {
		code, body := doBearer(t, ts, step.method, step.path, token, "denied-"+step.permission, step.body)
		if code != http.StatusForbidden {
			t.Fatalf("%s = %d %s", step.path, code, body)
		}
		var denials []events.Event
		if err := log.Replay(ctx, 0, func(ev events.Event) error {
			if ev.Type == orchestrator.EventAuthzDecision {
				denials = append(denials, ev)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(denials) != i+1 {
			t.Fatalf("guard denial audit count=%d, want %d", len(denials), i+1)
		}
		ev := denials[len(denials)-1]
		var payload orchestrator.AuthzDecision
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			t.Fatal(err)
		}
		if ev.TenantID != tenantID || ev.Actor.Subject != "denied-reader" || payload.Actor != "denied-reader" || payload.Permission != step.permission || payload.Decision != "deny" || payload.Resource != "api_route" || payload.Target != step.pattern {
			t.Fatalf("wrong attributable decision: event=%+v payload=%+v", ev, payload)
		}
		if bytes.Contains(ev.Data, []byte(bodyCanary)) || bytes.Contains(ev.Data, []byte(token)) {
			t.Fatal("request body, query or bearer credential entered audit event")
		}
	}
	if _, err := st.GetTenantMember(ctx, tenantID, "denied-reader"); !store.IsNotFound(err) {
		t.Fatalf("denied self-promotion created member: %v", err)
	}
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type == "owner.created" || ev.Type == "api_token.created" || ev.Type == "tenant.member.upserted" {
			t.Errorf("denied mutation emitted %s", ev.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
