// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
)

// LS-1: a tenant's notification routing policies have distinct names, and a
// scope other than manual is routed by one policy. A second policy under a
// held name, or routing a scope another routes (the global scope included),
// is a 409 and nothing is appended; it used to append the policy event and
// fail its projection on the policy's unique indexes, a 500 that left an
// event a rebuild stopped at. A policy keeps its own name on update, and a
// log that already holds such an event rebuilds as live.
func TestServedNotificationRoutingPolicyUnderAHeldNameOrScopeIsAConflictLS1(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{&namedFlakyNotificationChannel{name: "slack"}}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")
	policy := func(name, scopeKind, scopeRef string) map[string]any {
		return map[string]any{"name": name, "scope_kind": scopeKind, "scope_ref": scopeRef,
			"channels_by_severity": map[string][]string{"warning": {"slack"}}, "default_channels": []string{"slack"}}
	}
	created := func(key string, body map[string]any) string {
		t.Helper()
		status, out := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-routing-policies", tok, key, body)
		var got struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(out, &got) != nil || got.ID == "" {
			t.Fatalf("create %s: %d %s", key, status, out)
		}
		return got.ID
	}
	refused := func(method, path, key string, body map[string]any, code, detail string) {
		t.Helper()
		status, out := secretsReqKey(t, h, method, path, tok, key, body)
		if status != http.StatusConflict || !strings.Contains(string(out), `"code":"`+code+`"`) || !strings.Contains(string(out), detail) {
			t.Fatalf("%s = %d %s, want a 409 %s naming %s", key, status, out, code, detail)
		}
	}
	first := created("ls1-route-first", policy("Payments route", "asset", "identity/payments"))
	created("ls1-route-global", policy("Everything else", "global", ""))
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	const routes = "/api/v1/notification-routing-policies"
	refused(http.MethodPost, routes, "ls1-route-same-name", policy("Payments route", "owner", "owner/ls1"),
		"name_held", `another notification routing policy is named \"Payments route\"`)
	refused(http.MethodPost, routes, "ls1-route-same-scope", policy("Payments again", "asset", "identity/payments"),
		"scope_held", `already routes asset \"identity/payments\"`)
	refused(http.MethodPost, routes, "ls1-route-second-global", policy("Fallback", "global", ""),
		"scope_held", "already routes the global scope")
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != before {
		t.Fatalf("the refused policies appended: %d -> %d %v", before, after, err)
	}

	// A policy renamed into a held name is refused and keeps its own name.
	third := created("ls1-route-third", policy("Owner route", "owner", "owner/ls1"))
	refused(http.MethodPut, routes+"/"+third, "ls1-route-rename", policy("Payments route", "owner", "owner/ls1"),
		"name_held", `another notification routing policy is named \"Payments route\"`)
	if status, out := secretsReqKey(t, h, http.MethodPut, routes+"/"+third, tok, "ls1-route-resave", policy("Owner route", "owner", "owner/ls1")); status != http.StatusOK {
		t.Fatalf("the third policy re-saved under its own name and scope: %d %s", status, out)
	}
	if got, err := h.store.GetNotificationRoutingPolicy(t.Context(), h.tenant, third); err != nil || got.Name != "Owner route" {
		t.Fatalf("the third policy: %+v %v", got, err)
	}

	// A log that already holds a pre-check duplicate (the first policy's
	// name and scope) rebuilds, with only the first.
	const duplicate = "18181818-1818-4818-8818-181818181818"
	poisoned, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{ID: duplicate, Name: "Payments route",
		ScopeKind: "asset", ScopeRef: "identity/payments", DefaultChannels: []string{"slack"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(t.Context(), events.Event{Type: projections.EventNotificationRoutingPolicyUpserted, TenantID: h.tenant, Data: poisoned}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("a log holding a pre-check duplicate does not rebuild: %v", err)
	}
	if _, err := h.store.GetNotificationRoutingPolicy(t.Context(), h.tenant, duplicate); err == nil {
		t.Fatal("the duplicate projected a policy")
	}
	if got, err := h.store.GetNotificationRoutingPolicy(t.Context(), h.tenant, first); err != nil || got.Name != "Payments route" || got.ScopeRef != "identity/payments" {
		t.Fatalf("the first policy after the rebuild: %+v %v", got, err)
	}
	t.Logf("LS1_ROUTING_OK first=%s third=%s", first, third)
}
