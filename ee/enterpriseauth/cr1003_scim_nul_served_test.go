// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// VL-174 (SW-NULC-SCIM): a SCIM bearer-token holder (the tenant's IdP) posts a JSON-escaped NUL in
// userName, displayName and a group displayName through the served /scim/v2 routes (real PostgreSQL).
// Reports the status, whether an event is retained although the request failed, and a restart Build.
func TestCR1003SCIMNULUserCannotAppendUnprojectableEvent(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL and embedded NATS; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const scimToken = "scim-test-token" // #nosec G101 -- fabricated fixture credential/identifier

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tokenFile := t.TempDir() + "/scim.token"
	if err := writeSecretFile(tokenFile, []byte(scimToken)); err != nil {
		t.Fatal(err)
	}
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	deps := server.Deps{TenantAuthFactory: Build, Store: st, Log: log,
		SCIM:       config.SCIM{Enabled: true, Tokens: []config.SCIMToken{{Name: "okta", TenantID: tenantID, TokenFile: tokenFile}}},
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true})}}
	srv, err := server.Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())

	ctl := doSCIM(t, ts, "POST", "/scim/v2/Users", scimToken, "vl174-ctl", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "clean@example.test", "displayName": "Clean", "active": true})
	t.Logf("VL174 control user create status=%d", ctl.Code)
	if ctl.Code != 201 {
		t.Fatalf("control create: %d %s", ctl.Code, ctl.Body.String())
	}
	type attack struct {
		name, method, path, key string
		body                    map[string]any
	}
	user := func(un, dn string) map[string]any {
		return map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": un, "displayName": dn, "active": true}
	}
	attacks := []attack{
		{"SCIM create userName", "POST", "/scim/v2/Users", "vl174-s1", user("bad\u0000user@example.test", "Clean")},
		{"SCIM create displayName", "POST", "/scim/v2/Users", "vl174-s2", user("dn@example.test", "bad\u0000name")},
		{"SCIM create email", "POST", "/scim/v2/Users", "vl174-s3", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": "em@example.test", "emails": []map[string]any{{"value": "bad\u0000@example.test", "primary": true}}, "active": true}},
		{"SCIM create externalId", "POST", "/scim/v2/Users", "vl174-s5", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"userName": "ex@example.test", "externalId": "bad\u0000ext", "active": true}},
		{"SCIM create group displayName", "POST", "/scim/v2/Groups", "vl174-s4", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "bad\u0000group"}},
		{"SCIM PUT displayName", "PUT", "/scim/v2/Users/clean@example.test", "vl174-s6", user("clean@example.test", "bad\u0000name")},
		{"SCIM PATCH displayName", "PATCH", "/scim/v2/Users/clean@example.test", "vl174-s7", map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "bad\u0000name"}},
		}},
		{"SCIM Bulk nested user", "POST", "/scim/v2/Bulk", "vl174-s8", map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"},
			"Operations": []map[string]any{{"method": "POST", "path": "/Users", "bulkId": "poison", "data": user("bulk@example.test", "bad\u0000name")}},
		}},
	}
	for _, a := range attacks {
		before, _ := log.LastSequence(ctx)
		resp := doSCIM(t, ts, a.method, a.path, scimToken, a.key, a.body)
		after, _ := log.LastSequence(ctx)
		var types []string
		_ = log.Replay(ctx, before, func(e events.Event) error {
			if e.Sequence > before {
				types = append(types, e.Type)
			}
			return nil
		})
		b := resp.Body.String()
		if len(b) > 140 {
			b = b[:140]
		}
		t.Logf("VL174 %-32s status=%d appended=%d types=%v body=%s", a.name, resp.Code, after-before, types, b)
		if resp.Code != 400 || !strings.Contains(resp.Body.String(), `"scimType":"invalidValue"`) {
			t.Errorf("%s: status %d body %s, want SCIM 400 invalidValue", a.name, resp.Code, resp.Body.String())
		}
		if after != before {
			t.Errorf("%s: %d event(s) %v retained after invalid request", a.name, after-before, types)
		}
	}
	ts.Close()
	_ = srv.Shutdown(ctx)
}
