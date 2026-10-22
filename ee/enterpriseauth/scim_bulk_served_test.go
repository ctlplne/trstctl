// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// A72: an IdP provisions a tenant in one Bulk request. Operations run in
// order through the same logic as the single routes, a POST's bulkId names
// its user for the group that follows, per-operation failures are reported by
// name without stopping the rest unless failOnErrors says so, and a replay
// under the same Idempotency-Key returns the recorded response without
// re-running anything.
func TestServedSCIMBulkProvisionsUsersAndGroupsInOneRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL and embedded NATS; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const scimToken = "scim-bulk-token" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "bulk"}); err != nil {
		t.Fatal(err)
	}
	tokenFile := t.TempDir() + "/scim.token"
	if err := writeSecretFile(tokenFile, []byte(scimToken)); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessionIssuer([]byte("scim-bulk-session-secret-0123456789012"), time.Hour)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.Build(ctx, server.Deps{TenantAuthFactory: Build, Store: st, Log: log,
		SCIM:       config.SCIM{Enabled: true, Tokens: []config.SCIMToken{{Name: "okta", TenantID: tenantID, TokenFile: tokenFile}}},
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true, Sessions: sessions})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// The capability is advertised.
	cfg := doSCIM(t, ts, http.MethodGet, "/scim/v2/ServiceProviderConfig", scimToken, "", nil)
	if cfg.Code != http.StatusOK || !bytes.Contains(cfg.Body.Bytes(), []byte(`"bulk":{"maxOperations":100,"maxPayloadSize":1048576,"supported":true}`)) {
		t.Fatalf("ServiceProviderConfig = %d %s; want bulk supported", cfg.Code, cfg.Body)
	}

	user := func(name string) map[string]any {
		return map[string]any{"schemas": []string{scim.SchemaUser}, "userName": name, "displayName": name, "active": true}
	}
	bulk := map[string]any{
		"schemas": []string{scim.SchemaBulkRequest},
		"Operations": []map[string]any{
			{"method": "POST", "path": "/Users", "bulkId": "alice", "data": user("alice@example.com")},
			{"method": "POST", "path": "/Users", "bulkId": "bob", "data": user("bob@example.com")},
			{"method": "POST", "path": "/Groups", "bulkId": "viewers", "data": map[string]any{
				"schemas": []string{scim.SchemaGroup}, "displayName": "viewer",
				"members": []map[string]string{{"value": "bulkId:alice"}, {"value": "bulkId:bob"}},
			}},
			{"method": "PATCH", "path": "/Users/bulkId:bob", "data": map[string]any{
				"schemas": []string{scim.SchemaPatchOp}, "Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
			}},
			{"method": "DELETE", "path": "/Users/nobody@example.com"},
			{"method": "PATCH", "path": "/Groups/not-a-role", "data": map[string]any{"schemas": []string{scim.SchemaPatchOp}, "Operations": []map[string]any{}}},
			// A create that the mutation itself refuses must surface as that
			// operation's failure, not vanish behind a success.
			{"method": "POST", "path": "/Groups", "bulkId": "nogroup", "data": map[string]any{"schemas": []string{scim.SchemaGroup}, "displayName": "not-a-role"}},
		},
	}
	first := doSCIM(t, ts, http.MethodPost, "/scim/v2/Bulk", scimToken, "bulk-1", bulk)
	if first.Code != http.StatusOK {
		t.Fatalf("bulk = %d %s", first.Code, first.Body)
	}
	var response scim.BulkResponse
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode bulk response: %v %s", err, first.Body)
	}
	if len(response.Schemas) != 1 || response.Schemas[0] != scim.SchemaBulkResponse || len(response.Operations) != 7 {
		t.Fatalf("bulk response = %+v", response)
	}
	wantStatus := []string{"201", "201", "201", "200", "404", "404", "400"}
	for i, op := range response.Operations {
		if op.Status != wantStatus[i] {
			t.Fatalf("operation %d = %+v, want status %s", i, op, wantStatus[i])
		}
	}
	if response.Operations[0].BulkID != "alice" || response.Operations[0].Location != ts.URL+"/scim/v2/Users/alice@example.com" ||
		response.Operations[2].Location != ts.URL+"/scim/v2/Groups/viewer" {
		t.Fatalf("locations = %+v", response.Operations)
	}
	// Alice is a viewer, Bob was provisioned and then deactivated by his bulkId.
	group := doSCIM(t, ts, http.MethodGet, "/scim/v2/Groups/viewer", scimToken, "", nil)
	if group.Code != http.StatusOK || !bytes.Contains(group.Body.Bytes(), []byte(`"value":"alice@example.com"`)) {
		t.Fatalf("viewer group = %d %s", group.Code, group.Body)
	}
	bob := doSCIM(t, ts, http.MethodGet, "/scim/v2/Users/bob%40example.com", scimToken, "", nil)
	if bob.Code != http.StatusOK || !bytes.Contains(bob.Body.Bytes(), []byte(`"active":false`)) {
		t.Fatalf("bob after bulk = %d %s; want provisioned then deactivated", bob.Code, bob.Body)
	}

	// A replay under the same key is the recorded response, not a second run.
	replay := doSCIM(t, ts, http.MethodPost, "/scim/v2/Bulk", scimToken, "bulk-1", bulk)
	if replay.Code != http.StatusOK || !bytes.Equal(bytes.TrimSpace(replay.Body.Bytes()), bytes.TrimSpace(first.Body.Bytes())) {
		t.Fatalf("replay = %d %s, want the recorded response", replay.Code, replay.Body)
	}

	// failOnErrors stops after the first failure: the later POST never runs.
	stopping := map[string]any{
		"schemas": []string{scim.SchemaBulkRequest}, "failOnErrors": 1,
		"Operations": []map[string]any{
			{"method": "DELETE", "path": "/Users/ghost@example.com"},
			{"method": "POST", "path": "/Users", "bulkId": "carol", "data": user("carol@example.com")},
		},
	}
	stopped := doSCIM(t, ts, http.MethodPost, "/scim/v2/Bulk", scimToken, "bulk-2", stopping)
	if err := json.Unmarshal(stopped.Body.Bytes(), &response); err != nil || stopped.Code != http.StatusOK || len(response.Operations) != 1 || response.Operations[0].Status != "404" {
		t.Fatalf("failOnErrors bulk = %d %s", stopped.Code, stopped.Body)
	}
	if carol := doSCIM(t, ts, http.MethodGet, "/scim/v2/Users/carol%40example.com", scimToken, "", nil); carol.Code != http.StatusNotFound {
		t.Fatalf("carol was created after failOnErrors stopped the request: %d %s", carol.Code, carol.Body)
	}

	// Malformed requests are refused whole, by name.
	for name, body := range map[string]map[string]any{
		"wrong schema":        {"schemas": []string{scim.SchemaUser}, "Operations": []map[string]any{{"method": "DELETE", "path": "/Users/x"}}},
		"post without bulkId": {"schemas": []string{scim.SchemaBulkRequest}, "Operations": []map[string]any{{"method": "POST", "path": "/Users", "data": user("d@example.com")}}},
		"unknown reference":   {"schemas": []string{scim.SchemaBulkRequest}, "Operations": []map[string]any{{"method": "DELETE", "path": "/Users/bulkId:missing"}}},
	} {
		got := doSCIM(t, ts, http.MethodPost, "/scim/v2/Bulk", scimToken, "bulk-"+name, body)
		if name == "unknown reference" {
			if err := json.Unmarshal(got.Body.Bytes(), &response); err != nil || got.Code != http.StatusOK || response.Operations[0].Status != "400" {
				t.Fatalf("%s = %d %s", name, got.Code, got.Body)
			}
			continue
		}
		if got.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d %s, want 400", name, got.Code, got.Body)
		}
	}
}
