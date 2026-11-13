// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// A207-L1 Done-when: the SCIM writeback bearer rotates without a restart.
// The directory rotates the bearer it accepts and the operator rewrites
// writeback_token_file: the next write-back carries the new bearer and lands;
// an empty rewrite (a rotation caught half-written) keeps the last good
// bearer, and the write-back after it still lands.
func TestServedSCIMWritebackBearerRotatesWithoutRestartA207L1(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL and embedded NATS; skipped in -short")
	}
	saved := scimTokenRecheck
	scimTokenRecheck = 0
	t.Cleanup(func() { scimTokenRecheck = saved })
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const scimToken = "scim-in-scim-in"                                            // #nosec G101 -- fabricated fixture credential (CWE-798)
	const first, second = "a207l1-outbound-first", "a207l1-outbound-second-longer" // #nosec G101 -- fabricated fixture credentials (CWE-798)
	directory := &scimDirectoryDouble{bearer: first, users: map[string]map[string]any{
		"dir-alice": {"id": "dir-alice", "userName": "alice@example.com", "active": true, "roles": []any{}},
	}, byName: map[string]string{"alice@example.com": "dir-alice"}}
	double := httptest.NewServer(http.HandlerFunc(directory.handle))
	defer double.Close()

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "writeback-rotation"}); err != nil {
		t.Fatal(err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "platform-admin", []string{string(authz.AccessRead), string(authz.AccessWrite), "access:role.assign"})
	dir := t.TempDir()
	if err := writeSecretFile(dir+"/scim.token", []byte(scimToken)); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(dir+"/writeback.token", []byte(first)); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessionIssuer([]byte("a207l1-writeback-session-secret-0123456"), time.Hour)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.Build(ctx, server.Deps{TenantAuthFactory: Build, Store: st, Log: log,
		SCIM: config.SCIM{Enabled: true, Tokens: []config.SCIMToken{{
			Name: "okta", TenantID: tenantID, TokenFile: dir + "/scim.token",
			WritebackEndpoint: double.URL + "/scim/v2", WritebackTokenFile: dir + "/writeback.token",
		}}},
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true, Sessions: sessions})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if created := doSCIM(t, ts, http.MethodPost, "/scim/v2/Users", scimToken, "a207l1-create", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "alice@example.com", "displayName": "Alice", "active": true,
	}); created.Code != http.StatusCreated {
		t.Fatalf("provision alice = %d %s", created.Code, created.Body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	grant := func(key string, roles ...string) {
		t.Helper()
		if code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+url.PathEscape("alice@example.com"), adminToken, key,
			map[string]any{"roles": roles, "display_name": "Alice"}); code != http.StatusOK {
			t.Fatalf("grant %v = %d %s", roles, code, body)
		}
		if err := srv.Drain(ctx); err != nil {
			t.Fatalf("drain after %s: %v", key, err)
		}
	}
	landed := func() (int, int) {
		directory.mu.Lock()
		defer directory.mu.Unlock()
		return len(directory.patches), directory.refused
	}

	grant("a207l1-grant-1", "viewer")
	if patches, refused := landed(); patches != 1 || refused != 0 {
		t.Fatalf("first write-back: %d patches, %d refused", patches, refused)
	}
	// The directory rotates; the operator rewrites the file.
	directory.accept(second)
	if err := writeSecretFile(dir+"/writeback.token", []byte(second)); err != nil {
		t.Fatal(err)
	}
	grant("a207l1-grant-2", "viewer", "operator")
	if patches, refused := landed(); patches != 2 || refused != 0 {
		t.Fatalf("write-back after the rotation: %d patches, %d refused; want it to carry the new bearer", patches, refused)
	}
	// An empty rewrite keeps the last good bearer.
	if err := writeSecretFile(dir+"/writeback.token", []byte("  \n")); err != nil {
		t.Fatal(err)
	}
	grant("a207l1-grant-3", "viewer")
	if patches, refused := landed(); patches != 3 || refused != 0 {
		t.Fatalf("write-back after an empty rewrite: %d patches, %d refused; want the last good bearer kept", patches, refused)
	}
}
