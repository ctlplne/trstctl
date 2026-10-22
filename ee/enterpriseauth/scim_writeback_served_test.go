// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// scimDirectoryDouble stands in for the directory's own SCIM endpoint: it
// answers the filter lookup, records every PATCH, and reads the user back.
type scimDirectoryDouble struct {
	mu      sync.Mutex
	users   map[string]map[string]any // id -> resource
	byName  map[string]string
	patches []map[string]any
	bearer  string
}

func (d *scimDirectoryDouble) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+d.bearer {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	w.Header().Set("Content-Type", "application/scim+json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/scim/v2/Users":
		filter := r.URL.Query().Get("filter")
		name := strings.Trim(strings.TrimPrefix(filter, "userName eq "), `"`)
		resources := []any{}
		if id, ok := d.byName[name]; ok {
			resources = append(resources, d.users[id])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources})
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/scim/v2/Users/"):
		id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
		user, ok := d.users[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var patch struct {
			Operations []struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value any    `json:"value"`
			} `json:"Operations"`
		}
		_ = json.NewDecoder(r.Body).Decode(&patch)
		applied := map[string]any{"id": id}
		for _, op := range patch.Operations {
			user[op.Path] = op.Value
			applied[op.Path] = op.Value
		}
		d.patches = append(d.patches, applied)
		_ = json.NewEncoder(w).Encode(user)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/scim/v2/Users/"):
		id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
		user, ok := d.users[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(user)
	default:
		http.NotFound(w, r)
	}
}

// A73: a tenant's SCIM token may name the directory's own SCIM endpoint. A
// change an operator makes in trstctl to a directory-owned member — roles, or
// offboarding — is written back to the directory's User through the outbox,
// read back, and recorded as audit evidence; a change the directory itself
// pushed is never echoed back, and a member the directory does not own is
// left alone.
func TestServedSCIMWritebackPushesLocalMemberChangesToTheDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL and embedded NATS; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const scimToken = "scim-writeback-inbound"          // #nosec G101 -- fabricated fixture credential (CWE-798)
	const directoryBearer = "directory-outbound-bearer" // #nosec G101 -- fabricated fixture credential (CWE-798)
	directory := &scimDirectoryDouble{bearer: directoryBearer, users: map[string]map[string]any{
		"dir-alice": {"id": "dir-alice", "userName": "alice@example.com", "active": true, "roles": []any{}},
	}, byName: map[string]string{"alice@example.com": "dir-alice"}}
	double := httptest.NewServer(http.HandlerFunc(directory.handle))
	defer double.Close()

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "writeback"}); err != nil {
		t.Fatal(err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "platform-admin", []string{string(authz.AccessRead), string(authz.AccessWrite), "access:role.assign"})
	dir := t.TempDir()
	if err := writeSecretFile(dir+"/scim.token", []byte(scimToken)); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(dir+"/writeback.token", []byte(directoryBearer)); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessionIssuer([]byte("scim-writeback-session-secret-012345678"), time.Hour)
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

	// The directory provisions alice; nothing is written back for its own push.
	created := doSCIM(t, ts, http.MethodPost, "/scim/v2/Users", scimToken, "wb-create", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "alice@example.com", "displayName": "Alice", "active": true,
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("provision alice = %d %s", created.Code, created.Body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n := len(directory.patches); n != 0 {
		t.Fatalf("the directory's own push was echoed back: %d patches", n)
	}

	// An operator grants viewer here: the directory's User gets the role.
	code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+url.PathEscape("alice@example.com"), adminToken, "wb-grant", map[string]any{"roles": []string{"viewer"}, "display_name": "Alice"})
	if code != http.StatusOK {
		t.Fatalf("grant viewer = %d %s", code, body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain after grant: %v", err)
	}
	directory.mu.Lock()
	patches := append([]map[string]any(nil), directory.patches...)
	directory.mu.Unlock()
	if len(patches) != 1 || patches[0]["id"] != "dir-alice" || patches[0]["active"] != true {
		t.Fatalf("directory patches after the grant = %+v, want one on dir-alice with active true", patches)
	}
	if encoded, _ := json.Marshal(patches[0]["roles"]); !bytes.Contains(encoded, []byte(`"value":"viewer"`)) {
		t.Fatalf("written roles = %s, want viewer", encoded)
	}

	// The operator offboards alice here: the directory's User goes inactive.
	code, body = doBearer(t, ts, http.MethodPost, "/api/v1/access/members/"+url.PathEscape("alice@example.com")+"/offboard", adminToken, "wb-offboard", map[string]any{"reason": "left the team"})
	if code != http.StatusOK {
		t.Fatalf("offboard = %d %s", code, body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain after offboard: %v", err)
	}
	directory.mu.Lock()
	patches = append([]map[string]any(nil), directory.patches...)
	directory.mu.Unlock()
	if len(patches) != 2 || patches[1]["active"] != false {
		t.Fatalf("directory patches after the offboard = %+v, want a second one with active false", patches)
	}

	// A member the directory does not own is never written back.
	code, body = doBearer(t, ts, http.MethodPut, "/api/v1/access/members/local-operator", adminToken, "wb-local", map[string]any{"roles": []string{"viewer"}, "display_name": "Local"})
	if code != http.StatusOK {
		t.Fatalf("local member = %d %s", code, body)
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain after local member: %v", err)
	}
	if n := len(directory.patches); n != 2 {
		t.Fatalf("a member the directory does not own was written back: %d patches", n)
	}

	// Every writeback is audit evidence with the readback's verdict.
	var written, offboarded int
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID || ev.Type != projections.EventSCIMWritebackRecorded {
			return nil
		}
		var recorded projections.SCIMWritebackRecorded
		if err := json.Unmarshal(ev.Data, &recorded); err != nil {
			return err
		}
		if recorded.Status != "written" || recorded.DirectoryUserID != "dir-alice" || recorded.Subject != "alice@example.com" {
			t.Fatalf("writeback record = %+v", recorded)
		}
		switch recorded.Change {
		case "upsert":
			written++
		case "offboard":
			offboarded++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if written != 1 || offboarded != 1 {
		t.Fatalf("writeback records: upsert %d offboard %d, want one each", written, offboarded)
	}
}
