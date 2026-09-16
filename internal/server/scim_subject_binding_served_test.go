// SPDX-License-Identifier: MPL-2.0

package server

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
	"trstctl.com/trstctl/internal/projections"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/scim"
	"trstctl.com/trstctl/internal/store"
)

// An IdP's human-readable SCIM userName is not necessarily its OIDC subject.
// An explicit deployment choice must bind the trusted provisioning identifier
// to the same principal used by existing sessions and API tokens.
func TestServedSCIMExplicitSubjectBindingControlsRealSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real PostgreSQL and embedded NATS")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const subject = "68a8b4fa-4935-452b-a174-7f50826c0ef3"
	const userName = "opaque-subject@example.test"
	const provisionToken = "scim-subject-binding-fixture" // #nosec G101 -- fabricated local fixture, not a credential (CWE-798)
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "opaque subject"}); err != nil {
		t.Fatal(err)
	}
	bearer := seedServedAPIToken(t, ctx, st, tenantID, subject, []string{"access:read"})
	tokenFile := t.TempDir() + "/scim.token"
	if err := writeSecretFile(tokenFile, []byte(provisionToken)); err != nil {
		t.Fatal(err)
	}
	// JSON preserves a runnable before-repair regression: the old configuration
	// ignores the new explicit mapping and therefore still misbinds userName.
	raw, err := json.Marshal(map[string]any{"enabled": true, "tokens": []map[string]string{{"name": "opaque-idp", "tenant_id": tenantID, "token_file": tokenFile, "subject_attribute": "externalId"}}})
	if err != nil {
		t.Fatal(err)
	}
	var provisioning config.SCIM
	if err := json.Unmarshal(raw, &provisioning); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessionIssuer([]byte("scim-subject-binding-session-fixture-0123456789"), time.Hour)
	session, err := sessions.Issue(subject, tenantID, userName, []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, SCIM: provisioning, APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true, Sessions: sessions})}})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	user := map[string]any{"schemas": []string{scim.SchemaUser}, "userName": userName, "externalId": subject, "displayName": "Opaque Subject", "active": true}
	created := doSCIM(t, ts, http.MethodPost, "/scim/v2/Users", provisionToken, "bind-subject", user)
	if created.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", created.Code, created.Body)
	}
	var resource scim.User
	if err := json.Unmarshal(created.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	if resource.ID != subject || resource.UserName != userName || resource.ExternalID != subject {
		t.Fatalf("SCIM identifiers were not preserved/bound: got id=%q userName=%q externalId=%q", resource.ID, resource.UserName, resource.ExternalID)
	}
	retried := doSCIM(t, ts, http.MethodPost, "/scim/v2/Users", provisionToken, "bind-subject", user)
	if retried.Code != http.StatusCreated || !bytes.Equal(retried.Body.Bytes(), created.Body.Bytes()) {
		t.Fatal("exact provisioning retry changed its result")
	}
	path := "/scim/v2/Users/" + url.PathEscape(resource.ID)
	renamed := "renamed-opaque@example.test"
	patch := map[string]any{"schemas": []string{scim.SchemaPatchOp}, "Operations": []map[string]any{{"op": "replace", "path": "userName", "value": renamed}}}
	rename := doSCIM(t, ts, http.MethodPatch, path, provisionToken, "rename-username", patch)
	if rename.Code != http.StatusOK {
		t.Fatalf("rename=%d %s", rename.Code, rename.Body)
	}
	if err := json.Unmarshal(rename.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	if resource.ID != subject || resource.UserName != renamed || resource.ExternalID != subject {
		t.Fatal("renaming SCIM userName changed/lost the immutable login binding")
	}
	if code, _ := doSession(t, ts, http.MethodGet, "/api/v1/access/roles", session); code != http.StatusOK {
		t.Fatalf("same subject session after rename=%d", code)
	}
	if code, _ := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", bearer, "", nil); code != http.StatusOK {
		t.Fatalf("same subject token before offboard=%d", code)
	}

	group := map[string]any{"schemas": []string{scim.SchemaGroup}, "displayName": "operator", "members": []map[string]string{{"value": subject}}}
	if got := doSCIM(t, ts, http.MethodPost, "/scim/v2/Groups", provisionToken, "bind-group", group); got.Code != http.StatusCreated {
		t.Fatalf("group grant=%d %s", got.Code, got.Body)
	}
	member, err := st.GetTenantMember(ctx, tenantID, subject)
	if err != nil || member.SCIM == nil || member.SCIM.UserName != renamed || !strings.Contains(strings.Join(member.Roles, ","), "operator") {
		t.Fatalf("group grant lost binding or role: %+v err=%v", member, err)
	}
	filtered := doSCIM(t, ts, http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "`+renamed+`"`), provisionToken, "", nil)
	if filtered.Code != http.StatusOK || !bytes.Contains(filtered.Body.Bytes(), []byte(`"id":"`+subject+`"`)) {
		t.Fatalf("renamed resource filter=%d %s", filtered.Code, filtered.Body)
	}
	patch["Operations"] = []map[string]any{{"op": "replace", "path": "externalId", "value": "a-different-login-subject"}}
	rebound := doSCIM(t, ts, http.MethodPatch, path, provisionToken, "reject-rebinding", patch)
	if rebound.Code != http.StatusBadRequest {
		t.Fatalf("changing the bound subject=%d, want400", rebound.Code)
	}

	for _, operation := range []map[string]any{{"op": "remove", "path": "externalId"}, {"op": "replace", "value": map[string]any{"externalId": "different-subject"}}} {
		patch["Operations"] = []map[string]any{operation}
		if got := doSCIM(t, ts, http.MethodPatch, path, provisionToken, "reject-other-binding-"+operation["op"].(string), patch); got.Code != http.StatusBadRequest {
			t.Fatalf("binding mutation=%d %s", got.Code, got.Body)
		}
	}
	replacement := map[string]any{"schemas": []string{scim.SchemaUser}, "userName": renamed, "externalId": "different-subject", "active": true}
	if got := doSCIM(t, ts, http.MethodPut, path, provisionToken, "reject-put-binding", replacement); got.Code != http.StatusBadRequest {
		t.Fatalf("PUT binding mutation=%d %s", got.Code, got.Body)
	}
	patch["Operations"] = []map[string]any{{"op": "replace", "path": "active", "value": false}}
	offboard := doSCIM(t, ts, http.MethodPatch, path, provisionToken, "offboard-bound-subject", patch)
	if offboard.Code != http.StatusOK {
		t.Fatalf("offboard=%d %s", offboard.Code, offboard.Body)
	}
	if err := json.Unmarshal(offboard.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	if resource.Active || resource.ID != subject || resource.UserName != renamed || resource.ExternalID != subject {
		t.Fatal("offboarding lost the provisioning identifiers or remained active")
	}
	// Offboarding's response must use the committed timestamp, including the
	// datastore's precision, so retries and subsequent reads agree exactly.
	readback := doSCIM(t, ts, http.MethodGet, path, provisionToken, "", nil)
	var storedResource scim.User
	if readback.Code != http.StatusOK || json.Unmarshal(readback.Body.Bytes(), &storedResource) != nil || storedResource.Meta == nil || resource.Meta == nil || storedResource.Meta.LastModified == nil || resource.Meta.LastModified == nil || !storedResource.Meta.LastModified.Equal(*resource.Meta.LastModified) {
		t.Fatalf("offboard response/readback timestamps differ: response=%s read=%s", offboard.Body, readback.Body)
	}
	if code, _ := doSession(t, ts, http.MethodGet, "/api/v1/access/roles", session); code != http.StatusForbidden {
		t.Fatalf("offboarded real-subject session=%d, want403", code)
	}
	if code, _ := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", bearer, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("offboarded real-subject token=%d, want401", code)
	}
	if _, err := st.GetTenantMember(ctx, tenantID, userName); err == nil {
		t.Fatal("provisioning also created a separate email-named principal")
	}

	t.Run("missing binding cannot create a shadow account", func(t *testing.T) {
		payload := map[string]any{"userName": "missing-binding@example.test", "active": true}
		got := doSCIM(t, ts, http.MethodPost, "/scim/v2/Users", provisionToken, "missing-binding", payload)
		if got.Code != http.StatusBadRequest {
			t.Fatalf("missing externalId=%d %s", got.Code, got.Body)
		}
		if _, err := st.GetTenantMember(ctx, tenantID, "missing-binding@example.test"); !store.IsNotFound(err) {
			t.Fatalf("shadow account err=%v", err)
		}
	})
	t.Run("inactive first provisioning has no activation event", func(t *testing.T) {
		const inactiveSubject = "never-active-opaque-subject"
		payload := map[string]any{"userName": "inactive-first@example.test", "externalId": inactiveSubject, "active": false}
		got := doSCIM(t, ts, http.MethodPost, "/scim/v2/Users", provisionToken, "inactive-first", payload)
		if got.Code != http.StatusCreated || !bytes.Contains(got.Body.Bytes(), []byte(`"active":false`)) {
			t.Fatalf("inactive first=%d %s", got.Code, got.Body)
		}
		upserts, offboards := 0, 0
		if err := log.Replay(ctx, 0, func(ev events.Event) error {
			if ev.TenantID != tenantID || !bytes.Contains(ev.Data, []byte(`"subject":"`+inactiveSubject+`"`)) {
				return nil
			}
			if ev.Type == projections.EventTenantMemberUpserted {
				upserts++
			}
			if ev.Type == projections.EventTenantMemberOffboarded {
				offboards++
				if ev.SchemaVersion != projections.TenantMemberSCIMSchemaVersion {
					t.Errorf("binding event schema=%d", ev.SchemaVersion)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if upserts != 0 || offboards != 1 {
			t.Fatalf("inactive-first emitted upserts=%d offboards=%d", upserts, offboards)
		}
	})
	t.Run("concurrent case-insensitive alias collision is rejected before append", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make(chan *scimTestResponse, 2)
		for _, item := range []struct{ sub, name string }{{"collision-opaque-a", "same-alias@example.test"}, {"collision-opaque-b", "SAME-ALIAS@example.test"}} {
			wg.Add(1)
			go func(sub, name string) {
				defer wg.Done()
				results <- doSCIM(t, ts, http.MethodPost, "/scim/v2/Users", provisionToken, "collision-"+sub, map[string]any{"userName": name, "externalId": sub, "active": true})
			}(item.sub, item.name)
		}
		wg.Wait()
		close(results)
		success, conflict := 0, 0
		for result := range results {
			switch result.Code {
			case http.StatusCreated:
				success++
			case http.StatusConflict:
				conflict++
			default:
				t.Fatalf("collision=%d %s", result.Code, result.Body)
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatalf("success=%d conflict=%d", success, conflict)
		}
		count := 0
		if err := log.Replay(ctx, 0, func(ev events.Event) error {
			if ev.TenantID == tenantID && ev.Type == projections.EventTenantMemberUpserted && bytes.Contains(ev.Data, []byte(`"subject":"collision-opaque-`)) {
				count++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("alias race appended %d events, want one valid event", count)
		}
	})
}
