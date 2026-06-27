package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedSCIMProvisioningReflectsRBAC(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL and embedded NATS; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const scimToken = "scim-test-token"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "platform-admin", []string{
		string(authz.AccessRead), string(authz.AccessWrite),
	})

	tokenFile := t.TempDir() + "/scim.token"
	if err := writeSecretFile(tokenFile, []byte(scimToken)); err != nil {
		t.Fatalf("write scim token file: %v", err)
	}
	sessions := auth.NewSessionIssuer([]byte("scim-session-secret-0123456789012345"), time.Hour)
	aliceSession, err := sessions.Issue("alice@example.com", tenantID, "alice@example.com", nil)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store: st,
		Log:   log,
		SCIM: config.SCIM{
			Enabled: true,
			Tokens:  []config.SCIMToken{{Name: "okta", TenantID: tenantID, TokenFile: tokenFile}},
		},
		APIOptions: []api.Option{api.WithAuth(api.AuthConfig{OIDCEnabled: true, Sessions: sessions})},
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	user := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":    "alice@example.com",
		"externalId":  "okta-alice",
		"displayName": "Alice Example",
		"emails":      []map[string]any{{"value": "alice@example.com", "primary": true}},
		"active":      true,
	}
	createUser := doSCIM(t, ts, http.MethodPost, "/scim/v2/Users", scimToken, "scim-user-create", user)
	if createUser.Code != http.StatusCreated {
		t.Fatalf("create SCIM user = %d, want 201; body=%s", createUser.Code, createUser.Body)
	}
	if ct := createUser.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
		t.Fatalf("SCIM content-type = %q, want application/scim+json", ct)
	}
	aliceID := scimID(t, createUser.Body.Bytes())

	group := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "viewer",
		"members":     []map[string]string{{"value": aliceID, "display": "Alice Example"}},
	}
	createGroup := doSCIM(t, ts, http.MethodPost, "/scim/v2/Groups", scimToken, "scim-group-create", group)
	if createGroup.Code != http.StatusCreated {
		t.Fatalf("create SCIM group = %d, want 201; body=%s", createGroup.Code, createGroup.Body)
	}

	code, members := doBearer(t, ts, http.MethodGet, "/api/v1/access/members?include_offboarded=true", adminToken, "", nil)
	if code != http.StatusOK || !bytes.Contains(members, []byte(`"subject":"alice@example.com"`)) || !bytes.Contains(members, []byte(`"viewer"`)) {
		t.Fatalf("access members = %d body=%s; want SCIM-provisioned alice with viewer role", code, members)
	}
	if code, body := doSession(t, ts, http.MethodGet, "/api/v1/access/roles", aliceSession); code != http.StatusOK || !bytes.Contains(body, []byte(`"name":"viewer"`)) {
		t.Fatalf("SCIM-provisioned session role read = %d body=%s; want viewer RBAC grant from tenant member state", code, body)
	}

	patch := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{
			"op":    "replace",
			"path":  "active",
			"value": false,
		}},
	}
	deprovision := doSCIM(t, ts, http.MethodPatch, "/scim/v2/Users/"+url.PathEscape(aliceID), scimToken, "scim-user-deprovision", patch)
	if deprovision.Code != http.StatusOK || !bytes.Contains(deprovision.Body.Bytes(), []byte(`"active":false`)) {
		t.Fatalf("deprovision SCIM user = %d body=%s; want active=false", deprovision.Code, deprovision.Body.String())
	}
	if code, body := doSession(t, ts, http.MethodGet, "/api/v1/access/roles", aliceSession); code != http.StatusForbidden {
		t.Fatalf("deprovisioned session role read = %d body=%s; want 403 after SCIM offboard removes RBAC grants", code, body)
	}

	var sawUpsert, sawOffboard bool
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID {
			return nil
		}
		switch ev.Type {
		case projections.EventTenantMemberUpserted:
			if bytes.Contains(ev.Data, []byte(`"subject":"alice@example.com"`)) && bytes.Contains(ev.Data, []byte(`"viewer"`)) {
				sawUpsert = true
			}
		case projections.EventTenantMemberOffboarded:
			if bytes.Contains(ev.Data, []byte(`"subject":"alice@example.com"`)) {
				sawOffboard = true
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if !sawUpsert || !sawOffboard {
		t.Fatalf("SCIM did not emit tenant.member upsert/offboard events: upsert=%v offboard=%v", sawUpsert, sawOffboard)
	}
}

type scimTestResponse struct {
	Code    int
	Headers http.Header
	Body    *bytes.Buffer
}

func (r *scimTestResponse) Header() http.Header {
	return r.Headers
}

func doSCIM(t *testing.T, ts *httptest.Server, method, path, token, idem string, body any) *scimTestResponse {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal SCIM body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new SCIM request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/scim+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rec := &scimTestResponse{
		Code:    resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    &bytes.Buffer{},
	}
	_, _ = io.Copy(rec.Body, resp.Body)
	return rec
}

func doSession(t *testing.T, ts *httptest.Server, method, path, session string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("new session request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "__Host-trstctl_session", Value: session})
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func scimID(t *testing.T, body []byte) string {
	t.Helper()
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.ID == "" {
		t.Fatalf("decode SCIM id: id=%q err=%v body=%s", got.ID, err, body)
	}
	return got.ID
}

func writeSecretFile(path string, value []byte) error {
	return os.WriteFile(path, value, 0o600)
}
