// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A role reduction must take effect on an existing browser session even when
// the source event is retained but its member read model cannot be projected.
func TestServedMemberRoleNarrowingDeniesCookieDuringProjectionGap(t *testing.T) {
	if testing.Short() {
		t.Skip("starts PostgreSQL and embedded JetStream")
	}
	ctx := context.Background()
	const tenantID = "f2630000-0000-4000-8000-000000000264"
	const subject = "qa-role-narrowing-gap"
	dsn := serverTestPostgresDSN(t)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	resetServerTestStore(t, st)
	idp := newMockIdP(t, "trstctl-ui")
	idp.registerUser("code-role-gap", subject, map[string]any{"tenant": tenantID})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + ln.Addr().String()
	srv := buildServer(t, ctx, dsn, config.OIDC{
		Enabled: true, Issuer: idp.issuer, ClientID: "trstctl-ui",
		AuthEndpoint: idp.issuer + "/authorize", TokenEndpoint: idp.issuer + "/token",
		RedirectURI: baseURL + "/auth/callback", JWKSJSON: idp.jwksJSON(t),
		SessionSecretFile: t.TempDir() + "/session.secret", SessionTTL: "1h",
		TenantClaim: "tenant", ClaimIsTenant: true, DefaultRoles: []string{"admin"},
	})
	defer func() { _ = srv.Shutdown(context.Background()) }()
	registerServerTestTenant(t, srv.store, srv.log, tenantID, "role narrowing gap")
	ts := httptest.NewUnstartedServer(srv.Handler())
	_ = ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	servedOIDCLoginF263(t, baseURL, idp, jar, "code-role-gap")
	if code := servedSessionGetF263(t, baseURL, jar, "/api/v1/audit/events?limit=1"); code != http.StatusOK {
		t.Fatalf("baseline admin audit read = %d, want 200", code)
	}
	admin := seedServedAPIToken(t, ctx, srv.store, tenantID, "qa-role-gap-admin", []string{"*"})
	const trigger = "qa_member_role_projection_gap"
	const function = "qa_member_role_projection_gap_fn"
	clearFault := func() {
		if _, err := st.SystemPool().Exec(context.Background(),
			"DROP TRIGGER IF EXISTS "+trigger+" ON tenant_members; DROP FUNCTION IF EXISTS "+function+"()"); err != nil {
			t.Errorf("clear owned role fault: %v", err)
		}
	}
	defer clearFault()
	_, err = st.SystemPool().Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.tenant_id = '%s'::uuid AND NEW.subject = '%s' AND NEW.roles = ARRAY['viewer']::text[] THEN
				RAISE EXCEPTION 'owned member role projection fault';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s BEFORE INSERT OR UPDATE ON tenant_members
		FOR EACH ROW EXECUTE FUNCTION %s()`, function, tenantID, subject, trigger, function))
	if err != nil {
		t.Fatalf("install owned role fault: %v", err)
	}
	if code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+subject, admin,
		"qa-role-narrowing-gap-1", map[string]any{"roles": []string{"viewer"}, "source": "manual"}); code < 500 {
		t.Fatalf("faulted narrowing = %d body=%s, want retryable 5xx", code, body)
	}
	var retained int
	if err := srv.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == tenantID && event.Type == projections.EventTenantMemberUpserted {
			retained++
		}
		return nil
	}); err != nil || retained != 1 {
		t.Fatalf("retained role events=%d err=%v, want one", retained, err)
	}
	if pending, err := srv.store.ListPendingTenantMemberUpsertCommands(ctx, tenantID, 100); err != nil || len(pending) != 1 {
		t.Fatalf("pending role commands=%d err=%v, want one", len(pending), err)
	}
	if _, err := srv.store.GetTenantMember(ctx, tenantID, subject); !store.IsNotFound(err) {
		t.Fatalf("fault did not retain stale absent read model: %v", err)
	}
	if code := servedSessionGetF263(t, baseURL, jar, "/api/v1/audit/events?limit=1"); code != http.StatusForbidden {
		t.Fatalf("retained role reduction admitted old admin cookie: status=%d, want 403", code)
	}
	clearFault()
	if healed, err := srv.orch.ReconcilePendingTenantMemberUpserts(ctx); err != nil || healed != 1 {
		t.Fatalf("recover pending role command: healed=%d err=%v, want one", healed, err)
	}
	if roles, _ := servedSessionMeF263(t, baseURL, jar); len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("old cookie after role projection has roles=%v, want viewer", roles)
	}
	if code := servedSessionGetF263(t, baseURL, jar, "/api/v1/audit/events?limit=1"); code != http.StatusForbidden {
		t.Fatalf("old cookie after role projection read audit: status=%d, want 403", code)
	}
	// Make only the role-authority read fail. The earlier offboard check does
	// not query this table, so this isolates the old cookie-role fallback.
	if _, err := st.SystemPool().Exec(ctx, `REVOKE SELECT ON tenant_member_upsert_commands FROM trstctl_app`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := st.SystemPool().Exec(context.Background(), `GRANT SELECT ON tenant_member_upsert_commands TO trstctl_app`); err != nil {
			t.Errorf("restore owned role read permission: %v", err)
		}
	}()
	if code := servedSessionGetF263(t, baseURL, jar, "/auth/me"); code < 500 {
		t.Fatalf("failed role-authority read returned stale cookie roles: status=%d, want retryable error", code)
	}
	if _, err := st.SystemPool().Exec(ctx, `GRANT SELECT ON tenant_member_upsert_commands TO trstctl_app`); err != nil {
		t.Fatal(err)
	}

	// A crash after the first-writer claim but before source append must not
	// make a later urgent offboard wait or permit delayed reactivation.
	const crashSubject = "qa-role-crash-before-append"
	data, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: crashSubject, Roles: []string{"viewer"}, Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldEvent := events.Event{ID: uuid.NewString(), Type: projections.EventTenantMemberUpserted,
		TenantID: tenantID, SchemaVersion: 1, Time: time.Now().UTC().Truncate(time.Microsecond), Data: data}
	command, created, err := srv.store.ClaimTenantMemberUpsertCommand(ctx, tenantID, crashSubject, oldEvent, false)
	if err != nil || !created || command.Status != "pending" {
		t.Fatalf("pre-append role command: created=%v status=%q err=%v", created, command.Status, err)
	}
	if code, body := doBearer(t, ts, http.MethodPost, "/api/v1/access/members/"+crashSubject+"/offboard",
		admin, "qa-role-crash-offboard", map[string]string{"reason": "urgent QA offboard"}); code != http.StatusOK {
		t.Fatalf("urgent offboard behind pending role command = %d body=%s", code, body)
	}
	if healed, err := srv.orch.ReconcilePendingTenantMemberUpserts(ctx); err != nil || healed != 1 {
		t.Fatalf("supersede unappended role event: healed=%d err=%v", healed, err)
	}
	if _, found, err := srv.log.EventByID(ctx, oldEvent.ID); err != nil || found {
		t.Fatalf("superseded role event appended after offboard: found=%v err=%v", found, err)
	}
	if member, err := srv.store.GetTenantMember(ctx, tenantID, crashSubject); err != nil || member.Status != "offboarded" {
		t.Fatalf("urgent offboard lost to delayed role command: status=%q err=%v", member.Status, err)
	}
	if code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+crashSubject, admin,
		"qa-role-crash-explicit-rehire", map[string]any{"roles": []string{"viewer"}, "source": "manual"}); code != http.StatusOK {
		t.Fatalf("explicit rehire after completed offboard = %d body=%s", code, body)
	}
	if member, err := srv.store.GetTenantMember(ctx, tenantID, crashSubject); err != nil || member.Status != "active" {
		t.Fatalf("explicit rehire failed: status=%q err=%v", member.Status, err)
	}
	// A retry must keep the first pending event. A changed role payload under
	// the same subject is a conflict, not a replacement of the denial fence.
	const retrySubject = "qa-role-first-writer"
	retryData, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: retrySubject, Roles: []string{"viewer"}, Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	retryEvent := events.Event{ID: uuid.NewString(), Type: projections.EventTenantMemberUpserted,
		TenantID: tenantID, SchemaVersion: 1, Time: time.Now().UTC().Truncate(time.Microsecond), Data: retryData}
	first, created, err := srv.store.ClaimTenantMemberUpsertCommand(ctx, tenantID, retrySubject, retryEvent, false)
	if err != nil || !created {
		t.Fatalf("claim first role command: created=%t err=%v", created, err)
	}
	second, created, err := srv.store.ClaimTenantMemberUpsertCommand(ctx, tenantID, retrySubject,
		events.Event{ID: uuid.NewString(), Type: retryEvent.Type, TenantID: tenantID,
			SchemaVersion: 1, Time: time.Now().UTC().Truncate(time.Microsecond), Data: retryData}, false)
	if err != nil || created || second.Event.ID != first.Event.ID {
		t.Fatalf("exact retry changed role first writer: created=%t first=%s second=%s err=%v",
			created, first.Event.ID, second.Event.ID, err)
	}
	changedData, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: retrySubject, Roles: []string{"admin"}, Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.store.ClaimTenantMemberUpsertCommand(ctx, tenantID, retrySubject,
		events.Event{ID: uuid.NewString(), Type: retryEvent.Type, TenantID: tenantID,
			SchemaVersion: 1, Time: time.Now().UTC().Truncate(time.Microsecond), Data: changedData}, false); err == nil {
		t.Fatal("changed role payload replaced pending first writer")
	}
	// The same source event may already exist when offboarding wins projection.
	// Its later replay must not reactivate the offboarded subject.
	if _, err := srv.log.Append(ctx, first.Event); err != nil {
		t.Fatalf("append pending role source: %v", err)
	}
	if code, body := doBearer(t, ts, http.MethodPost, "/api/v1/access/members/"+retrySubject+"/offboard",
		admin, "qa-role-after-append-offboard", map[string]string{"reason": "urgent QA offboard"}); code != http.StatusOK {
		t.Fatalf("offboard after role source append = %d body=%s", code, body)
	}
	if healed, err := srv.orch.ReconcilePendingTenantMemberUpserts(ctx); err != nil || healed != 1 {
		t.Fatalf("recover stale role source: healed=%d err=%v", healed, err)
	}
	if member, err := srv.store.GetTenantMember(ctx, tenantID, retrySubject); err != nil || member.Status != "offboarded" {
		t.Fatalf("late role projection reactivated offboarded member: status=%q err=%v", member.Status, err)
	}
}
