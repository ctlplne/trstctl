// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A retained offboard event must remove authority before its SQL read model
// catches up. The fault affects only one disposable tenant and subject.
func TestServedMemberOffboardDeniesBearerDuringProjectionGap(t *testing.T) {
	if testing.Short() {
		t.Skip("served offboard fault needs PostgreSQL and embedded JetStream")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const subject = "qa-offboard-gap-member"
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "offboard gap"}); err != nil {
		t.Fatal(err)
	}
	admin := seedServedAPIToken(t, ctx, st, tenantID, "qa-offboard-admin", []string{"access:read", "access:write", "access:role.assign"})
	memberToken := seedServedAPIToken(t, ctx, st, tenantID, subject, []string{"access:read"})
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
	upsertMember(t, ts, admin, subject, []string{"viewer"})
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", memberToken, "", nil); code != http.StatusOK {
		t.Fatalf("baseline member bearer = %d body=%s", code, body)
	}
	// A source event can be retained while its token row is still absent.
	// Project it only after the offboard and later explicit rehire.
	lateRaw, lateHash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(lateRaw)
	lateID := uuid.NewString()
	latePayload, err := json.Marshal(projections.APITokenCreated{ID: lateID,
		TokenHash: lateHash, Subject: subject, Scopes: []string{"access:read"}})
	if err != nil {
		t.Fatal(err)
	}
	lateEvent, err := log.Append(ctx, events.Event{ID: uuid.NewString(), Type: projections.EventAPITokenCreated,
		TenantID: tenantID, SchemaVersion: events.DefaultSchemaVersion,
		Time: time.Now().UTC().Truncate(time.Microsecond), Data: latePayload})
	if err != nil {
		t.Fatal(err)
	}

	const trigger = "qa_member_offboard_projection_gap"
	const function = "qa_member_offboard_projection_gap_fn"
	clearFault := func() {
		if _, err := st.SystemPool().Exec(context.Background(),
			"DROP TRIGGER IF EXISTS "+trigger+" ON tenant_members; DROP FUNCTION IF EXISTS "+function+"()"); err != nil {
			t.Errorf("clear owned offboard fault: %v", err)
		}
	}
	defer clearFault()
	_, err = st.SystemPool().Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.tenant_id = '%s'::uuid AND NEW.subject = '%s' AND NEW.status = 'offboarded' THEN
				RAISE EXCEPTION 'owned member offboard projection fault';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s BEFORE INSERT OR UPDATE ON tenant_members
		FOR EACH ROW EXECUTE FUNCTION %s()`, function, tenantID, subject, trigger, function))
	if err != nil {
		t.Fatalf("install owned offboard fault: %v", err)
	}
	path := "/api/v1/access/members/" + subject + "/offboard"
	if code, body := doBearer(t, ts, http.MethodPost, path, admin, "qa-offboard-gap-1", map[string]string{"reason": "retired in QA"}); code < 500 {
		t.Fatalf("faulted offboard = %d body=%s, want retryable 5xx", code, body)
	}
	retained := 0
	var offboardEvent events.Event
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == tenantID && event.Type == projections.EventTenantMemberOffboarded {
			retained++
			offboardEvent = event
		}
		return nil
	}); err != nil || retained != 1 {
		t.Fatalf("retained offboard events=%d err=%v, want exactly one", retained, err)
	}
	member, err := st.GetTenantMember(ctx, tenantID, subject)
	if err != nil || member.Status != "active" {
		t.Fatalf("fault did not retain stale active read model: status=%q err=%v", member.Status, err)
	}
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", memberToken, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("retained offboard event admitted old bearer: status=%d body=%s; want 401", code, body)
	}
	if code, body := doBearer(t, ts, http.MethodPost, "/api/v1/access/api-tokens", admin,
		"qa-pending-token", map[string]any{"subject": subject, "scopes": []string{"access:read"}}); code != http.StatusConflict {
		t.Fatalf("pending offboard allowed token creation: status=%d body=%s", code, body)
	}
	if code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+subject, admin,
		"qa-pending-rehire", map[string]any{"display_name": subject, "roles": []string{"viewer"}}); code != http.StatusConflict {
		t.Fatalf("pending offboard allowed rehire: status=%d body=%s", code, body)
	}
	clearFault()
	if code, body := doBearer(t, ts, http.MethodPost, path, admin, "qa-offboard-gap-retry", map[string]string{"reason": "retired in QA"}); code != http.StatusOK {
		t.Fatalf("retry canonical offboard after fault repair = %d body=%s", code, body)
	}
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", memberToken, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("completed offboard admitted old bearer: status=%d body=%s", code, body)
	}
	if code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+subject, admin,
		"qa-rehire-1", map[string]any{"display_name": subject, "roles": []string{"viewer"}, "source": "manual"}); code != http.StatusOK {
		t.Fatalf("explicit rehire = %d body=%s", code, body)
	}
	member, err = st.GetTenantMember(ctx, tenantID, subject)
	if err != nil || member.Status != "active" {
		t.Fatalf("rehire member status=%q err=%v", member.Status, err)
	}
	denied, err := st.MemberOffboardStatus(ctx, tenantID, subject)
	if err != nil || denied {
		t.Fatalf("rehire admission denied=%v err=%v", denied, err)
	}
	newToken := createServedToken(t, ts, admin, subject, []string{"access:read"})
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", newToken, "", nil); code != http.StatusOK {
		t.Fatalf("new rehire bearer = %d body=%s", code, body)
	}
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", memberToken, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("rehire revived old bearer: status=%d body=%s", code, body)
	}
	if err := projections.New(st).Apply(ctx, offboardEvent); err != nil {
		t.Fatalf("duplicate older offboard projection: %v", err)
	}
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", newToken, "", nil); code != http.StatusOK {
		t.Fatalf("older offboard replay displaced later rehire: status=%d body=%s", code, body)
	}
	if err := projections.New(st).Apply(ctx, lateEvent); err != nil {
		t.Fatalf("late pre-offboard token projection: %v", err)
	}
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", string(lateRaw), "", nil); code != http.StatusUnauthorized {
		t.Fatalf("late pre-offboard bearer revived after rehire: status=%d body=%s", code, body)
	}
	// Historical offboard events have no independent command row. Their
	// projected tombstones must still refuse new credentials after upgrade.
	const legacySubject = "qa-legacy-offboard-member"
	legacyToken := seedServedAPIToken(t, ctx, st, tenantID, legacySubject, []string{"access:read"})
	upsertMember(t, ts, admin, legacySubject, []string{"viewer"})
	legacyPayload, err := json.Marshal(projections.TenantMemberOffboarded{Subject: legacySubject, Reason: "legacy retirement"})
	if err != nil {
		t.Fatal(err)
	}
	legacyEvent, err := log.Append(ctx, events.Event{ID: uuid.NewString(), Type: projections.EventTenantMemberOffboarded,
		TenantID: tenantID, SchemaVersion: events.DefaultSchemaVersion,
		Time: time.Now().UTC().Truncate(time.Microsecond), Data: legacyPayload})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, legacyEvent); err != nil {
		t.Fatal(err)
	}
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", legacyToken, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("legacy offboard bearer = %d body=%s", code, body)
	}
	if code, body := doBearer(t, ts, http.MethodPost, "/api/v1/access/api-tokens", admin,
		"qa-legacy-token", map[string]any{"subject": legacySubject, "scopes": []string{"access:read"}}); code != http.StatusConflict {
		t.Fatalf("legacy offboard permitted new token = %d body=%s", code, body)
	}
}
