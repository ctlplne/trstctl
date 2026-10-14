// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedPrivacyErasureSupersedesPendingMemberRole(t *testing.T) {
	for _, tc := range []struct {
		name      string
		projected bool
		retained  bool
	}{
		{name: "projected-unappended", projected: true},
		{name: "projected-retained", projected: true, retained: true},
		{name: "absent-unappended"},
		{name: "absent-retained", retained: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runServedPendingMemberRolePrivacyCase(t, tc.name, tc.projected, tc.retained)
		})
	}
}

func runServedPendingMemberRolePrivacyCase(t *testing.T, name string, projected, retained bool) {
	if testing.Short() {
		t.Skip("starts PostgreSQL and history-aware embedded JetStream")
	}
	ctx := context.Background()
	const tenantID = "f2630000-0000-4000-8000-000000000266"
	subject := "qa-pending-role-privacy-" + name
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "pending role erasure"}); err != nil {
		t.Fatal(err)
	}
	admin := seedServedAPIToken(t, ctx, st, tenantID, "qa-privacy-admin", []string{"*"})
	auditKey, err := jose.GenerateRSASigningKey("qa-member-role-erasure")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, st, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if projected {
		upsertMember(t, ts, admin, subject, []string{"viewer"})
	}
	issuedAt := time.Now().UTC().Truncate(time.Microsecond)
	oldSessionHash := strings.Repeat("a", 64)
	if err := st.CreateBrowserSession(ctx, store.BrowserSession{
		TenantID: tenantID, SessionHash: oldSessionHash,
		SubjectHash: privacy.SubjectRef(tenantID, subject),
		CreatedAt:   issuedAt, LastSeenAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
	}); err != nil {
		t.Fatalf("old browser session: %v", err)
	}
	oldToken, err := st.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantID, Subject: subject, TokenHash: strings.Repeat("c", 64), Scopes: []string{"certificates:read"},
	})
	if err != nil {
		t.Fatalf("old subject token: %v", err)
	}
	payload, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: subject, Roles: []string{"admin"}, Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	roleEvent := events.Event{ID: uuid.NewString(), Type: projections.EventTenantMemberUpserted,
		TenantID: tenantID, SchemaVersion: 1, Time: time.Now().UTC().Truncate(time.Microsecond), Data: payload}
	if _, created, err := st.ClaimTenantMemberUpsertCommand(ctx, tenantID, subject, roleEvent, projected); err != nil || !created {
		t.Fatalf("pending role before erasure: created=%t err=%v", created, err)
	}
	if retained {
		if _, err := log.Append(ctx, roleEvent); err != nil {
			t.Fatalf("retain role source before erasure: %v", err)
		}
	}
	if code, body := doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-erasures", admin,
		"qa-member-role-privacy-erasure-"+name, map[string]string{"subject": subject, "reason": "QA subject erasure"}); code != http.StatusCreated {
		t.Fatalf("privacy erasure = %d body=%s", code, body)
	}
	if healed, err := srv.orch.ReconcilePendingTenantMemberUpserts(ctx); err != nil || healed != 1 {
		t.Fatalf("role recovery after erasure: healed=%d err=%v", healed, err)
	}
	rows, err := st.ListTenantMembersPage(ctx, tenantID, "", true, 100)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantID, subject))
	for _, member := range rows {
		if (member.Subject == subject || member.Subject == placeholder) && member.Status == "active" {
			t.Fatalf("pending role recovery reactivated erased member: subject=%q status=%q", member.Subject, member.Status)
		}
	}
	if denied, err := st.MemberOffboardStatus(ctx, tenantID, subject); err != nil || !denied {
		t.Fatalf("erased member admitted old session: denied=%t err=%v", denied, err)
	}
	oldSession, err := st.GetBrowserSession(ctx, tenantID, oldSessionHash)
	if err != nil || oldSession.RevokedAt == nil {
		t.Fatalf("erasure retained old browser session: revoked=%v err=%v", oldSession.RevokedAt, err)
	}
	oldToken, err = st.GetAPIToken(ctx, tenantID, oldToken.ID)
	if err != nil || oldToken.RevokedAt == nil {
		t.Fatalf("erasure retained old token: revoked=%v err=%v", oldToken.RevokedAt, err)
	}
	if code, body := doBearer(t, ts, http.MethodPut, "/api/v1/access/members/"+subject, admin,
		"qa-fresh-member-after-privacy-"+name,
		map[string]any{"display_name": "Fresh QA member", "roles": []string{"viewer"}, "source": "manual"}); code != http.StatusOK {
		t.Fatalf("explicit post-erasure rehire = %d body=%s", code, body)
	}
	if denied, err := st.MemberOffboardStatus(ctx, tenantID, subject); err != nil || denied {
		t.Fatalf("fresh rehire remained offboarded: denied=%t err=%v", denied, err)
	}
	member, err := st.GetTenantMember(ctx, tenantID, subject)
	if err != nil || member.Status != "active" {
		t.Fatalf("fresh rehire member: status=%q err=%v", member.Status, err)
	}
	rows, err = st.ListTenantMembersPage(ctx, tenantID, "", true, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Subject == placeholder {
			t.Fatalf("fresh rehire left old privacy authority tombstone: %+v", row)
		}
	}
	newSessionHash := strings.Repeat("b", 64)
	if err := st.CreateBrowserSession(ctx, store.BrowserSession{
		TenantID: tenantID, SessionHash: newSessionHash,
		SubjectHash: privacy.SubjectRef(tenantID, subject),
		CreatedAt:   time.Now().UTC(), LastSeenAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("fresh post-rehire browser session: %v", err)
	}
	newToken, err := st.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantID, Subject: subject, TokenHash: strings.Repeat("d", 64), Scopes: []string{"certificates:read"},
	})
	if err != nil {
		t.Fatalf("fresh post-rehire token: %v", err)
	}
	var erasureEvent events.Event
	if err := log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.TenantID == tenantID && ev.Type == projections.EventPrivacySubjectErased {
			erasureEvent = ev
		}
		return nil
	}); err != nil || erasureEvent.ID == "" {
		t.Fatalf("find retained erasure source: event=%s err=%v", erasureEvent.ID, err)
	}
	if err := projections.New(st).Apply(ctx, erasureEvent); err != nil {
		t.Fatalf("replay exact older erasure after rehire: %v", err)
	}
	newSession, err := st.GetBrowserSession(ctx, tenantID, newSessionHash)
	if err != nil || newSession.RevokedAt != nil {
		t.Fatalf("older erasure revoked fresh session: revoked=%v err=%v", newSession.RevokedAt, err)
	}
	newToken, err = st.GetAPIToken(ctx, tenantID, newToken.ID)
	if err != nil || newToken.RevokedAt != nil {
		t.Fatalf("older erasure revoked fresh token: revoked=%v err=%v", newToken.RevokedAt, err)
	}
	oldSession, err = st.GetBrowserSession(ctx, tenantID, oldSessionHash)
	if err != nil || oldSession.RevokedAt == nil {
		t.Fatalf("rehire revived old browser session: revoked=%v err=%v", oldSession.RevokedAt, err)
	}
}
