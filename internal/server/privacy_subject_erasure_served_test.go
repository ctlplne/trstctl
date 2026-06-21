package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// PRIVACY-001 acceptance: subject erasure is served, event-sourced, and keeps the
// raw data subject out of tenant audit replay/export while preserving evidence
// bundle verification.
func TestServedPrivacySubjectErasureRedactsAuditAndExports(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const subject = "alice@example.com"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	subjectToken := seedServedAPIToken(t, ctx, st, tenantID, subject, []string{
		string(authz.OwnersWrite), string(authz.PrivacyWrite),
	})
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "privacy-admin", []string{
		string(authz.OwnersRead), string(authz.PrivacyRead), string(authz.AuditRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("privacy-001-audit")
	if err != nil {
		_ = log.Close()
		t.Fatalf("generate audit key: %v", err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/owners", subjectToken, "owner-alice", map[string]string{
		"kind": "user", "name": subject, "email": subject,
	})
	if code != http.StatusCreated {
		t.Fatalf("create owner = %d, want 201; body=%s", code, body)
	}
	var ownerResp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ownerResp); err != nil || ownerResp.ID == "" {
		t.Fatalf("decode owner response: id=%q err=%v body=%s", ownerResp.ID, err, body)
	}

	code, body = doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-erasures", subjectToken, "erase-alice", map[string]string{
		"subject": subject, "reason": "data subject request",
	})
	if code != http.StatusCreated {
		t.Fatalf("erase subject = %d, want 201; body=%s", code, body)
	}
	if bytes.Contains(body, []byte(subject)) {
		t.Fatalf("erasure response leaked raw subject: %s", body)
	}
	var erasureResp struct {
		SubjectRef string         `json:"subject_ref"`
		Counts     map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(body, &erasureResp); err != nil || erasureResp.SubjectRef == "" {
		t.Fatalf("decode erasure response: ref=%q err=%v body=%s", erasureResp.SubjectRef, err, body)
	}
	if erasureResp.Counts["api_tokens"] != 1 {
		t.Fatalf("api token erasure count = %d, want 1", erasureResp.Counts["api_tokens"])
	}

	owner, err := st.GetOwner(ctx, tenantID, ownerResp.ID)
	if err != nil {
		t.Fatalf("load owner after erasure: %v", err)
	}
	if owner.Email != "" || strings.Contains(owner.Name, subject) || !strings.HasPrefix(owner.Name, "erased:") {
		t.Fatalf("owner after erasure = name %q email %q", owner.Name, owner.Email)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/access/roles", subjectToken, "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("erased subject token still authenticated = %d body=%s", code, body)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/events?q="+url.QueryEscape(subject), adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit search by erased subject = %d body=%s", code, body)
	}
	if bytes.Contains(body, []byte(subject)) || !bytes.Contains(body, []byte(`"count":0`)) {
		t.Fatalf("audit search leaked or matched erased subject: %s", body)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/events", adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit events = %d body=%s", code, body)
	}
	if bytes.Contains(body, []byte(subject)) || !bytes.Contains(body, []byte("erased:")) {
		t.Fatalf("audit events did not redact erased subject: %s", body)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/export", adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit export = %d body=%s", code, body)
	}
	var exportResp struct {
		Bundle string `json:"bundle"`
	}
	if err := json.Unmarshal(body, &exportResp); err != nil || exportResp.Bundle == "" {
		t.Fatalf("decode export response: %v body=%s", err, body)
	}
	bundle, err := audit.VerifyBundle(exportResp.Bundle, auditKey.JWKS())
	if err != nil {
		t.Fatalf("verify export bundle: %v", err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal verified bundle: %v", err)
	}
	if bytes.Contains(bundleJSON, []byte(subject)) || !bytes.Contains(bundleJSON, []byte("erased:")) {
		t.Fatalf("verified export bundle did not redact erased subject: %s", bundleJSON)
	}

	var sawErasureEvent bool
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type == projections.EventPrivacySubjectErased && ev.TenantID == tenantID {
			sawErasureEvent = true
			if bytes.Contains(ev.Data, []byte(subject)) || !bytes.Contains(ev.Data, []byte(erasureResp.SubjectRef)) {
				t.Fatalf("privacy erasure event payload = %s; want subject_ref without raw subject", ev.Data)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if !sawErasureEvent {
		t.Fatal("privacy.subject.erased event was not recorded")
	}
}
