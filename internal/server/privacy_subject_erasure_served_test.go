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
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
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
		if bytes.Contains(ev.Data, []byte(subject)) {
			t.Fatalf("event %s payload leaked erased subject after storage rewrite: %s", ev.Type, ev.Data)
		}
		if ev.Actor != nil && strings.Contains(ev.Actor.Subject, subject) {
			t.Fatalf("event %s actor leaked erased subject after storage rewrite: %+v", ev.Type, ev.Actor)
		}
		if ev.Type == projections.EventPrivacySubjectErased && ev.TenantID == tenantID {
			sawErasureEvent = true
			if !bytes.Contains(ev.Data, []byte(erasureResp.SubjectRef)) {
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

// PRIVACY-004 hardening: the served erasure route must keep pace with newer PII
// catalog fixture classes, including discovery source config and finding metadata
// values that carry principals, IP addresses, and user agents.
func TestServedPrivacySubjectErasureRedactsDiscoveryJSONReadSurfaces(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const (
		tenantID  = "11111111-1111-1111-1111-111111111111"
		principal = "svc-privacy@example.com"
		ip        = "203.0.113.44"
		userAgent = "privacy-fixture-agent/1.0"
	)

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	seedSubjectErasureDiscoveryJSON(t, ctx, st, tenantID, principal, ip, userAgent)
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "privacy-admin", []string{
		string(authz.PrivacyRead), string(authz.PrivacyWrite), string(authz.AuditRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("privacy-004-discovery-audit")
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

	for i, raw := range []string{principal, ip, userAgent} {
		if hits := countSubjectErasureDiscoveryJSONHits(t, ctx, st, tenantID, raw); hits == 0 {
			t.Fatalf("seeded discovery JSON does not contain %q before erasure", raw)
		}
		code, body := doBearer(t, ts, http.MethodPost, "/api/v1/privacy/subject-erasures", adminToken, "erase-discovery-json-"+string(rune('a'+i)), map[string]string{
			"subject": raw,
			"reason":  "data subject request",
		})
		if code != http.StatusCreated {
			t.Fatalf("erase discovery JSON subject %q = %d, want 201; body=%s", raw, code, body)
		}
		if bytes.Contains(body, []byte(raw)) {
			t.Fatalf("erasure response for %q leaked raw subject: %s", raw, body)
		}
		var erasureResp struct {
			SubjectRef string         `json:"subject_ref"`
			Counts     map[string]int `json:"counts"`
		}
		if err := json.Unmarshal(body, &erasureResp); err != nil || erasureResp.SubjectRef == "" {
			t.Fatalf("decode discovery erasure response for %q: ref=%q err=%v body=%s", raw, erasureResp.SubjectRef, err, body)
		}
		if erasureResp.Counts["discovery_sources"] != 1 || erasureResp.Counts["discovery_findings"] != 1 {
			t.Fatalf("discovery erasure counts for %q = sources:%d findings:%d, want 1/1; counts=%v",
				raw, erasureResp.Counts["discovery_sources"], erasureResp.Counts["discovery_findings"], erasureResp.Counts)
		}
		if hits := countSubjectErasureDiscoveryJSONHits(t, ctx, st, tenantID, raw); hits != 0 {
			t.Fatalf("served erasure left raw discovery JSON value %q in %d source config/finding metadata values", raw, hits)
		}
		placeholder := privacy.Placeholder(privacy.SubjectRef(tenantID, raw))
		if hits := countSubjectErasureDiscoveryJSONHits(t, ctx, st, tenantID, placeholder); hits == 0 {
			t.Fatalf("served erasure for %q did not write discovery JSON placeholder %q", raw, placeholder)
		}
		assertEventLogOmitsRawSubject(t, ctx, log, tenantID, raw)
	}
}

func seedSubjectErasureDiscoveryJSON(t *testing.T, ctx context.Context, st *store.Store, tenantID, principal, ip, userAgent string) {
	t.Helper()
	now := time.Now().UTC()
	config := jsonText(t, map[string]any{
		"events": []any{
			map[string]any{
				"principal":  principal,
				"owner":      principal,
				"ip":         ip,
				"user_agent": userAgent,
			},
		},
	})
	metadata := jsonText(t, map[string]any{
		"principal":     principal,
		"owner":         principal,
		"ip":            ip,
		"user_agent":    userAgent,
		"evidence_refs": []any{principal},
	})
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_sources (id, tenant_id, kind, name, config, created_at, updated_at)
			 VALUES ('aaaaaaaa-0000-0000-0000-000000000001', $1, 'nhi_behavior', 'privacy-discovery-json', $2::jsonb, $3, $3)`,
			tenantID, config, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_runs (id, tenant_id, source_id, status, dry_run, requested_by, started_at, completed_at, created_at)
			 VALUES ('aaaaaaaa-0000-0000-0000-000000000002', $1, 'aaaaaaaa-0000-0000-0000-000000000001', 'succeeded', false, 'privacy-seed', $2, $2, $2)`,
			tenantID, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO discovery_findings
			        (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, risk_score, metadata, discovered_at,
			         triage_status, triage_actor, triage_reason, triaged_at)
			 VALUES ('aaaaaaaa-0000-0000-0000-000000000003', $1, 'aaaaaaaa-0000-0000-0000-000000000002',
			         'aaaaaaaa-0000-0000-0000-000000000001', 'nhi_behavior_finding', 'ref-nhi-behavior',
			         'privacy:nhi_behavior', 'fp-privacy-discovery-json', 80, $2::jsonb, $3, 'open', '', '', NULL)`,
			tenantID, metadata, now)
		return err
	}); err != nil {
		t.Fatalf("seed discovery JSON privacy fixture: %v", err)
	}
}

func countSubjectErasureDiscoveryJSONHits(t *testing.T, ctx context.Context, st *store.Store, tenantID, raw string) int {
	t.Helper()
	var hits int
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
			  (SELECT count(*) FROM discovery_sources
			    WHERE tenant_id = $1
			      AND EXISTS (
			            SELECT 1 FROM jsonb_path_query(config, '$.**') AS v(value)
			             WHERE jsonb_typeof(v.value) = 'string' AND v.value #>> '{}' = $2
			          )) +
			  (SELECT count(*) FROM discovery_findings
			    WHERE tenant_id = $1
			      AND EXISTS (
			            SELECT 1 FROM jsonb_path_query(metadata, '$.**') AS v(value)
			             WHERE jsonb_typeof(v.value) = 'string' AND v.value #>> '{}' = $2
			          ))`,
			tenantID, raw).Scan(&hits)
	}); err != nil {
		t.Fatalf("count discovery JSON hits for %q: %v", raw, err)
	}
	return hits
}

func assertEventLogOmitsRawSubject(t *testing.T, ctx context.Context, log *events.Log, tenantID, raw string) {
	t.Helper()
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID {
			return nil
		}
		if bytes.Contains(ev.Data, []byte(raw)) {
			t.Fatalf("event %s payload leaked erased subject %q after storage rewrite: %s", ev.Type, raw, ev.Data)
		}
		if ev.Actor != nil && strings.Contains(ev.Actor.Subject, raw) {
			t.Fatalf("event %s actor leaked erased subject %q after storage rewrite: %+v", ev.Type, raw, ev.Actor)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log after erasing %q: %v", raw, err)
	}
}

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON fixture: %v", err)
	}
	return string(b)
}
