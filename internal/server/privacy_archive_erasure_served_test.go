// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// PRIVACY-003 acceptance: pre-erasure backup/audit-archive residue is not left as
// a docs-only operator chore. Operators can record tenant-scoped, non-PII evidence
// for deletion, legal hold, or cryptographic shredding, and the privacy surface
// lists that evidence back.
func TestServedPrivacyArchiveErasureAttestations(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const rawSubject = "alice.archive@example.com"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "privacy-archive-admin", []string{
		string(authz.PrivacyRead), string(authz.PrivacyWrite), string(authz.AuditRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("privacy-archive-audit")
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

	req := map[string]any{
		"subject":       rawSubject,
		"artifact_type": "signed_audit_archive",
		"artifact_uri":  "s3://worm-audit/acme/alice.archive@example.com/audit-42.jws",
		"action":        "deleted",
		"reason":        "DSR archive cleanup for alice.archive@example.com",
		"evidence_refs": []string{"ticket:DSR-42", "object-version:archive-42"},
	}
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/privacy/archive-erasure-attestations", adminToken, "privacy-archive-attest-1", req)
	if code != http.StatusCreated {
		t.Fatalf("create archive erasure attestation = %d, want 201; body=%s", code, body)
	}
	if bytes.Contains(body, []byte(rawSubject)) {
		t.Fatalf("archive erasure response leaked raw subject: %s", body)
	}
	subjectRef := privacy.SubjectRef(tenantID, rawSubject)
	if !bytes.Contains(body, []byte(subjectRef)) || !bytes.Contains(body, []byte(`"action":"deleted"`)) {
		t.Fatalf("archive erasure response missing subject ref/action: %s", body)
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/privacy/archive-erasure-attestations", adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list archive erasure attestations = %d, want 200; body=%s", code, body)
	}
	if bytes.Contains(body, []byte(rawSubject)) || !bytes.Contains(body, []byte(subjectRef)) {
		t.Fatalf("archive erasure list leaked raw subject or missed subject ref: %s", body)
	}

	var sawEvent bool
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type != projections.EventPrivacyArchiveErasureAttested || ev.TenantID != tenantID {
			return nil
		}
		sawEvent = true
		if bytes.Contains(ev.Data, []byte(rawSubject)) {
			t.Fatalf("privacy archive erasure event leaked raw subject: %s", ev.Data)
		}
		if !bytes.Contains(ev.Data, []byte(subjectRef)) || !bytes.Contains(ev.Data, []byte(`"artifact_type":"signed_audit_archive"`)) {
			t.Fatalf("privacy archive erasure event missing evidence fields: %s", ev.Data)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if !sawEvent {
		t.Fatal("privacy.archive_erasure.attested event was not recorded")
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
	if bytes.Contains(bundleJSON, []byte(rawSubject)) || !bytes.Contains(bundleJSON, []byte(projections.EventPrivacyArchiveErasureAttested)) {
		t.Fatalf("verified export bundle leaked raw subject or missed archive-erasure event: %s", bundleJSON)
	}
}
