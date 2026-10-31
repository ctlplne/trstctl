// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// seedTenantAuditSegment archives the tenant's current audit records exactly
// as the licensed retention worker's directory archiver does: a signed
// retention segment at <dir>/<tenant>/audit-<count>.jws, the worker's
// audit.archived event ID scheme, and the sealed checkpoint. The worker itself
// is proven against the core reader in ee/auditcompliance.
func seedTenantAuditSegment(t *testing.T, log *events.Log, st *store.Store, key *jose.SigningKey, service *audit.Service, tenantID, dir string) string {
	t.Helper()
	ctx := context.Background()
	records, seed, err := service.SearchWithSeed(ctx, audit.Query{TenantID: tenantID})
	if err != nil || len(records) == 0 {
		t.Fatalf("segment fixture records=%d err=%v", len(records), err)
	}
	boundary := records[len(records)-1]
	payload, err := json.Marshal(audit.Bundle{TenantID: tenantID, GeneratedAt: time.Now().UTC(), Query: audit.Query{TenantID: tenantID},
		Records: records, Count: len(records), PrevHash: seed, ChainHead: boundary.Hash})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := key.SignArtifact(jose.ArtifactAuditRetention, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, tenantID), 0o700); err != nil {
		t.Fatal(err)
	}
	uri := filepath.Join(dir, tenantID, fmt.Sprintf("audit-%020d.jws", boundary.Sequence))
	if err := os.WriteFile(uri, []byte(signed), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpoint := audit.Checkpoint{TenantID: tenantID, BoundarySeq: boundary.StreamSequence, BoundaryHash: boundary.Hash, RecordCount: int(boundary.Sequence), ArchiveURI: uri} // #nosec G115 -- a test fixture count (CWE-190)
	archived, err := json.Marshal(audit.ArchivedEvent{Count: checkpoint.RecordCount, BoundarySeq: checkpoint.BoundarySeq, BoundaryHash: checkpoint.BoundaryHash, ArchiveURI: uri, SourceHistoryRetained: true})
	if err != nil {
		t.Fatal(err)
	}
	id := "audit-archive-" + crypto.SHA256Hex([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s", tenantID, checkpoint.BoundarySeq, checkpoint.BoundaryHash, uri)))
	if _, err := log.Append(ctx, events.Event{ID: id, Type: audit.EventTypeArchived, TenantID: tenantID, SchemaVersion: audit.ArchivedEventSchemaVersion, Data: archived}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuditCheckpoint(ctx, checkpoint); err != nil {
		t.Fatal(err)
	}
	return id
}

// A234 Done-when: a tenant with audit:archive.read downloads its own signed
// segment and verifies it offline; another tenant's events never appear; a
// caller without the permission is refused; every download is audited.
func TestServedTenantDownloadsItsOwnSignedAuditSegments(t *testing.T) {
	ctx := context.Background()
	const tenant, other = "4f1e2d3c-5b6a-4978-8c9d-0e1f2a3b4c5d", "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, id := range []string{tenant, other} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: id, Name: "archive " + id[:4]}); err != nil {
			t.Fatal(err)
		}
		registerServerTestTenant(t, st, log, id, "archive "+id[:4])
		if _, err := log.Append(ctx, events.Event{ID: "history-" + id[:4], TenantID: id, Type: "audit.test", Data: []byte(`{"reason":"tenant ` + id[:4] + ` history"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	key, err := jose.GenerateRSASigningKey("archive-download")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: key, AuditArchiveDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	mine := seedTenantAuditSegment(t, log, st, key, srv.audit, tenant, dir)
	theirs := seedTenantAuditSegment(t, log, st, key, srv.audit, other, dir)
	allowed := seedServedAPIToken(t, ctx, st, tenant, "archive-reader@example.invalid", []string{string(authz.AuditArchiveRead)})
	plain := seedServedAPIToken(t, ctx, st, tenant, "audit-reader@example.invalid", []string{string(authz.AuditRead)})
	call := func(path, token string) (int, []byte, http.Header) {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, request)
		return response.Code, response.Body.Bytes(), response.Header()
	}
	downloads := func() int {
		head, err := log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		if err := log.ReplayTenantMetadataTypesThrough(ctx, tenant, 1, head, []string{audit.EventTypeArchiveDownloaded}, func(events.EnvelopeMetadata) error { n++; return nil }); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if code, _, _ := call("/api/v1/audit/archives", plain); code != http.StatusForbidden {
		t.Fatalf("list without audit:archive.read = %d; want 403", code)
	}
	if code, _, _ := call("/api/v1/audit/archives/"+mine, plain); code != http.StatusForbidden || downloads() != 0 {
		t.Fatalf("download without the permission = %d (downloads %d); want 403 and none", code, downloads())
	}
	code, body, _ := call("/api/v1/audit/archives", allowed)
	if code != http.StatusOK || !strings.Contains(string(body), mine) || strings.Contains(string(body), theirs) || strings.Contains(string(body), dir) {
		t.Fatalf("list = %d %s; want only this tenant's segment and no locator", code, body)
	}
	code, body, _ = call("/api/v1/audit/archives/"+mine, allowed)
	var release struct {
		SegmentID string `json:"segment_id"`
		Bundle    string `json:"bundle"`
		SHA256    string `json:"sha256"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &release) != nil || release.SegmentID != mine || strings.Contains(string(body), dir) {
		t.Fatalf("download = %d %s", code, body)
	}
	verified, err := audit.VerifyRetentionBundle(release.Bundle, key.JWKS())
	if err != nil || verified.TenantID != tenant || crypto.SHA256Hex([]byte(release.Bundle)) != release.SHA256 {
		t.Fatalf("downloaded segment does not verify offline: %v", err)
	}
	for _, record := range verified.Records {
		if record.TenantID != tenant || strings.Contains(string(record.Data), other[:4]) {
			t.Fatalf("downloaded segment carries another tenant's record: %+v", record)
		}
	}
	if downloads() != 1 {
		t.Fatalf("download audit events = %d; want exactly one", downloads())
	}
	for _, probe := range []string{theirs, "audit-archive-..%2F..%2Fetc", "audit-archive-" + strings.Repeat("0", 64)} {
		if code, _, _ := call("/api/v1/audit/archives/"+probe, allowed); code != http.StatusNotFound {
			t.Fatalf("segment %q through this tenant = %d; want 404", probe, code)
		}
	}
	// Tampered stored bytes are refused and nothing is released or audited.
	stored := filepath.Join(dir, tenant)
	entries, err := os.ReadDir(stored)
	if err != nil || len(entries) != 1 {
		t.Fatal(err)
	}
	path := filepath.Join(stored, entries[0].Name())
	raw, err := os.ReadFile(path) // #nosec G304 -- the test's own archive (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-5] ^= 0x01
	if err := os.WriteFile(path, tampered, 0o600); err != nil { // #nosec G703 -- the test's own archive under its t.TempDir (CWE-22)
		t.Fatal(err)
	}
	if code, _, _ := call("/api/v1/audit/archives/"+mine, allowed); code != http.StatusConflict || downloads() != 1 {
		t.Fatalf("tampered segment = %d (downloads %d); want 409 and no new download", code, downloads())
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil { // #nosec G703 -- the test's own archive under its t.TempDir (CWE-22)
		t.Fatal(err)
	}
	// The per-tenant limit sheds with Retry-After once the bucket is empty.
	limited := false
	for i := 0; i < 10 && !limited; i++ {
		code, _, header := call("/api/v1/audit/archives/"+mine, allowed)
		if code == http.StatusTooManyRequests {
			limited = header.Get("Retry-After") != ""
		} else if code != http.StatusOK {
			t.Fatalf("download %d = %d", i, code)
		}
	}
	if !limited {
		t.Fatal("downloads were never rate limited")
	}
}
