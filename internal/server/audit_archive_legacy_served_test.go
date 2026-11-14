// SPDX-License-Identifier: BUSL-1.1

package server

import (
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
	"trstctl.com/trstctl/internal/store"
)

// A234-L2 Done-when: a tenant whose oldest records went into a legacy
// audit.archived v1 segment (segment-local counts) lists its first v2 segment
// with the record it really starts at, read from that segment's own verified
// bundle, not 0.
func TestServedFirstSegmentAfterALegacyArchiveListsItsFirstRecordA234L2(t *testing.T) {
	ctx := context.Background()
	const tenant = "7c1e2d3c-5b6a-4978-8c9d-0e1f2a3b4c71"
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "legacy archive"}); err != nil {
		t.Fatal(err)
	}
	registerServerTestTenant(t, st, log, tenant, "legacy archive")
	for _, id := range []string{"legacy-history-1", "legacy-history-2", "legacy-history-3"} {
		if _, err := log.Append(ctx, events.Event{ID: id, TenantID: tenant, Type: "audit.test", Data: []byte(`{"reason":"` + id + `"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: key, AuditArchiveDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// The legacy archive retired the first two records: a v1 event with its
	// segment-local count, and the checkpoint at the second record.
	records, _, err := srv.audit.SearchWithSeed(ctx, audit.Query{TenantID: tenant})
	if err != nil || len(records) < 4 {
		t.Fatalf("records = %d %v; want at least 4", len(records), err)
	}
	legacyEnd := records[1]
	if err := st.SaveAuditCheckpoint(ctx, audit.Checkpoint{TenantID: tenant, BoundarySeq: legacyEnd.StreamSequence, BoundaryHash: legacyEnd.Hash,
		RecordCount: 2, ArchiveURI: "legacy-v1-segment"}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{ID: "legacy-v1-archive", TenantID: tenant, Type: audit.EventTypeArchived, SchemaVersion: 1,
		Data: []byte(`{"count":2,"boundary_sequence":2,"boundary_hash":"` + legacyEnd.Hash + `","archive_uri":"legacy-v1-segment"}`)}); err != nil {
		t.Fatal(err)
	}
	segment := seedTenantAuditSegment(t, log, st, key, srv.audit, tenant, dir)

	token := seedServedAPIToken(t, ctx, st, tenant, "archive-reader-a234l2@example.invalid", []string{string(authz.AuditArchiveRead)})
	call := func(path string) (int, []byte) {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, request)
		return response.Code, response.Body.Bytes()
	}
	code, body := call("/api/v1/audit/archives/" + segment)
	var release struct {
		FirstRecord int `json:"first_record"`
		LastRecord  int `json:"last_record"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &release) != nil || release.FirstRecord != 3 {
		t.Fatalf("download = %d %s; want the bundle to start at record 3", code, body)
	}
	code, body = call("/api/v1/audit/archives")
	var list struct {
		Items []struct {
			ID          string `json:"id"`
			FirstRecord int    `json:"first_record"`
			LastRecord  int    `json:"last_record"`
		} `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 1 || list.Items[0].ID != segment {
		t.Fatalf("list = %d %s", code, body)
	}
	if got := list.Items[0]; got.FirstRecord != release.FirstRecord || got.LastRecord != release.LastRecord {
		t.Fatalf("the list says records %d–%d; the segment's own bundle holds %d–%d", got.FirstRecord, got.LastRecord, release.FirstRecord, release.LastRecord)
	}
	t.Logf("A234L2_OK segment=%s records=%d-%d", segment, list.Items[0].FirstRecord, list.Items[0].LastRecord)
}
