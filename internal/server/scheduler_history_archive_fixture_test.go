// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// seedSchedulerHistoryArchive supplies a previously licensed archive/checkpoint
// for the core downgrade/recovery test. It intentionally has no retention policy,
// tenant iteration, retry logic or worker attachment. The real producer is tested
// with PostgreSQL/NATS in ee/auditcompliance/retention_rebuild_test.go.
func seedSchedulerHistoryArchive(t *testing.T, log *events.Log, st *store.Store, key *jose.SigningKey, service *audit.Service, tenantID, dir string, minimumRecords int) {
	t.Helper()
	ctx := context.Background()
	records, seed, err := service.SearchWithSeed(ctx, audit.Query{TenantID: tenantID})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) < minimumRecords {
		t.Fatalf("archive fixture records=%d, want at least %d", len(records), minimumRecords)
	}
	boundary := records[len(records)-1]
	payload, err := json.Marshal(audit.Bundle{TenantID: tenantID, GeneratedAt: time.Now().UTC(), Query: audit.Query{TenantID: tenantID}, Records: records, Count: len(records), PrevHash: seed, ChainHead: boundary.Hash})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := key.SignArtifact(jose.ArtifactAuditRetention, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.VerifyRetentionBundle(signed, service.VerificationKeys()); err != nil {
		t.Fatal(err)
	}
	uri := filepath.Join(dir, "prior-licensed-archive.jws")
	if err := os.WriteFile(uri, []byte(signed), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpoint := audit.Checkpoint{TenantID: tenantID, BoundarySeq: boundary.StreamSequence, BoundaryHash: boundary.Hash, RecordCount: len(records), ArchiveURI: uri}
	archived, err := json.Marshal(audit.ArchivedEvent{Count: checkpoint.RecordCount, BoundarySeq: checkpoint.BoundarySeq, BoundaryHash: checkpoint.BoundaryHash, ArchiveURI: uri, SourceHistoryRetained: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{ID: "prior-licensed-audit-archive", Type: audit.EventTypeArchived, TenantID: tenantID, SchemaVersion: audit.ArchivedEventSchemaVersion, Data: archived}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuditCheckpoint(ctx, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := audit.VerifyCheckpointSourceRetained(ctx, log, checkpoint); err != nil {
		t.Fatal(err)
	}
}
