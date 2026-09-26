// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCoreAuditExportsExplainUnlicensedAnchoring(t *testing.T) {
	ts, token, _ := newAuditExportHarness(t)
	for _, format := range auditanchor.Formats() {
		t.Run(string(format), func(t *testing.T) {
			code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?format="+string(format), token, "", nil)
			if code != http.StatusOK {
				t.Fatalf("core history export %s: status=%d body=%s", format, code, body)
			}
			if !bytes.Contains(body, []byte("anchoring requires an Enterprise licence")) {
				t.Fatalf("core export %s does not explain the edition boundary: %s", format, body)
			}
			if bytes.Contains(body, []byte("timestamp authority did not answer")) || bytes.Contains(body, []byte("rfc3161")) {
				t.Fatalf("unlicensed export %s incorrectly claims an attempted or successful timestamp", format)
			}
		})
	}
}

func TestCoreAuditRetentionConfigurationDoesNotArchiveHistory(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-4111-8111-111111111116"
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "core audit retention"}); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	registerServerTestTenant(t, st, log, tenantID, "core audit retention")
	key, err := jose.GenerateRSASigningKey("core-retention")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: "retained-core-history", TenantID: tenantID, Type: "audit.test",
		Time: time.Now().Add(-48 * time.Hour), Data: []byte(`{"reason":"history remains exportable"}`),
	}); err != nil {
		t.Fatal(err)
	}
	archiveDir := t.TempDir()
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: key, AuditRetention: time.Hour, AuditArchiveDir: archiveDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	summary, err := srv.RunRetentionOnce(ctx)
	if err != nil || summary.RecordsArchived != 0 {
		t.Fatalf("core assembly ran commercial retention: summary=%+v err=%v", summary, err)
	}
	if _, exists, err := st.LatestAuditCheckpoint(ctx, tenantID); err != nil || exists {
		t.Fatalf("core assembly advanced the history floor: exists=%v err=%v", exists, err)
	}
	entries, err := os.ReadDir(archiveDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("core assembly wrote archive files: entries=%d err=%v", len(entries), err)
	}
	signed, err := srv.audit.Export(ctx, audit.Query{TenantID: tenantID})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := audit.VerifyBundle(signed, key.JWKS())
	if err != nil || bundle.Count != 2 || len(bundle.Records) != 2 {
		t.Fatalf("ordinary signed history is unavailable: count=%d err=%v", bundle.Count, err)
	}
	var registrationRetained, historyRetained bool
	for _, record := range bundle.Records {
		registrationRetained = registrationRetained || record.Type == projections.EventTenantRegistered
		historyRetained = historyRetained || record.ID == "retained-core-history"
	}
	if !registrationRetained || !historyRetained {
		t.Fatal("core signed export lost registration or retained history")
	}
}
