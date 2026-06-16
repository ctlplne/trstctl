package projections_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
)

// TestAssembledServerEnforcesAuditRetention is R4.4's wired-into-the-binary
// acceptance: server.Build with AuditRetention + AuditArchiveDir set constructs the
// retention worker; driving it through the assembled server archives audit records
// older than the window to a signed bundle, seals a checkpoint in the REAL store,
// prunes the records from the hot log, keeps the chain verifiable across the
// checkpoint, and exposes the run on /metrics.
func TestAssembledServerEnforcesAuditRetention(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	ctx := context.Background()

	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	archiveDir := t.TempDir()

	// Assemble the control plane with retention enabled. No signer (issuance is
	// unavailable, fine) — we are exercising the audit lifecycle, not issuance.
	asm, err := server.Build(ctx, server.Deps{
		Store: st, Log: log, AuditSigningKey: auditKey,
		AuditRetention: 24 * time.Hour, AuditArchiveDir: archiveDir,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	// Seed three records past the window and two within it (after Build's projection
	// catch-up, so these synthetic events never reach a projector).
	const tenant = "33333333-3333-3333-3333-333333333333"
	oldT := time.Now().Add(-72 * time.Hour)
	recentT := time.Now().Add(-1 * time.Minute)
	const nOld, nRecent = 3, 2
	for i := 0; i < nOld; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "thing.created", TenantID: tenant,
			Time: oldT.Add(time.Duration(i) * time.Second), Data: []byte(fmt.Sprintf(`{"old":%d}`, i))}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < nRecent; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "thing.created", TenantID: tenant,
			Time: recentT.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}

	// Drive one retention cycle through the ASSEMBLED server (proves the worker is
	// wired into Build, not just constructable in isolation).
	sum, err := asm.RunRetentionOnce(ctx)
	if err != nil {
		t.Fatalf("RunRetentionOnce: %v", err)
	}
	if sum.RecordsArchived != nOld || sum.RecordsPruned != nOld {
		t.Fatalf("summary = %+v, want archived/pruned=%d", sum, nOld)
	}

	// The checkpoint is sealed in the REAL store (AN-1 tenant-scoped).
	cp, ok, err := st.LatestAuditCheckpoint(ctx, tenant)
	if err != nil || !ok {
		t.Fatalf("store checkpoint not sealed: ok=%v err=%v", ok, err)
	}
	if cp.RecordCount != nOld || cp.BoundaryHash == "" || cp.ArchiveURI == "" {
		t.Fatalf("store checkpoint = %+v, want count=%d with boundary hash + archive uri", cp, nOld)
	}

	// The archive bundle exists and recovers + verifies.
	matches, _ := filepath.Glob(filepath.Join(archiveDir, tenant, "*.jws"))
	if len(matches) != 1 {
		t.Fatalf("archive files = %v, want exactly 1", matches)
	}

	// The chain still verifies across the checkpoint via the same store as the
	// checkpoint source (the survivors anchor on the sealed boundary).
	svc := audit.NewService(log, auditKey, audit.WithCheckpoints(st))
	if _, err := svc.VerifyChain(ctx, tenant); err != nil {
		t.Fatalf("VerifyChain across the store checkpoint failed: %v", err)
	}
	post, err := svc.Search(ctx, audit.Query{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	// 2 recent survivors + the worker's own audit.archived event.
	if len(post) != nRecent+1 {
		t.Errorf("post-prune live records = %d, want %d", len(post), nRecent+1)
	}

	// The run is observable on /metrics.
	body := scrape(t, ts, "/metrics")
	for _, want := range []string{
		"trstctl_audit_records_archived_total 3",
		"trstctl_audit_records_pruned_total 3",
		"trstctl_audit_retention_runs_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}

func scrape(t *testing.T, ts *httptest.Server, path string) string {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", path, resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
