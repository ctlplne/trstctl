// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/auditcompliance"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditarchive"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A234 against the real producer: segments the licensed retention worker
// archives are readable by the core tenant reader only for their own tenant,
// verify as signed retention segments, and refuse once tampered.
func TestCoreReaderServesTheRetentionWorkersSegmentsPerTenant(t *testing.T) {
	ctx := context.Background()
	st := newAuditTestStore(t)
	log := openTestLog(t)
	const other = "22222222-2222-2222-2222-222222222222"
	old := time.Now().Add(-48 * time.Hour)
	for i, tenant := range []string{tenantA, other} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Time: old, Data: tenantRegistered("archive tenant")}); err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{Type: projections.EventOwnerCreated, TenantID: tenant, Time: old.Add(time.Second),
			Data: ownerCreated([]string{"00000000-0000-0000-0000-0000000000a1", "00000000-0000-0000-0000-0000000000b1"}[i], "archived-owner")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := projections.New(st).Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	service := audit.NewService(log, key, audit.WithCheckpoints(st))
	dir := t.TempDir()
	if _, err := auditcompliance.NewRetentionWorker(service, log, auditcompliance.DirArchiver{Dir: dir}, st, time.Hour, key).RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	reader := auditarchive.Reader{Log: log, Keys: service.VerificationKeys, Dir: dir}
	mine, err := reader.List(ctx, tenantA)
	if err != nil || len(mine) != 1 || mine[0].FirstRecord != 1 || mine[0].LastRecord < 2 {
		t.Fatalf("tenant segments = %+v %v; want one segment from record 1", mine, err)
	}
	theirs, err := reader.List(ctx, other)
	if err != nil || len(theirs) != 1 || theirs[0].ID == mine[0].ID {
		t.Fatalf("other tenant segments = %+v %v", theirs, err)
	}
	release, err := reader.Read(ctx, tenantA, mine[0].ID)
	if err != nil {
		t.Fatalf("read own segment: %v", err)
	}
	verified, err := audit.VerifyRetentionBundle(release.Signed, service.VerificationKeys())
	if err != nil || verified.TenantID != tenantA {
		t.Fatalf("released segment does not verify offline for its tenant: %v", err)
	}
	for _, record := range verified.Records {
		if record.TenantID != tenantA {
			t.Fatalf("released segment holds a record of tenant %s", record.TenantID)
		}
	}
	if _, err := reader.Read(ctx, tenantA, theirs[0].ID); !errors.Is(err, auditarchive.ErrNotFound) {
		t.Fatalf("another tenant's segment through this tenant = %v; want not found", err)
	}
	path := filepath.Join(dir, tenantA)
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 {
		t.Fatalf("archive layout: %v", err)
	}
	stored := filepath.Join(path, entries[0].Name())
	raw, err := os.ReadFile(stored) // #nosec G304 -- the test's own archive (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-5] ^= 0x01
	if err := os.WriteFile(stored, raw, 0o600); err != nil { // #nosec G703 -- the test's own archive under its t.TempDir (CWE-22)
		t.Fatal(err)
	}
	if _, err := reader.Read(ctx, tenantA, mine[0].ID); !errors.Is(err, auditarchive.ErrUnavailable) {
		t.Fatalf("tampered segment = %v; want unavailable", err)
	}
}
