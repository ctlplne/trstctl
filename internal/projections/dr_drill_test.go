package projections_test

import (
	"bytes"
	"context"
	"sort"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestBackupRestoreDRDrillReproducesState is the R2.4 disconfirming test for the
// backup/DR blocker (B6): a backup → restore drill reconstructs a control plane
// whose state matches the source. It backs up the event log (the source of
// truth), restores it into a FRESH, empty log, rebuilds the read model purely
// from the restored log (the now-real R1.1 AN-2 rebuild), and asserts the
// recovered inventory matches the original — owners and certificates.
func TestBackupRestoreDRDrillReproducesState(t *testing.T) {
	st := newStore(t)
	srcLog := openLog(t)
	ctx := context.Background()
	tenant := tenantA

	// Seed the source control plane through the real command path.
	orch := orchestrator.NewOrchestrator(srcLog, st, orchestrator.NewOutbox(st))
	o1, err := orch.CreateOwner(ctx, tenant, "workload", "payments", "")
	if err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	if _, err := orch.CreateOwner(ctx, tenant, "workload", "billing", ""); err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	owner := o1.ID
	na := time.Now().Add(24 * time.Hour)
	if _, err := orch.RecordCertificate(ctx, tenant, store.Certificate{
		OwnerID: &owner, Subject: "CN=payments.svc", Serial: "01", Fingerprint: "aa01",
		KeyAlgorithm: "ECDSA-P256", NotAfter: &na, Source: "issued",
	}); err != nil {
		t.Fatalf("RecordCertificate: %v", err)
	}
	if _, err := orch.RecordCertificate(ctx, tenant, store.Certificate{
		Subject: "CN=billing.svc", Serial: "02", Fingerprint: "bb02",
		KeyAlgorithm: "ECDSA-P256", NotAfter: &na, Source: "discovered",
	}); err != nil {
		t.Fatalf("RecordCertificate: %v", err)
	}

	// Snapshot the source read model.
	srcOwners := ownerNames(t, st, tenant)
	srcCerts := certFingerprints(t, st, tenant)
	if len(srcOwners) == 0 || len(srcCerts) == 0 {
		t.Fatal("the drill seeded no state")
	}

	// Back up the event log.
	var buf bytes.Buffer
	if _, err := backup.WriteLog(ctx, srcLog, &buf); err != nil {
		t.Fatalf("WriteLog: %v", err)
	}

	// Restore into a fresh, empty log (simulating a new datastore after a disaster).
	restoredLog := openLog(t)
	if _, err := backup.RestoreLog(ctx, restoredLog, &buf); err != nil {
		t.Fatalf("RestoreLog: %v", err)
	}

	// Rebuild the read model purely from the restored log (AN-2 / R1.1).
	if err := projections.New(st).Rebuild(ctx, restoredLog); err != nil {
		t.Fatalf("Rebuild from restored log: %v", err)
	}

	// The recovered state matches the source.
	if got := ownerNames(t, st, tenant); !sameStrings(got, srcOwners) {
		t.Errorf("owners after restore = %v, want %v", got, srcOwners)
	}
	if got := certFingerprints(t, st, tenant); !sameStrings(got, srcCerts) {
		t.Errorf("certificates after restore = %v, want %v", got, srcCerts)
	}
}

func ownerNames(t *testing.T, st *store.Store, tenant string) []string {
	t.Helper()
	owners, err := st.ListOwners(context.Background(), tenant)
	if err != nil {
		t.Fatalf("ListOwners: %v", err)
	}
	names := make([]string, 0, len(owners))
	for _, o := range owners {
		names = append(names, o.Name)
	}
	sort.Strings(names)
	return names
}

func certFingerprints(t *testing.T, st *store.Store, tenant string) []string {
	t.Helper()
	certs, err := st.ListCertificatesPage(context.Background(), tenant, store.ZeroUUID, nil, 1000, nil)
	if err != nil {
		t.Fatalf("ListCertificatesPage: %v", err)
	}
	fps := make([]string, 0, len(certs))
	for _, c := range certs {
		fps = append(fps, c.Fingerprint)
	}
	sort.Strings(fps)
	return fps
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
