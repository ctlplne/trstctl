// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/reportarchive"
	"trstctl.com/trstctl/internal/store"
)

const a206Tenant = "a2060000-0000-4000-8000-000000000001"

// seedCompletedReportRun projects a schedule and a completed run that records
// ref and digest, as the report worker leaves them.
func seedCompletedReportRun(t *testing.T, st *store.Store, tenantID, scheduleID, runID string, due time.Time, ref, digest string) {
	t.Helper()
	ctx := context.Background()
	schedule := store.ComplianceReportSchedule{
		ID: scheduleID, TenantID: tenantID, Framework: "soc2", Name: "pack " + scheduleID[len(scheduleID)-4:],
		ReportType: "framework_evidence_pack", IntervalSeconds: 3600, Enabled: true, Delivery: "audit_export",
		NextRunAt: due, CreatedAt: due.Add(-time.Hour), UpdatedAt: due.Add(-time.Hour),
	}
	queued := store.ComplianceReportRun{
		ID: runID, TenantID: tenantID, ScheduleID: scheduleID, DueAt: due, Framework: "soc2",
		ReportType: "framework_evidence_pack", Status: "queued", EventSequence: 1, CreatedAt: due, UpdatedAt: due,
	}
	completed := queued
	completed.Status, completed.Attempt, completed.EventSequence = "completed", 1, 2
	completed.CompletedAt, completed.UpdatedAt = due.Add(time.Minute), due.Add(time.Minute)
	completed.ArtifactRef, completed.ArtifactDigest = ref, digest
	if err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := st.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, schedule); err != nil {
			return err
		}
		if err := st.ApplyComplianceReportRunTx(ctx, tx, queued); err != nil {
			return err
		}
		return st.ApplyComplianceReportRunTx(ctx, tx, completed)
	}); err != nil {
		t.Fatalf("seed report run %s: %v", runID, err)
	}
}

// A206: the full backup carries every completed run's report, encrypted, with
// an index; a run whose report was already gone is recorded, not fatal. A full
// restore puts each report back where its run's reference says (the archive
// directory or the object store) and the isolated drill into its own directory;
// every restored report reads back against its digest.
func TestFullBackupCarriesAndRestoresComplianceReports(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	dir := t.TempDir()
	source := reportarchive.Archive{Dir: reportarchive.Dir{Root: filepath.Join(dir, "source-archive")}}
	if err := os.MkdirAll(source.Dir.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	objects := newA206ObjectStore()
	source.Objects = objects
	due := time.Now().UTC().Truncate(time.Hour).Add(-48 * time.Hour)

	onDisk := []byte(`{"signed_export":{"report":"on disk","signature":"AQ=="}}`)
	diskRef, diskDigest, err := source.Dir.Put(a206Tenant, "a2060000-0000-4000-8000-0000000000a1", onDisk)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedReportRun(t, st, a206Tenant, "a2060000-0000-4000-8000-0000000000b1", "a2060000-0000-4000-8000-0000000000a1", due, diskRef, diskDigest)

	inObjects := []byte(`{"signed_export":{"report":"in the object store","signature":"Ag=="}}`)
	objectRef, objectDigest, err := source.Put(ctx, a206Tenant, "a2060000-0000-4000-8000-0000000000a2", inObjects)
	if err != nil {
		t.Fatal(err)
	}
	if reportarchive.IsDirectoryReference(objectRef) {
		t.Fatalf("object store reference %s", objectRef)
	}
	seedCompletedReportRun(t, st, a206Tenant, "a2060000-0000-4000-8000-0000000000b2", "a2060000-0000-4000-8000-0000000000a2", due.Add(time.Hour), objectRef, objectDigest)

	gone := crypto.SHA256Hex([]byte(`{"deleted":true}`))
	goneRef, err := reportarchive.Reference(a206Tenant, "a2060000-0000-4000-8000-0000000000a3", gone)
	if err != nil {
		t.Fatal(err)
	}
	seedCompletedReportRun(t, st, a206Tenant, "a2060000-0000-4000-8000-0000000000b3", "a2060000-0000-4000-8000-0000000000a3", due.Add(2*time.Hour), goneRef, gone)

	key := []byte("0123456789abcdef0123456789abcdef")
	defer secret.Wipe(key)
	keyID, err := backup.BackupArtifactKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")
	artifact, err := captureFullBackupReports(ctx, st, source, backupDir, &fullBackupEncryption{key: key, keyID: keyID})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if !artifact.Captured || !artifact.Required || !artifact.Sensitive || artifact.Encryption == nil || !strings.HasSuffix(artifact.Path, ".enc") {
		t.Fatalf("report artifact = %+v", artifact)
	}
	for _, plaintext := range [][]byte{onDisk, inObjects} {
		if leaked, err := treeContainsBytes(backupDir, plaintext); err != nil || leaked {
			t.Fatalf("the backup holds report plaintext: %v %v", leaked, err)
		}
	}
	if err := verifyStoredDirArtifact(artifact, reportArchiveArtifactName, filepath.Join(backupDir, filepath.FromSlash(artifact.Path))); err != nil {
		t.Fatalf("verify the stored artifact: %v", err)
	}
	manifest := backup.NewFullManifest([]backup.Artifact{artifact})

	// A full restore into a fresh deployment's archive directory and store.
	target := reportarchive.Archive{Dir: reportarchive.Dir{Root: filepath.Join(dir, "restored-archive")}, Objects: newA206ObjectStore()}
	got, err := restoreFullBackupReports(ctx, manifest, backupDir, target, key, false)
	if err != nil || got.Restored != 2 || got.MissingAtBackup != 1 {
		t.Fatalf("restore = %+v %v", got, err)
	}
	for _, c := range []struct {
		ref, runID, digest string
		want               []byte
	}{
		{diskRef, "a2060000-0000-4000-8000-0000000000a1", diskDigest, onDisk},
		{objectRef, "a2060000-0000-4000-8000-0000000000a2", objectDigest, inObjects},
	} {
		data, err := target.Read(ctx, c.ref, a206Tenant, c.runID, c.digest)
		if err != nil || !bytes.Equal(data, c.want) {
			t.Fatalf("restored %s = %q %v", c.ref, data, err)
		}
	}
	// Restoring again over what is there converges.
	if again, err := restoreFullBackupReports(ctx, manifest, backupDir, target, key, false); err != nil || again.Restored != 2 {
		t.Fatalf("second restore = %+v %v", again, err)
	}

	// The isolated drill restores every report into its own directory and
	// never touches an object store.
	isolated := reportarchive.Archive{Dir: reportarchive.Dir{Root: filepath.Join(dir, "drill-archive")}}
	drilled, err := restoreFullBackupReports(ctx, manifest, backupDir, isolated, key, true)
	if err != nil || drilled.Restored != 2 || drilled.MissingAtBackup != 1 {
		t.Fatalf("isolated restore = %+v %v", drilled, err)
	}
	if data, err := isolated.Dir.Read(a206Tenant, "a2060000-0000-4000-8000-0000000000a2", objectDigest); err != nil || !bytes.Equal(data, inObjects) {
		t.Fatalf("drill copy of the object-store report = %q %v", data, err)
	}

	// A restore target without the object store refuses rather than dropping
	// the report.
	noObjects := reportarchive.Archive{Dir: reportarchive.Dir{Root: filepath.Join(dir, "no-objects")}}
	if _, err := restoreFullBackupReports(ctx, manifest, backupDir, noObjects, key, false); err == nil || !strings.Contains(err.Error(), "object store") {
		t.Fatalf("restore without the object store = %v", err)
	}
	// The wrong backup key cannot open the artifact.
	if _, err := restoreFullBackupReports(ctx, manifest, backupDir, target, []byte("fedcba9876543210fedcba9876543210"), false); err == nil {
		t.Fatal("the wrong key restored the reports")
	}
}

// A deployment with no completed report runs records no report artifact.
func TestFullBackupWithoutReportsRecordsNoArtifact(t *testing.T) {
	st := newServerTestStore(t)
	artifact, err := captureFullBackupReports(context.Background(), st, reportarchive.Archive{}, t.TempDir(), nil)
	if err != nil || artifact.Captured || artifact.Required {
		t.Fatalf("artifact = %+v %v", artifact, err)
	}
}

// a206ObjectStore is an in-memory archive object store.
type a206ObjectStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newA206ObjectStore() *a206ObjectStore { return &a206ObjectStore{objects: map[string][]byte{}} }

func (s *a206ObjectStore) Create(_ context.Context, name string, body io.ReadSeeker, size int64, sum []byte) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(data)) != size || !bytes.Equal(crypto.SHA256Sum(data), sum) {
		return errors.New("digest mismatch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[name]; ok {
		return objectstore.ErrExists
	}
	s.objects[name] = data
	return nil
}

func (s *a206ObjectStore) Get(_ context.Context, name string, w io.Writer, limit int64) (objectstore.Object, error) {
	s.mu.Lock()
	data, ok := s.objects[name]
	s.mu.Unlock()
	if !ok {
		return objectstore.Object{}, objectstore.ErrNotFound
	}
	if int64(len(data)) > limit {
		return objectstore.Object{}, objectstore.ErrTooLarge
	}
	_, err := w.Write(data)
	return objectstore.Object{Name: name, Size: int64(len(data)), SHA256: crypto.SHA256Hex(data)}, err
}

func (s *a206ObjectStore) Head(_ context.Context, name string) (objectstore.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[name]
	if !ok {
		return objectstore.Object{}, objectstore.ErrNotFound
	}
	return objectstore.Object{Name: name, Size: int64(len(data)), SHA256: crypto.SHA256Hex(data)}, nil
}

func (s *a206ObjectStore) List(_ context.Context, prefix string, limit int) ([]objectstore.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []objectstore.Object
	for name, data := range s.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, objectstore.Object{Name: name, Size: int64(len(data)), SHA256: crypto.SHA256Hex(data)})
		}
	}
	if len(out) > limit {
		return nil, errors.New("too many objects")
	}
	return out, nil
}

func (s *a206ObjectStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, name)
	return nil
}

func (s *a206ObjectStore) Location(name string) string { return "mem://" + name }

func (s *a206ObjectStore) NameOf(location string) (string, error) {
	return strings.TrimPrefix(location, "mem://"), nil
}
