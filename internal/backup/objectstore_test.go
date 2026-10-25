// SPDX-License-Identifier: BUSL-1.1

package backup_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// writeSet builds a small finished full backup set: a file artifact, a
// directory artifact, and the manifest that hashes both.
func writeSet(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "files", "signer-keystore"), 0o700); err != nil {
		t.Fatal(err)
	}
	for rel, data := range map[string]string{
		"events.jsonl":                    "{\"seq\":1}\n{\"seq\":2}\n",
		"files/signer-keystore/key-1.bin": "sealed-key-one",
		"files/signer-keystore/key-2.bin": "sealed-key-two",
	} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	eventsSum, eventsBytes, err := backup.HashFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	treeSum, treeBytes, err := backup.HashTree(filepath.Join(dir, "files", "signer-keystore"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := backup.NewFullManifest([]backup.Artifact{
		{Name: "event-log", Role: "event-log", Path: "events.jsonl", SHA256: eventsSum, Bytes: eventsBytes, Exists: true, Captured: true, Required: true},
		{Name: "signer-keystore", Role: "signer-keystore", Path: "files/signer-keystore", SHA256: treeSum, Bytes: treeBytes, Exists: true, Captured: true, Required: true, Sensitive: true},
	})
	if err := backup.WriteFullManifest(filepath.Join(dir, backup.FullManifestName), manifest); err != nil {
		t.Fatal(err)
	}
}

// A finished set uploads as backups/<directory name>/ with its manifest last;
// downloaded into a new directory it re-hashes clean against that manifest. A
// complete set is never uploaded again under the same name.
func TestFullBackupSetRoundTripsThroughTheObjectStore(t *testing.T) {
	srv := s3test.NewServer(t)
	store := srv.Open(t, func(o *objectstore.Options) { o.Prefix = "site-a" })
	dir := filepath.Join(t.TempDir(), "nightly-2026-10-25")
	writeSet(t, dir)
	set, err := backup.UploadFullBackup(t.Context(), store, dir)
	if err != nil {
		t.Fatal(err)
	}
	if set.Name != "nightly-2026-10-25" || set.Objects != 4 || set.Location != "s3://"+srv.Bucket+"/site-a/backups/nightly-2026-10-25/" {
		t.Fatalf("uploaded set = %+v", set)
	}
	var puts []string
	for _, request := range srv.Requests() {
		if strings.HasPrefix(request, "PUT ") {
			puts = append(puts, strings.TrimPrefix(request, "PUT site-a/backups/nightly-2026-10-25/"))
		}
	}
	if len(puts) != 4 || puts[len(puts)-1] != backup.FullManifestName {
		t.Fatalf("upload order = %v, want the manifest last", puts)
	}
	if _, err := backup.UploadFullBackup(t.Context(), store, dir); err == nil || !strings.Contains(err.Error(), "already holds a complete set") {
		t.Fatalf("second upload of a complete set = %v, want a refusal", err)
	}

	restoreDir := filepath.Join(t.TempDir(), "fetched")
	report, err := backup.DownloadFullBackup(t.Context(), store, "nightly-2026-10-25", restoreDir)
	if err != nil || !report.Verified || len(report.Checks) != 2 {
		t.Fatalf("download = %+v %v, want a verified two-artifact set", report, err)
	}
	if got, err := os.ReadFile(filepath.Join(restoreDir, "files", "signer-keystore", "key-2.bin")); err != nil || string(got) != "sealed-key-two" { // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		t.Fatalf("downloaded keystore file = %q %v", got, err)
	}
	if _, err := backup.DownloadFullBackup(t.Context(), store, "nightly-2026-10-25", restoreDir); err == nil {
		t.Fatal("a download overwrote a non-empty directory")
	}
}

// An upload interrupted before its manifest resumes: objects already stored
// with the same bytes are kept, and the set is complete only once the manifest
// lands. A partial set does not download, and a stored object whose bytes
// differ from the local file stops the upload.
func TestInterruptedFullBackupUploadResumesAndPartialSetsDoNotDownload(t *testing.T) {
	srv := s3test.NewServer(t)
	store := srv.Open(t)
	dir := filepath.Join(t.TempDir(), "weekly")
	writeSet(t, dir)
	events, err := os.ReadFile(filepath.Join(dir, "events.jsonl")) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	srv.Seed("backups/weekly/events.jsonl", events)
	if _, err := backup.DownloadFullBackup(t.Context(), store, "weekly", filepath.Join(t.TempDir(), "x")); err == nil || !strings.Contains(err.Error(), "no complete set") {
		t.Fatalf("download of a set without its manifest = %v", err)
	}
	set, err := backup.UploadFullBackup(t.Context(), store, dir)
	if err != nil || set.Resumed != 1 || set.Objects != 4 {
		t.Fatalf("resumed upload = %+v %v", set, err)
	}

	other := filepath.Join(t.TempDir(), "monthly")
	writeSet(t, other)
	srv.Seed("backups/monthly/events.jsonl", []byte("different bytes\n"))
	if _, err := backup.UploadFullBackup(t.Context(), store, other); err == nil || !strings.Contains(err.Error(), "different bytes") {
		t.Fatalf("upload over different stored bytes = %v", err)
	}
	if _, found := srv.Object("backups/monthly/" + backup.FullManifestName); found {
		t.Fatal("a refused upload still published its manifest")
	}
}

// A downloaded set whose stored artifact was altered after upload fails the
// download, because every object is checked against its stored checksum.
func TestDownloadRefusesAnAlteredObject(t *testing.T) {
	srv := s3test.NewServer(t)
	store := srv.Open(t)
	dir := filepath.Join(t.TempDir(), "daily")
	writeSet(t, dir)
	if _, err := backup.UploadFullBackup(t.Context(), store, dir); err != nil {
		t.Fatal(err)
	}
	srv.Replace("backups/daily/events.jsonl", []byte("tampered\n"))
	if _, err := backup.DownloadFullBackup(t.Context(), store, "daily", filepath.Join(t.TempDir(), "fetched")); err == nil {
		t.Fatal("an altered object downloaded")
	}
	for _, bad := range []string{"", "../daily", "a/b", ".hidden"} {
		if _, err := backup.DownloadFullBackup(t.Context(), store, bad, filepath.Join(t.TempDir(), "y")); err == nil {
			t.Fatalf("set name %q was accepted", bad)
		}
	}
}
