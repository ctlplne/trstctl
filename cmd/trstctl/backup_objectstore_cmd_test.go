// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// A97 (owner 2026-10-24): a finished full backup set uploads to the
// configured object store with --full-backup-upload, and --full-backup-download
// fetches it into a new directory and re-hashes every artifact against its
// manifest, ready for --full-restore-dir. Neither command starts the control
// plane.
func TestFullBackupSetUploadsAndDownloadsThroughTheObjectStore(t *testing.T) {
	srv := s3test.NewServer(t)
	secretPath := filepath.Join(t.TempDir(), "s3-secret")
	if err := os.WriteFile(secretPath, srv.Secret, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"TRSTCTL_OBJECT_STORE_ENDPOINT": srv.URL, "TRSTCTL_OBJECT_STORE_BUCKET": srv.Bucket,
		"TRSTCTL_OBJECT_STORE_PATH_STYLE": "true", "TRSTCTL_OBJECT_STORE_ALLOW_INSECURE_LOOPBACK": "true",
		"TRSTCTL_OBJECT_STORE_ACCESS_KEY_ID": srv.AccessKeyID, "TRSTCTL_OBJECT_STORE_SECRET_ACCESS_KEY_FILE": secretPath,
	}
	getenv := func(k string) string { return env[k] }

	set := filepath.Join(t.TempDir(), "nightly-1")
	if err := os.MkdirAll(set, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(set, "events.jsonl"), []byte("{\"seq\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, size, err := backup.HashFile(filepath.Join(set, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.WriteFullManifest(filepath.Join(set, backup.FullManifestName), backup.NewFullManifest([]backup.Artifact{
		{Name: "event-log", Role: "event-log", Path: "events.jsonl", SHA256: sum, Bytes: size, Exists: true, Captured: true, Required: true},
	})); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := run(context.Background(), []string{"--full-backup-upload", set}, getenv, &out, io.Discard); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !strings.Contains(out.String(), "uploaded 2 objects") || !strings.Contains(out.String(), "s3://"+srv.Bucket+"/backups/nightly-1/") {
		t.Fatalf("upload output = %q", out.String())
	}
	fetched := filepath.Join(t.TempDir(), "fetched")
	out.Reset()
	if err := run(context.Background(), []string{"--full-backup-download", "nightly-1", "--full-backup-download-dir", fetched}, getenv, &out, io.Discard); err != nil {
		t.Fatalf("download: %v", err)
	}
	if !strings.Contains(out.String(), "1 artifacts re-hashed against its manifest") {
		t.Fatalf("download output = %q", out.String())
	}
	if report, err := backup.VerifyFullBackup(fetched); err != nil || !report.Verified {
		t.Fatalf("the fetched set = %+v %v", report, err)
	}
	if err := run(context.Background(), []string{"--full-backup-download", "nightly-1"}, getenv, io.Discard, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "--full-backup-download-dir") {
		t.Fatalf("download without a directory = %v", err)
	}
	if err := run(context.Background(), []string{"--full-backup-upload", set}, emptyEnv, io.Discard, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "no object store is configured") {
		t.Fatalf("upload with no object store = %v", err)
	}
}
