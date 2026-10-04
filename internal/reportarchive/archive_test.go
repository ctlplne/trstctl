// SPDX-License-Identifier: BUSL-1.1

package reportarchive_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/reportarchive"
)

func TestArchiveRetainsExactSignedBytesAndRefusesTamper(t *testing.T) {
	root := filepath.Join(t.TempDir(), "archive")
	archive := reportarchive.Dir{Root: root}
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const runID = "22222222-2222-4222-8222-222222222222"
	artifact := []byte(` {"signed_export":{"signature":"AQ=="},"public_key_der":"AQ=="} `)
	ref, digest, err := archive.Put(tenantID, runID, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if ref != "reports/"+tenantID+"/"+runID+"-"+digest+".json" {
		t.Fatalf("unexpected archive ref %s", ref)
	}
	got, err := archive.Read(tenantID, runID, digest)
	if err != nil || !bytes.Equal(got, artifact) {
		t.Fatalf("read exact signed bytes: %s, %v", got, err)
	}
	if _, _, err := archive.Put(tenantID, runID, artifact); err != nil {
		t.Fatalf("idempotent write: %v", err)
	}
	if _, err := archive.Read("33333333-3333-4333-8333-333333333333", runID, digest); err == nil {
		t.Fatal("another tenant read the report")
	}
	path := filepath.Join(root, ref)
	if err := os.WriteFile(path, []byte(`{"signed_export":"altered"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Read(tenantID, runID, digest); err == nil {
		t.Fatal("tampered report passed readback")
	}
	if _, _, err := archive.Put(tenantID, runID, artifact); err == nil {
		t.Fatal("idempotent write replaced a tampered artifact")
	}
}

func TestArchiveRejectsUnsafeIdentityAndPath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "archive")
	archive := reportarchive.Dir{Root: root}
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const runID = "22222222-2222-4222-8222-222222222222"
	if _, _, err := archive.Put("../escape", runID, []byte(`{}`)); err == nil {
		t.Fatal("path traversal tenant accepted")
	}
	if _, _, err := archive.Put(tenantID, "../escape", []byte(`{}`)); err == nil {
		t.Fatal("path traversal run accepted")
	}
	if _, _, err := archive.Put(tenantID, runID, []byte(`broken`)); err == nil {
		t.Fatal("invalid signed JSON accepted")
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "reports")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := archive.Put(tenantID, runID, []byte(`{}`)); err == nil {
		t.Fatal("symlink reports directory accepted")
	}
}
