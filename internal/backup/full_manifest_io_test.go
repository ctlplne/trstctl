// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestFullManifestHashAndCopyHelpers(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(filepath.Join(src, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	aPath := filepath.Join(src, "a.txt")
	bPath := filepath.Join(src, "nested", "b.txt")
	if err := os.WriteFile(aPath, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bPath, []byte("defg"), 0o640); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}

	sum, n, err := HashFile(aPath)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if sum == "" || n != 3 {
		t.Fatalf("HashFile = %q/%d, want non-empty/3", sum, n)
	}
	treeSum, treeBytes, err := HashTree(src)
	if err != nil {
		t.Fatalf("HashTree: %v", err)
	}
	if treeSum == "" || treeBytes != 7 {
		t.Fatalf("HashTree = %q/%d, want non-empty/7", treeSum, treeBytes)
	}

	dstFile := filepath.Join(root, "copy", "a.txt")
	if err := CopyFile(aPath, dstFile, 0o600); err != nil {
		t.Fatalf("CopyFile: %v", err)
	}
	if data, err := os.ReadFile(dstFile); err != nil || string(data) != "abc" { // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		t.Fatalf("copied file = %q, %v", data, err)
	}
	dstTree := filepath.Join(root, "tree-copy")
	if err := CopyTree(src, dstTree); err != nil {
		t.Fatalf("CopyTree: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dstTree, "nested", "b.txt")); err != nil || string(data) != "defg" { // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		t.Fatalf("copied tree file = %q, %v", data, err)
	}
}

func TestWriteReadFullManifestSortsAndValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), FullManifestName)
	manifest := NewFullManifest([]Artifact{
		{Name: "z-event-log", Role: "event-log", Exists: true, Captured: true},
		{Name: "a-postgres", Role: "postgres-state", Exists: true, Captured: true},
	})
	manifest.RecoveryClasses["custom"] = []string{"z", "a"}
	if err := WriteFullManifest(path, manifest); err != nil {
		t.Fatalf("WriteFullManifest: %v", err)
	}
	got, err := ReadFullManifest(path)
	if err != nil {
		t.Fatalf("ReadFullManifest: %v", err)
	}
	if got.Format != fullFormatTag || got.Version != fullVersion {
		t.Fatalf("manifest identity = %q/%d", got.Format, got.Version)
	}
	if got.Artifacts[0].Name != "a-postgres" || got.Artifacts[1].Name != "z-event-log" {
		t.Fatalf("artifacts not sorted by name: %#v", got.Artifacts)
	}
	if !slices.Equal(got.RecoveryClasses["custom"], []string{"a", "z"}) {
		t.Fatalf("custom recovery class not sorted: %#v", got.RecoveryClasses["custom"])
	}

	if err := os.WriteFile(path, []byte(`{"format":"other","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFullManifest(path); err == nil {
		t.Fatal("ReadFullManifest accepted wrong format")
	}
}
