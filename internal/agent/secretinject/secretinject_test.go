package secretinject

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCopyOnceCopiesMappedSecretBytes(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "db-password"), []byte("s3cr3t"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := CopyOnce(Options{
		SourceDir: source,
		TargetDir: target,
		Mappings:  []Mapping{{Key: "db-password", Path: "db/password"}},
		FileMode:  0o440,
	}); err != nil {
		t.Fatalf("CopyOnce: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(target, "db", "password"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("copied bytes = %q", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(target, "db", "password"))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o440 {
			t.Fatalf("mode = %v, want 0440", got)
		}
	}
}

func TestCopyOnceDiscoversSourceFiles(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "api-key"), []byte("api-v1"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, ".hidden"), []byte("ignored"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := CopyOnce(Options{SourceDir: source, TargetDir: target, Once: true}); err != nil {
		t.Fatalf("CopyOnce: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(target, "api-key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "api-v1" {
		t.Fatalf("copied bytes = %q", got)
	}
	if _, err := os.Stat(filepath.Join(target, ".hidden")); !os.IsNotExist(err) {
		t.Fatalf("hidden key copied or unexpected stat error: %v", err)
	}
}

func TestParseMappingsRejectsEscapes(t *testing.T) {
	mappings, err := ParseMappings("db=database/password,api=api/key")
	if err != nil {
		t.Fatalf("ParseMappings: %v", err)
	}
	if len(mappings) != 2 || mappings[0].Key != "db" || mappings[1].Path != "api/key" {
		t.Fatalf("mappings = %+v", mappings)
	}
	if _, err := normalizeMappings("/source", "/target", []Mapping{{Key: "../db", Path: "db"}}); err == nil {
		t.Fatal("expected source key escape to fail")
	}
	if _, err := normalizeMappings("/source", "/target", []Mapping{{Key: "db", Path: "../db"}}); err == nil {
		t.Fatal("expected target path escape to fail")
	}
}
