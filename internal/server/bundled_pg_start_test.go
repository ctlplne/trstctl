// SPDX-License-Identifier: MPL-2.0
//go:build unix

package server

import (
	_ "embed"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

//go:embed testdata/bundled-pg/verified-postgres-fixture.txz
var bundledPGHarmlessArchive []byte

// The archive and local pin in these tests are synthetic. No PostgreSQL server
// exists in the fixture: initdb prints one marker line and exits86, and the other
// two executables also only print that line and exit86.
func TestBundledPostgresRejectsUnrelatedExtractedCache(t *testing.T) {
	root, fixture := bundledPGTestRoot(t)
	t.Setenv("TMPDIR", root)
	cacheDir := filepath.Join(root, "trstctl-pg-bin")
	if err := os.MkdirAll(filepath.Join(cacheDir, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "untrusted.marker")
	t.Setenv("TRSTCTL_PG_TEST_MARKER", marker)
	script := []byte("#!/bin/sh\nprintf 'untrusted-executed\\n' > \"$TRSTCTL_PG_TEST_MARKER\"\nexit 86\n")
	// The harmless marker must be executable for this negative control to detect
	// a provenance bypass. Rooted writes keep it inside the private test tree.
	if err := fixture.WriteFile("trstctl-pg-bin/bin/initdb", script, 0700); err != nil {
		t.Fatal(err)
	}
	// Authenticated fixture bytes do not form an archive and cannot justify any
	// existing executable. The legacy implementation nevertheless runs bin/.
	trusted := []byte("controlled authenticated fixture; no executable or TAR")
	setBundledPGFixturePin(t, trusted)
	if err := os.WriteFile(bundledPGCacheArchive(cacheDir), trusted, 0600); err != nil {
		t.Fatal(err)
	}
	_, stop, err := startBundledPostgres(config.Postgres{DataDir: filepath.Join(root, "data"), Port: bundledPGTestPort(t)})
	if err == nil || stop != nil {
		t.Fatal("invalid archive accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("untrusted cached executable ran despite unrelated archive")
	}
	if data, err := fixture.ReadFile("trstctl-pg-bin/bin/initdb"); err != nil || string(data) != string(script) {
		t.Fatal("legacy cache was modified")
	}
}

func TestBundledPostgresAuthenticatedFixtureReachesInitializerAndCleansUp(t *testing.T) {
	root, _ := bundledPGTestRoot(t)
	t.Setenv("TMPDIR", root)
	cacheDir := filepath.Join(root, "trstctl-pg-bin")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	setBundledPGFixturePin(t, bundledPGHarmlessArchive)
	if err := os.WriteFile(bundledPGCacheArchive(cacheDir), bundledPGHarmlessArchive, 0600); err != nil {
		t.Fatal(err)
	}
	_, stop, err := startBundledPostgres(config.Postgres{DataDir: filepath.Join(root, "data"), Port: bundledPGTestPort(t)})
	if err == nil || stop != nil || !strings.Contains(err.Error(), "verified harmless fixture") || !strings.Contains(err.Error(), "exit status 86") {
		t.Fatalf("verified fixture did not reach initializer: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "trstctl-pg-verified-") || strings.HasPrefix(entry.Name(), "embedded_postgres_log") {
			t.Fatal("failed initializer leaked owned executable tree or log")
		}
	}
}

// A real committed pin must reject a mismatched archive before an adjacent
// cached executable can run. This path needs no network or synthetic pin.
func TestBundledPostgresRejectsMismatchedArchiveBeforeCachedInit(t *testing.T) {
	root, fixture := bundledPGTestRoot(t)
	t.Setenv("TMPDIR", root)
	cacheDir := filepath.Join(root, "trstctl-pg-bin")
	if err := os.MkdirAll(filepath.Join(cacheDir, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "untrusted.marker")
	t.Setenv("TRSTCTL_PG_TEST_MARKER", marker)
	script := []byte("#!/bin/sh\nprintf 'untrusted-executed\\n' > \"$TRSTCTL_PG_TEST_MARKER\"\nexit 86\n")
	// See the executable negative control above: no real database is involved.
	if err := fixture.WriteFile("trstctl-pg-bin/bin/initdb", script, 0700); err != nil {
		t.Fatal(err)
	}
	archivePath := bundledPGCacheArchive(cacheDir)
	mismatched := []byte("mismatched archive; never the committed PostgreSQL bytes")
	if err := os.WriteFile(archivePath, mismatched, 0600); err != nil {
		t.Fatal(err)
	}
	dsn, stop, err := startBundledPostgres(config.Postgres{DataDir: filepath.Join(root, "data"), Port: bundledPGTestPort(t)})
	if err == nil || !strings.Contains(err.Error(), "provenance check FAILED") || dsn != "" || stop != nil {
		t.Fatalf("mismatched archive startup result: %v", err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("mismatched archive allowed cached initdb execution")
	}
	if data, err := fixture.ReadFile("trstctl-pg-bin/bin/initdb"); err != nil || string(data) != string(script) {
		t.Fatal("legacy executable changed")
	}
	if data, err := fixture.ReadFile(filepath.Join("trstctl-pg-bin", filepath.Base(archivePath))); err != nil || string(data) != string(mismatched) {
		t.Fatal("mismatched legacy archive changed")
	}
}

func bundledPGTestRoot(t *testing.T) (string, *os.Root) {
	t.Helper()
	// TempDir creates a private directory with mode 0700.
	path := t.TempDir()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return path, root
}

func setBundledPGFixturePin(t *testing.T, archive []byte) {
	t.Helper()
	key := runtime.GOOS + "-" + archiveArch()
	old, exists := bundledPGTxzSHA256[key]
	bundledPGTxzSHA256[key] = crypto.SHA256Hex(archive)
	t.Cleanup(func() {
		if exists {
			bundledPGTxzSHA256[key] = old
		} else {
			delete(bundledPGTxzSHA256, key)
		}
	})
}

func bundledPGTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// A configured port must not wrap during conversion and start another database.
func TestBundledPostgresRejectsInvalidPortBeforeAcquisition(t *testing.T) {
	for _, port := range []int{-1, 65536, int(^uint(0) >> 1)} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			root, fixture := bundledPGTestRoot(t)
			t.Setenv("TMPDIR", root)
			dsn, stop, err := startBundledPostgres(config.Postgres{DataDir: filepath.Join(root, "data"), Port: port})
			if err == nil || dsn != "" || stop != nil || !strings.Contains(err.Error(), "port") {
				t.Fatalf("invalid port result: %v", err)
			}
			entries, err := fs.ReadDir(fixture.FS(), ".")
			if err != nil || len(entries) != 0 {
				t.Fatalf("invalid port acquired resources: %v, %v", entries, err)
			}
		})
	}
}

// A precreated cache ancestor cannot redirect authenticated publication into
// another directory, even when its final identity child would look private.
func TestBundledPostgresRejectsUnsafeCacheAncestorBeforeAcquisition(t *testing.T) {
	for _, kind := range []string{"prefix-link", "identity-link", "writable-prefix", "nonsticky-anchor"} {
		t.Run(kind, func(t *testing.T) {
			root, fixture := bundledPGTestRoot(t)
			outside, sentinel := bundledPGTestRoot(t)
			t.Setenv("TMPDIR", root)
			identity, err := bundledPGArchiveIdentity()
			if err != nil {
				t.Fatal(err)
			}
			child := identity.OS + "-" + identity.Arch + "-" + string(identity.Version) + "-" + identity.SHA256
			switch kind {
			case "prefix-link":
				err = fixture.Symlink(outside, "trstctl-pg-archives")
			case "identity-link":
				err = fixture.Mkdir("trstctl-pg-archives", 0700)
				if err == nil {
					err = fixture.Symlink(outside, filepath.Join("trstctl-pg-archives", child))
				}
			case "writable-prefix":
				err = fixture.Mkdir("trstctl-pg-archives", 0700)
				if err == nil {
					err = fixture.Chmod("trstctl-pg-archives", 0777)
				}
			case "nonsticky-anchor":
				err = fixture.Chmod(".", 0777)
			}
			if err != nil {
				t.Fatal(err)
			}
			// If the cache guard regresses, an inert legacy archive prevents this
			// negative control from downloading or executing PostgreSQL.
			if err := fixture.Mkdir("trstctl-pg-bin", 0700); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join("trstctl-pg-bin", filepath.Base(bundledPGCacheArchive(root)))
			if err := fixture.WriteFile(archive, []byte("inert mismatched archive"), 0600); err != nil {
				t.Fatal(err)
			}
			before := bundledPGTestTopology(t, fixture)
			want := "postgres cache child must be an owned directory without links or shared write access"
			if kind == "nonsticky-anchor" {
				want = "postgres cache anchor must be private or a trusted sticky temporary directory"
			}
			dsn, stop, err := startBundledPostgres(config.Postgres{DataDir: filepath.Join(root, "data"), Port: 5432})
			if err == nil || dsn != "" || stop != nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("unsafe cache accepted: %v", err)
			}
			if after := bundledPGTestTopology(t, fixture); before != after {
				t.Fatalf("cache rejection created resources: before=%q after=%q", before, after)
			}
			entries, err := fs.ReadDir(sentinel.FS(), ".")
			if err != nil || len(entries) != 0 {
				t.Fatalf("outside sentinel changed: %v, %v", entries, err)
			}
		})
	}
}

func bundledPGTestTopology(t *testing.T, root *os.Root) string {
	t.Helper()
	var names []string
	if err := fs.WalkDir(root.FS(), ".", func(name string, _ fs.DirEntry, err error) error {
		if err == nil {
			names = append(names, name)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return strings.Join(names, "\n")
}
