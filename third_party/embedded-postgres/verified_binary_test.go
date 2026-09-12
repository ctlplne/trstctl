// SPDX-License-Identifier: MIT
//go:build unix

package embeddedpostgres

import (
	"archive/tar"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

//go:embed testdata/verified-postgres-fixture.txz
var verifiedFixtureArchive []byte

func verifiedTestConfig(dir string) Config {
	return DefaultConfig().Version("16.15.0").Port(0).DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "old-runtime")).BinariesPath(filepath.Join(dir, "old-binaries")).CachePath(filepath.Join(dir, "cache"))
}

func verifiedTestIdentity(config Config) ArchiveIdentity {
	goos, arch, version := defaultVersionStrategy(config, runtime.GOOS, runtime.GOARCH, linuxMachineName, shouldUseAlpineLinuxBuild)()
	return ArchiveIdentity{goos, arch, version, boundarycrypto.SHA256Hex(verifiedFixtureArchive)}
}

func verifiedTestDatabase(t *testing.T, config Config, archive []byte) *EmbeddedPostgres {
	t.Helper()
	ep, err := NewVerifiedDatabase(config, verifiedTestIdentity(config))
	if err != nil {
		t.Fatal(err)
	}
	cache, _ := ep.cacheLocator()
	if err := os.MkdirAll(filepath.Dir(cache), 0700); err != nil {
		t.Fatal(err)
	}
	if archive != nil {
		if err := os.WriteFile(cache, archive, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		// These cases normally reject before launching PostgreSQL. If a
		// regression unexpectedly starts our instance, still stop that instance.
		if ep.started {
			if err := ep.Stop(); err != nil {
				t.Error(err)
			}
			return
		}
		if err := ep.cleanupVerifiedBinary(); err != nil {
			t.Error(err)
		}
	})
	return ep
}

func TestVerifiedArchiveIdentityRejectsMissingAndWrongScope(t *testing.T) {
	config := verifiedTestConfig(t.TempDir())
	good := verifiedTestIdentity(config)
	for _, field := range []string{"digest-empty", "digest-short", "digest-uppercase", "version", "os", "arch", "data-path"} {
		t.Run(field, func(t *testing.T) {
			identity := good
			c := config
			switch field {
			case "digest-empty":
				identity.SHA256 = ""
			case "digest-short":
				identity.SHA256 = "00"
			case "digest-uppercase":
				identity.SHA256 = strings.ToUpper(good.SHA256)
			case "version":
				identity.Version = V16
			case "os":
				identity.OS = "unknown"
			case "arch":
				identity.Arch = "unknown"
			case "data-path":
				c.dataPath = ""
			}
			if _, err := NewVerifiedDatabase(c, identity); err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
	if V16 != "16.4.0" {
		t.Fatal("legacy fixture version must not be relabelled as served version")
	}
}

func TestVerifiedStartAuthenticatesColdArchiveBeforeInit(t *testing.T) {
	ep := verifiedTestDatabase(t, verifiedTestConfig(t.TempDir()), nil)
	fetches, initializations := 0, 0
	ep.fetchVerifiedArchive = func(destination string) error {
		fetches++
		return os.WriteFile(destination, []byte("unpinned downloaded archive"), 0600)
	}
	ep.initDatabase = func(string, string, string, string, string, string, string, *os.File) error {
		initializations++
		return errors.New("must not initialize")
	}
	err := ep.Start()
	if err == nil || !strings.Contains(err.Error(), "provenance check FAILED") || fetches != 1 || initializations != 0 || ep.verifiedRunPath != "" {
		t.Fatalf("cold provenance ordering: fetches=%d init=%d root=%q err=%v", fetches, initializations, ep.verifiedRunPath, err)
	}
}

func TestVerifiedStartRejectsCachedMismatchWithoutDataMutation(t *testing.T) {
	config := verifiedTestConfig(t.TempDir())
	ep := verifiedTestDatabase(t, config, []byte("wrong archive"))
	if err := os.MkdirAll(config.dataPath, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(config.dataPath, "keep")
	if err := os.WriteFile(sentinel, []byte("user data"), 0600); err != nil {
		t.Fatal(err)
	}
	ep.fetchVerifiedArchive = func(string) error { t.Error("mismatched cache must not be silently replaced"); return nil }
	if err := ep.Start(); err == nil || !strings.Contains(err.Error(), "provenance check FAILED") {
		t.Fatalf("unexpected mismatch result: %v", err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "user data" {
		t.Fatal("data modified before authentication")
	}
}

func TestVerifiedPreparationIgnoresLegacyBinAndReextracts(t *testing.T) {
	config := verifiedTestConfig(t.TempDir())
	ep := verifiedTestDatabase(t, config, verifiedFixtureArchive)
	old := filepath.Join(config.binariesPath, "bin/initdb")
	if err := os.MkdirAll(filepath.Dir(old), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("unrelated legacy executable"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := ep.prepareVerifiedBinary(); err != nil {
		t.Fatal(err)
	}
	firstRoot := ep.verifiedRunPath
	first := filepath.Join(ep.config.binariesPath, "bin/initdb")
	good, err := os.ReadFile(first)
	if err != nil || !bytes.Contains(good, []byte("harmless fixture")) {
		t.Fatal("fresh extracted bytes not used")
	}
	if err := os.WriteFile(first, []byte("tampered prepared tree"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := ep.cleanupVerifiedBinary(); err != nil {
		t.Fatal(err)
	}
	if err := ep.prepareVerifiedBinary(); err != nil {
		t.Fatal(err)
	}
	if ep.verifiedRunPath == firstRoot {
		t.Fatal("prepared directory reused")
	}
	if data, err := os.ReadFile(filepath.Join(ep.config.binariesPath, "bin/initdb")); err != nil || !bytes.Equal(data, good) {
		t.Fatal("later start trusted changed extracted content")
	}
	if data, err := os.ReadFile(old); err != nil || string(data) != "unrelated legacy executable" {
		t.Fatal("legacy cache modified")
	}
}

func TestVerifiedInitializationFailureCleansOnlyOwnedTree(t *testing.T) {
	config := verifiedTestConfig(t.TempDir())
	ep := verifiedTestDatabase(t, config, verifiedFixtureArchive)
	if err := os.MkdirAll(config.runtimePath, 0700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(config.runtimePath, "keep")
	if err := os.WriteFile(keep, []byte("old runtime"), 0600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("controlled initialization failure")
	var usedRoot string
	ep.initDatabase = func(binaryPath, runtimePath, dataPath, username, password, locale, encoding string, logger *os.File) error {
		usedRoot = ep.verifiedRunPath
		if usedRoot == "" || binaryPath == config.binariesPath || runtimePath == config.runtimePath {
			t.Error("initializer did not receive private paths")
		}
		if _, err := os.Stat(filepath.Join(binaryPath, "bin/initdb")); err != nil {
			t.Error(err)
		}
		return want
	}
	if err := ep.Start(); !errors.Is(err, want) {
		t.Fatalf("lost initialization error: %v", err)
	}
	if usedRoot == "" || ep.verifiedRunPath != "" {
		t.Fatal("owned tree cleanup missing")
	}
	if _, err := os.Stat(usedRoot); !os.IsNotExist(err) {
		t.Fatal("owned prepared tree remains")
	}
	if b, err := os.ReadFile(keep); err != nil || string(b) != "old runtime" {
		t.Fatal("legacy runtime modified")
	}
}

func TestVerifiedDataReuseRejectsWrongOrUnrecognizedData(t *testing.T) {
	for _, version := range []string{"", "15\n", "1\n", "16\n"} {
		t.Run(fmt.Sprintf("version-%q", version), func(t *testing.T) {
			config := verifiedTestConfig(t.TempDir())
			ep := verifiedTestDatabase(t, config, verifiedFixtureArchive)
			if err := os.MkdirAll(config.dataPath, 0700); err != nil {
				t.Fatal(err)
			}
			if version != "" {
				if err := os.WriteFile(filepath.Join(config.dataPath, "PG_VERSION"), []byte(version), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(config.dataPath, "keep"), []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			ready, err := ep.verifiedDataReady()
			if version == "16\n" {
				if !ready || err != nil {
					t.Fatal("matching data rejected")
				}
				return
			}
			if ready {
				t.Fatal("incorrect data version accepted")
			}
			if version == "" && ep.initVerifiedDataDirectory() == nil {
				t.Fatal("unrecognized data removed")
			}
			if b, e := os.ReadFile(filepath.Join(config.dataPath, "keep")); e != nil || string(b) != "preserve" {
				t.Fatal("data destroyed")
			}
		})
	}
}

func TestVerifiedPreparationConcurrencyUsesDistinctTrees(t *testing.T) {
	config := verifiedTestConfig(t.TempDir())
	_ = verifiedTestDatabase(t, config, verifiedFixtureArchive)
	var wait sync.WaitGroup
	roots := make(chan string, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ep, err := NewVerifiedDatabase(config, verifiedTestIdentity(config))
			if err == nil {
				err = ep.prepareVerifiedBinary()
			}
			if err != nil {
				errs <- err
				return
			}
			roots <- ep.verifiedRunPath
			errs <- ep.cleanupVerifiedBinary()
		}()
	}
	wait.Wait()
	close(roots)
	close(errs)
	seen := map[string]bool{}
	for root := range roots {
		if seen[root] {
			t.Error("concurrent starts shared executable tree")
		}
		seen[root] = true
	}
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if len(seen) != 8 {
		t.Fatalf("prepared %d/8 isolated trees", len(seen))
	}
}

func testTar(t *testing.T, extra ...*tar.Header) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for _, name := range []string{"initdb", "pg_ctl", "postgres"} {
		data := []byte("#!/bin/sh\nexit 86\n")
		if err := writer.WriteHeader(&tar.Header{Name: "bin/" + name, Mode: 0700, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	for _, header := range extra {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg && header.Size < 1024 {
			if _, err := writer.Write(make([]byte, header.Size)); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = writer.Close() // Oversized-header cases intentionally have no body.
	return tar.NewReader(bytes.NewReader(buf.Bytes()))
}

func TestVerifiedExtractionRejectsUnsafePathsLinksAndTypes(t *testing.T) {
	cases := map[string][]*tar.Header{
		"parent": {{Name: "../escape", Typeflag: tar.TypeReg}}, "absolute": {{Name: "/escape", Typeflag: tar.TypeReg}}, "backslash": {{Name: "a\\..\\escape", Typeflag: tar.TypeReg}}, "drive": {{Name: "C:/escape", Typeflag: tar.TypeReg}},
		"duplicate": {{Name: "bin/initdb", Typeflag: tar.TypeReg}}, "privileged": {{Name: "extra", Typeflag: tar.TypeReg, Mode: 04700}}, "device": {{Name: "device", Typeflag: tar.TypeChar}}, "hardlink": {{Name: "hard", Typeflag: tar.TypeLink, Linkname: "bin/initdb"}},
		"link-escape": {{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "../escape"}}, "dangling": {{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "missing"}}, "link-cycle": {{Name: "a", Typeflag: tar.TypeSymlink, Linkname: "b"}, {Name: "b", Typeflag: tar.TypeSymlink, Linkname: "a"}},
		"link-parent": {{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "bin"}, {Name: "alias/child", Typeflag: tar.TypeReg}}, "oversized": {{Name: "huge", Typeflag: tar.TypeReg, Size: maxPostgresFileBytes + 1}},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := extractVerifiedTar(testTar(t, headers...), root); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "..", "escape")); !os.IsNotExist(err) {
				t.Fatal("extraction escaped root")
			}
		})
	}
}

func TestVerifiedExtractionAllowsContainedLinkAndEnforcesBudgets(t *testing.T) {
	for _, mode := range []string{"good", "entry-limit", "total-limit", "file-limit", "invalid-limit"} {
		t.Run(mode, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			limits := archiveLimits{1024, 4096, 10}
			switch mode {
			case "entry-limit":
				limits.entries = 2
			case "total-limit":
				limits.expandedBytes = 20
			case "file-limit":
				limits.fileBytes = 2
			case "invalid-limit":
				limits.entries = 0
			}
			err = extractBoundedTar(testTar(t, &tar.Header{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "bin/initdb"}), root, limits)
			if (err == nil) != (mode == "good") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
		})
	}
	if _, err := readBounded(strings.NewReader("abc"), 2); err == nil {
		t.Fatal("download bound ignored")
	}
	if data, err := readBounded(strings.NewReader("ab"), 2); err != nil || string(data) != "ab" {
		t.Fatal("exact bound rejected")
	}
}

func TestVerifiedArchiveRejectsSymlinksAndWritableCache(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, verifiedFixtureArchive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedArchive(dir, "link"); err == nil {
		t.Fatal("archive symlink accepted")
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	if err := ensurePrivateCache(dir); err == nil {
		t.Fatal("writable cache accepted")
	}
}
