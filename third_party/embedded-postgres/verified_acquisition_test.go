// SPDX-License-Identifier: MIT
//go:build unix

package embeddedpostgres

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	_ "embed"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

//go:embed testdata/start-fails-postgres-fixture.txz
var verifiedStartFailureArchive []byte

//go:embed testdata/oversized-dictionary-fixture.txz
var oversizedDictionaryArchive []byte

//go:embed testdata/repeated-pax-fixture.tar
var repeatedPAXArchive []byte

func TestVerifiedAcquisitionPublishesOnlyAuthenticatedBytes(t *testing.T) {
	for _, good := range []bool{false, true} {
		t.Run(map[bool]string{false: "mismatch", true: "matching"}[good], func(t *testing.T) {
			ep := verifiedTestDatabase(t, verifiedTestConfig(t.TempDir()), nil)
			cache, _ := ep.cacheLocator()
			ep.fetchVerifiedArchive = func(destination string) error {
				if destination == cache || filepath.Dir(destination) == filepath.Dir(cache) {
					t.Fatal("download reached shared cache before authentication")
				}
				if _, err := os.Lstat(cache); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("cache published before download")
				}
				data := []byte("untrusted")
				if good {
					data = verifiedFixtureArchive
				}
				return os.WriteFile(destination, data, 0600)
			}
			err := ep.AcquireArchive()
			if good {
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(cache)
				if err != nil || !bytes.Equal(data, verifiedFixtureArchive) {
					t.Fatal("authenticated cache missing")
				}
			} else {
				if err == nil {
					t.Fatal("mismatch accepted")
				}
				if _, err := os.Lstat(cache); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("untrusted bytes published")
				}
			}
			if ep.verifiedRunPath != "" {
				t.Fatal("acquisition extracted executable tree")
			}
		})
	}
}

func TestVerifiedAcquireRejectsMissingDownload(t *testing.T) {
	ep := verifiedTestDatabase(t, verifiedTestConfig(t.TempDir()), nil)
	ep.fetchVerifiedArchive = func(string) error { return nil }
	if err := ep.AcquireArchive(); err == nil {
		t.Fatal("missing archive accepted")
	}
	cache, _ := ep.cacheLocator()
	if ok, err := VerifyArchiveFile(cache, ep.archiveIdentity.SHA256); ok || err != nil {
		t.Fatalf("missing archive must remain false,nil: %v %v", ok, err)
	}
	legacy := NewDatabase()
	if err := legacy.AcquireArchive(); err == nil {
		t.Fatal("legacy acquisition accepted without identity")
	}
}

func TestVerifiedPublicationCrossProcess(t *testing.T) {
	if dir := os.Getenv("TRSTCTL_VERIFIED_PUBLICATION_CHILD"); dir != "" {
		if err := publishVerifiedArchive(dir, "archive.txz", verifiedFixtureArchive); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(executable, "-test.run=^TestVerifiedPublicationCrossProcess$")
			cmd.Env = append(os.Environ(), "TRSTCTL_VERIFIED_PUBLICATION_CHILD="+dir)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("publication child: %v %s", err, output)
			}
		}()
	}
	wg.Wait()
	got, err := os.ReadFile(filepath.Join(dir, "archive.txz"))
	if err != nil || !bytes.Equal(got, verifiedFixtureArchive) {
		t.Fatal("winning archive differs")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("publication temporary files remain")
	}
	if err := publishVerifiedArchive(dir, "archive.txz", []byte("different contender")); err == nil {
		t.Fatal("different winner accepted")
	}
	got, err = os.ReadFile(filepath.Join(dir, "archive.txz"))
	if err != nil || !bytes.Equal(got, verifiedFixtureArchive) {
		t.Fatal("collision overwrote winner")
	}
}

func TestVerifiedStartRejectsNonregularDataVersion(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "directory", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			config := verifiedTestConfig(t.TempDir())
			ep := verifiedTestDatabase(t, config, verifiedFixtureArchive)
			if err := os.MkdirAll(config.dataPath, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(config.dataPath, "PG_VERSION")
			var err error
			switch kind {
			case "fifo":
				err = syscall.Mkfifo(file, 0600)
			case "symlink":
				err = os.Symlink("missing", file)
			case "directory":
				err = os.Mkdir(file, 0700)
			case "oversized":
				err = os.WriteFile(file, bytes.Repeat([]byte("x"), 17), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			ep.initDatabase = func(string, string, string, string, string, string, string, *os.File) error {
				t.Error("invalid data reached initializer")
				return errors.New("unexpected init")
			}
			if err := ep.Start(); err == nil || !strings.Contains(err.Error(), "version must be a regular bounded file") {
				t.Fatalf("nonregular data reached start: %v", err)
			}
		})
	}
}

func TestVerifiedStartFailureDoesNotStopUnownedServer(t *testing.T) {
	config := verifiedTestConfig(t.TempDir())
	identity := verifiedTestIdentity(config)
	identity.SHA256 = boundarycrypto.SHA256Hex(verifiedStartFailureArchive)
	ep, err := NewVerifiedDatabase(config, identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ep.cleanupVerifiedBinary(); err != nil {
			t.Error(err)
		}
	})
	cache, _ := ep.cacheLocator()
	if err := os.MkdirAll(filepath.Dir(cache), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, verifiedStartFailureArchive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config.dataPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.dataPath, "PG_VERSION"), []byte("16\n"), 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "unowned-stop")
	t.Setenv("TRSTCTL_VERIFIED_STOP_MARKER", marker)
	startErr := ep.Start()
	var exitErr *exec.ExitError
	if !errors.As(startErr, &exitErr) || exitErr.ExitCode() != 86 {
		t.Fatalf("native start failure cause lost: %v", startErr)
	}
	if err := startErr; err == nil || !strings.Contains(err.Error(), "startup ownership uncertain") {
		t.Fatalf("missing ownership diagnostic: %v", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed start stopped unowned server")
	}
	if ep.started || ep.syncedLogger != nil || ep.verifiedRunPath == "" {
		t.Fatal("failed start ownership or descriptor lifecycle is incorrect")
	}
	if err := ep.Stop(); err == nil {
		t.Fatal("unproven start exposed stop authority")
	}
	if _, err := os.Stat(filepath.Join(ep.verifiedRunPath, "binaries/bin/pg_ctl")); err != nil {
		t.Fatal("uncertain child lost executable tree")
	}
}

func TestVerifiedArchiveVerifierRejectsNonregularAndOversizedInputs(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "directory", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "archive.txz")
			var err error
			switch kind {
			case "fifo":
				err = syscall.Mkfifo(file, 0600)
			case "symlink":
				err = os.Symlink("missing", file)
			case "directory":
				err = os.Mkdir(file, 0700)
			case "oversized":
				var f *os.File
				f, err = os.Create(file)
				if err == nil {
					err = errors.Join(f.Truncate(maxPostgresArchiveBytes+1), f.Close())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := VerifyArchiveFile(file, boundarycrypto.SHA256Hex(verifiedFixtureArchive)); ok || err == nil {
				t.Fatal("unsafe verification input accepted")
			}
		})
	}
}

func TestVerifiedExtractionBoundsHiddenMetadataAndDictionary(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if len(repeatedPAXArchive) <= 4096 {
		t.Fatal("metadata control too small")
	}
	reader := tar.NewReader(&boundedArchiveReader{reader: bytes.NewReader(repeatedPAXArchive), remaining: 4096})
	if err := extractBoundedTar(reader, root, archiveLimits{4096, 4096, 10}); err == nil || !strings.Contains(err.Error(), "decompressed stream exceeds") {
		t.Fatalf("hidden PAX bytes escaped bound: %v", err)
	}
	if err := extractVerifiedArchive(oversizedDictionaryArchive, root); err == nil {
		t.Fatal("oversized XZ dictionary accepted")
	}
}

type verifiedResponseBody struct {
	io.Reader
	closed *int
	err    error
}

func (b verifiedResponseBody) Close() error { *b.closed++; return b.err }

type verifiedRoundTripper func(*http.Request) (*http.Response, error)

func (f verifiedRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifiedDownloadClosesBodiesAndBoundsResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		closeErr   error
		want       string
	}{{"oversized", "12345", 200, nil, "byte limit"}, {"status", "", 404, nil, "HTTP 404"}, {"close", "ok", 200, errors.New("close sentinel"), "close sentinel"}} {
		t.Run(tc.name, func(t *testing.T) {
			closed := 0
			client := &http.Client{Transport: verifiedRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, ContentLength: -1, Body: verifiedResponseBody{strings.NewReader(tc.body), &closed, tc.closeErr}}, nil
			})}
			if _, err := fetchBoundedResponse(client, "https://repo.example.test", 4); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("response result %v", err)
			}
			if closed != 1 {
				t.Fatal("response body leaked or double closed")
			}
		})
	}
}

func TestVerifiedJARRequiresExactlyExpectedTXZ(t *testing.T) {
	for _, names := range [][]string{{"wrong.txz"}, {"expected.txz", "another.txz"}, {"expected.txz", "expected.txz"}, {"../expected.txz"}, {"expected.txz"}} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			var b bytes.Buffer
			w := zip.NewWriter(&b)
			for _, name := range names {
				f, err := w.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.Write(verifiedFixtureArchive); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			err := decompressResponse(b.Bytes(), -1, func() (string, bool) { return filepath.Join(dir, "download.txz"), false }, "fixture", "expected.txz")
			want := len(names) == 1 && names[0] == "expected.txz"
			if (err == nil) != want {
				t.Fatalf("archive selection result %v", err)
			}
		})
	}
}
