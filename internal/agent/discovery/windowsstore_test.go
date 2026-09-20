// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// The Windows certificate store source (epic C1). The syscall lives behind a
// build tag; everything that decides what an operator SEES — refusing unknown
// stores, skipping unparseable blobs, failing rather than reporting empty — is
// tested here, on every platform.

// fakeWindowsReader stands in for crypt32.
type fakeWindowsReader struct {
	blobs map[string][]byte
	err   error
	// calls records what the source asked the platform for, so the test can
	// prove normalization happened before the syscall rather than after.
	calls []string
}

func (f *fakeWindowsReader) readStore(_ context.Context, location WindowsStoreLocation, store string) (map[string][]byte, error) {
	f.calls = append(f.calls, string(location)+"/"+store)
	if f.err != nil {
		return nil, f.err
	}
	return f.blobs, nil
}

// windowsTestCertDER mints a certificate through the crypto boundary (AN-3):
// this package may not import crypto/x509 itself, and routing the fixture
// through internal/crypto is the same discipline the production path follows.
func windowsTestCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	der, err := crypto.SelfSignedCACert(signer, cn, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func windowsSourceWithReader(location WindowsStoreLocation, store string, reader windowsCertReader) *WindowsStoreSource {
	return &WindowsStoreSource{location: location, store: strings.ToUpper(store), reader: reader}
}

// TestWindowsStoreReportsEveryCertificate is the capability itself: the estate
// an operator most wants inventoried, actually inventoried.
func TestWindowsStoreReportsEveryCertificate(t *testing.T) {
	reader := &fakeWindowsReader{blobs: map[string][]byte{
		"0": windowsTestCertDER(t, "iis-site-1"),
		"1": windowsTestCertDER(t, "iis-site-2"),
	}}
	src := windowsSourceWithReader(WindowsLocationLocalMachine, WindowsStoreWebHosting, reader)

	found, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d certificates, want 2", len(found))
	}
	for _, f := range found {
		if f.Source != SourceWindowsCert {
			t.Errorf("finding source = %q, want %q", f.Source, SourceWindowsCert)
		}
		if !strings.HasPrefix(f.Location, "local-machine/WEBHOSTING/") {
			t.Errorf("finding location %q does not name the hierarchy and store", f.Location)
		}
		// The locator is the certificate's own fingerprint, so two passes over
		// an unchanged store produce identical reports.
		if !strings.HasSuffix(f.Location, f.Cert.SHA256Fingerprint) {
			t.Errorf("finding location %q is not keyed by the certificate fingerprint", f.Location)
		}
	}
}

// TestWindowsStoreSkipsUnparseableBlobsButKeepsTheRest: a Windows store holds
// objects this does not understand. One of them must not cost an operator the
// inventory of everything else in the store.
func TestWindowsStoreSkipsUnparseableBlobsButKeepsTheRest(t *testing.T) {
	reader := &fakeWindowsReader{blobs: map[string][]byte{
		"0": []byte("not a certificate at all"),
		"1": windowsTestCertDER(t, "real-cert"),
		"2": {},
	}}
	src := windowsSourceWithReader(WindowsLocationLocalMachine, WindowsStoreMy, reader)

	found, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d certificates, want 1 (the malformed entries are skipped, not fatal)", len(found))
	}
	if found[0].Cert.Subject == "" {
		t.Error("the surviving finding carries no subject")
	}
}

// TestWindowsStoreFailsRatherThanReportingEmpty is the honesty property. "We
// could not look" and "there is nothing there" must never read the same.
func TestWindowsStoreFailsRatherThanReportingEmpty(t *testing.T) {
	reader := &fakeWindowsReader{err: errors.New("access denied")}
	src := windowsSourceWithReader(WindowsLocationLocalMachine, WindowsStoreMy, reader)

	found, err := src.Discover(context.Background())
	if err == nil {
		t.Fatal("an unreadable store reported success; an operator would read that as a clean estate")
	}
	if len(found) != 0 {
		t.Fatalf("a failed read returned %d findings", len(found))
	}
}

// TestWindowsStoreRefusesUnknownStoresAndLocations: a typo must not become a
// silent empty result. The real reader also passes CERT_STORE_OPEN_EXISTING_FLAG
// so the platform cannot create the misspelled store either.
func TestWindowsStoreRefusesUnknownStoresAndLocations(t *testing.T) {
	reader := &fakeWindowsReader{blobs: map[string][]byte{}}

	if _, err := windowsSourceWithReader(WindowsLocationLocalMachine, "NOT-A-STORE", reader).
		Discover(context.Background()); err == nil {
		t.Error("an unknown store name was accepted")
	}
	if _, err := windowsSourceWithReader("somewhere-else", WindowsStoreMy, reader).
		Discover(context.Background()); err == nil {
		t.Error("an unknown store location was accepted")
	}
	if len(reader.calls) != 0 {
		t.Fatalf("the source called the platform %v for input it should have refused first", reader.calls)
	}
}

// TestWindowsStoreNameNormalization: operators write "My", the platform wants
// "MY", and neither should have to care.
func TestWindowsStoreNameNormalization(t *testing.T) {
	for _, name := range []string{"my", "My", "  MY  ", "webhosting"} {
		if !ValidWindowsStoreName(name) {
			t.Errorf("ValidWindowsStoreName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"", "personal", "MY2"} {
		if ValidWindowsStoreName(name) {
			t.Errorf("ValidWindowsStoreName(%q) = true, want false", name)
		}
	}
	reader := &fakeWindowsReader{blobs: map[string][]byte{}}
	if _, err := NewWindowsCertStoreSource(WindowsLocationLocalMachine, " my ").Discover(context.Background()); err != nil {
		// On a non-Windows build this is ErrWindowsStoreUnsupported, which is
		// itself the correct answer; what must NOT happen is a name rejection.
		if !errors.Is(err, ErrWindowsStoreUnsupported) {
			t.Fatalf("normalized store name was rejected: %v", err)
		}
	}
	_ = reader
}

// TestWindowsStoreUnsupportedOnNonWindows pins the stub's behaviour: an error,
// never an empty inventory. A Linux operator must not be told their Windows
// estate is clean.
func TestWindowsStoreUnsupportedOnNonWindows(t *testing.T) {
	src := NewWindowsCertStoreSource(WindowsLocationLocalMachine, WindowsStoreMy)
	found, err := src.Discover(context.Background())
	if runtime.GOOS == "windows" {
		t.Skip("this build has a real Windows certificate store")
	}
	if !errors.Is(err, ErrWindowsStoreUnsupported) {
		t.Fatalf("non-Windows discover error = %v, want ErrWindowsStoreUnsupported", err)
	}
	if len(found) != 0 {
		t.Fatalf("the unsupported reader returned %d findings", len(found))
	}
}
