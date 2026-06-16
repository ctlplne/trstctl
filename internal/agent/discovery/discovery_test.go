package discovery_test

import (
	"context"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/destination/certstore"
	"trstctl.com/trstctl/internal/agent/destination/softtoken"
	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/crypto"
)

// Four distinct real ECDSA self-signed certificates.
const (
	cert1 = `-----BEGIN CERTIFICATE-----
MIIBjDCCATGgAwIBAgIUbUBdvVyLGrRCJmc3v/XUcPHXkiMwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQZGlzY292ZXJ5LTEudGVzdDAeFw0yNjA1MzAxODA5NTFaFw0z
NjA1MjcxODA5NTFaMBsxGTAXBgNVBAMMEGRpc2NvdmVyeS0xLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS/wgFIHrQZaIbPLJiTFRAw7jskcfmHyR3bK9v4
SA1pf3qDdiQB251mv+nF3qDY23d/fY3C96wgySv56nhoW/N7o1MwUTAdBgNVHQ4E
FgQUagh6v1IAMWknG6X38HDrLuL/bN0wHwYDVR0jBBgwFoAUagh6v1IAMWknG6X3
8HDrLuL/bN0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA6Uv9
Q944+/6g4qbJ1TvNUXdphxwfq+j91btwxC9ENq8CIQDHIBCvC3Hvx4DN08ItES2l
vGsFCZlEd32emYdgZuAgcw==
-----END CERTIFICATE-----
`
	cert2 = `-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUAszQnRQKYrsFKRU71TjK0belKB8wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQZGlzY292ZXJ5LTIudGVzdDAeFw0yNjA1MzAxODA5NTFaFw0z
NjA1MjcxODA5NTFaMBsxGTAXBgNVBAMMEGRpc2NvdmVyeS0yLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATNCyhgnxWQxFqXJdVqYzbhkANCXoaez6YfFZh2
uDN92Cpp3oVw7XVN6jWgmtgCq3EjXNQ4kwMfxU5O0M3/b7GTo1MwUTAdBgNVHQ4E
FgQU+XjpMRZ0jnTV7wIAXtMxkqoF9QowHwYDVR0jBBgwFoAU+XjpMRZ0jnTV7wIA
XtMxkqoF9QowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAhkkr
BFMCANrA21yK/JppflT5Cpyosc+WjpRA4qdix+4CIB8+l3vFTO1TMiXwPx1SS+6Z
s5jsd15ORDb+wnddXlIL
-----END CERTIFICATE-----
`
	cert3 = `-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUdwtF3CIHovZ+rfH+sdoDMZkohEowCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQZGlzY292ZXJ5LTMudGVzdDAeFw0yNjA1MzAxODA5NTFaFw0z
NjA1MjcxODA5NTFaMBsxGTAXBgNVBAMMEGRpc2NvdmVyeS0zLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQDLi3lpGpOgxrY4LozPz4wggMPZUaOHwiU2w6z
g2y+rfeckLUvyKa5Y5ya4B2NlOdf5PFXxAGlWoWYDNENxy1io1MwUTAdBgNVHQ4E
FgQUjBF6DfQvQbW8B37NSCJSIXztawYwHwYDVR0jBBgwFoAUjBF6DfQvQbW8B37N
SCJSIXztawYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAkqVf
WDbJTQ6Pq+RVgW8IG9Bm3vEeEucKdvKoqnG01aQCIHfrmT3WnjpCSqwHZRHzq0dv
G55LNTsp4ceKuJOgnD97
-----END CERTIFICATE-----
`
	cert4 = `-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUUiBiV4s9/yh6xyaqih+hrhLbl+QwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQZGlzY292ZXJ5LTQudGVzdDAeFw0yNjA1MzAxODA5NTFaFw0z
NjA1MjcxODA5NTFaMBsxGTAXBgNVBAMMEGRpc2NvdmVyeS00LnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASgnf56KL/XUOz671tYsQQJt/t8ti3TtHw+RT+g
uReJIKvRWMta+lO4A8YbunwI+Hb+anADwKbneBOtviOCj30No1MwUTAdBgNVHQ4E
FgQUo13h6z+VLBYD73sSkaRQa+uBt1EwHwYDVR0jBBgwFoAUo13h6z+VLBYD73sS
kaRQa+uBt1EwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAT/0MX
hGHZrtTuGvhoJVjLDwAUReLRPIDuxzLFHyE5lwIgZsfk03XzW+wMNTLuZd/JaRsF
MKMSe6JIDVvxWkz7/Jk=
-----END CERTIFICATE-----
`
)

func fingerprint(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("bad test cert PEM")
	}
	return crypto.SHA256Hex(block.Bytes)
}

func fingerprints(found []discovery.Found) map[string]bool {
	out := map[string]bool{}
	for _, f := range found {
		out[f.Cert.SHA256Fingerprint] = true
	}
	return out
}

// The filesystem source finds certificates in PEM files (single and multi-cert),
// in DER files, recurses into subdirectories, and skips non-certificate files.
func TestFilesystemSourceDiscoversCerts(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "leaf.crt"), []byte(cert1))
	mustWrite(t, filepath.Join(dir, "fullchain.pem"), []byte(cert2+cert3)) // two certs in one file
	mustWrite(t, filepath.Join(dir, "notes.txt"), []byte("this is not a certificate"))
	block, _ := pem.Decode([]byte(cert4))
	mustWrite(t, filepath.Join(dir, "sub", "cert.der"), block.Bytes) // raw DER, in a subdir

	found, err := discovery.NewFilesystemSource(dir).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fps := fingerprints(found)
	for i, c := range []string{cert1, cert2, cert3, cert4} {
		if !fps[fingerprint(t, c)] {
			t.Errorf("cert %d not discovered", i+1)
		}
	}
	if len(found) != 4 {
		t.Errorf("found %d certs, want 4 (notes.txt must be skipped)", len(found))
	}
	for _, f := range found {
		if f.Source != discovery.SourceFilesystem || f.Location == "" {
			t.Errorf("bad source/location: %+v", f)
		}
	}
}

// The PKCS#11 source discovers certificate objects on a token.
func TestPKCS11SourceDiscoversTokenCerts(t *testing.T) {
	tok := softtoken.New()
	if err := tok.ImportCertificate("leaf-a", []byte{1}, []byte(cert1)); err != nil {
		t.Fatal(err)
	}
	if err := tok.ImportCertificate("leaf-b", []byte{2}, []byte(cert2)); err != nil {
		t.Fatal(err)
	}

	found, err := discovery.NewPKCS11Source("hsm0", tok).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d, want 2", len(found))
	}
	fps := fingerprints(found)
	if !fps[fingerprint(t, cert1)] || !fps[fingerprint(t, cert2)] {
		t.Error("token certs not discovered")
	}
	for _, f := range found {
		if f.Source != discovery.SourcePKCS11 {
			t.Errorf("source = %q, want pkcs11", f.Source)
		}
	}
}

// The Windows-store source discovers certificate entries in the store.
func TestWindowsStoreSourceDiscoversEntries(t *testing.T) {
	mem := certstore.NewMemory()
	ref := destination.StoreRef{Location: destination.LocalMachine, Name: "MY"}
	if err := mem.AddCertificate(ref, "web", []byte(cert3)); err != nil {
		t.Fatal(err)
	}

	found, err := discovery.NewWindowsStoreSource("MY", mem).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Cert.SHA256Fingerprint != fingerprint(t, cert3) {
		t.Fatalf("store cert not discovered: %+v", found)
	}
	if found[0].Source != discovery.SourceWindowsCert {
		t.Errorf("source = %q, want windows-store", found[0].Source)
	}
}

// Discover runs every source and records what it finds; a source error is
// collected but does not stop the others.
func TestDiscoverMergesSourcesAndIsBestEffort(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.crt"), []byte(cert1))

	tok := softtoken.New()
	_ = tok.ImportCertificate("leaf", []byte{1}, []byte(cert2))

	sink := discovery.NewMemorySink()
	rep := discovery.Discover(context.Background(), []discovery.Source{
		discovery.NewFilesystemSource(dir),
		discovery.NewPKCS11Source("hsm0", tok),
		failingSource{},
	}, sink)

	if rep.Discovered != 2 {
		t.Errorf("discovered %d, want 2", rep.Discovered)
	}
	if len(rep.Errors) != 1 {
		t.Errorf("expected 1 collected source error, got %d: %v", len(rep.Errors), rep.Errors)
	}
	if len(sink.All()) != 2 {
		t.Errorf("sink recorded %d, want 2", len(sink.All()))
	}
}

type failingSource struct{}

func (failingSource) Kind() string { return "broken" }
func (failingSource) Discover(context.Context) ([]discovery.Found, error) {
	return nil, errors.New("token unreadable")
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
