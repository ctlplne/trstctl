package projections_test

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/agent/destination/certstore"
	"trstctl.com/trstctl/internal/agent/destination/softtoken"
	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	dcert1 = `-----BEGIN CERTIFICATE-----
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
	dcert2 = `-----BEGIN CERTIFICATE-----
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
	dcert3 = `-----BEGIN CERTIFICATE-----
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
	dcert4 = `-----BEGIN CERTIFICATE-----
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

func dfp(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	return crypto.SHA256Hex(block.Bytes)
}

// TestAgentDiscoveryReconcilesAllSourcesIntoInventory is the S6.2 acceptance:
// certificates across all four local sources — filesystem, PKCS#11, Windows
// store, and Kubernetes Secrets — are discovered and reconciled into the
// inventory (S4.1), deduplicated by fingerprint.
func TestAgentDiscoveryReconcilesAllSourcesIntoInventory(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Filesystem: cert1 (unique here) and cert4 (also served via Kubernetes, to
	// exercise cross-source dedup).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.crt"), []byte(dcert1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "shared.crt"), []byte(dcert4), 0o644); err != nil {
		t.Fatal(err)
	}

	// PKCS#11: cert2.
	tok := softtoken.New()
	_ = tok.ImportCertificate("app", []byte{1}, []byte(dcert2))

	// Windows store: cert3.
	mem := certstore.NewMemory()
	_ = mem.AddCertificate(destination.StoreRef{Location: destination.LocalMachine, Name: "MY"}, "web", []byte(dcert3))

	// Kubernetes: cert4 in a TLS Secret.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"items":[{"metadata":{"name":"web-tls"},"type":"kubernetes.io/tls","data":{"tls.crt":%q}}]}`,
			base64.StdEncoding.EncodeToString([]byte(dcert4)))
	}))
	defer srv.Close()
	kc := k8s.New(srv.URL, "token", "apps", srv.Client())

	rep := discovery.Discover(ctx, []discovery.Source{
		discovery.NewFilesystemSource(dir),
		discovery.NewPKCS11Source("hsm0", tok),
		discovery.NewWindowsStoreSource("MY", mem),
		discovery.NewKubernetesSource("apps", kc),
	}, discovery.NewStoreSink(s, tenantA))

	if len(rep.Errors) != 0 {
		t.Fatalf("unexpected discovery errors: %v", rep.Errors)
	}
	if rep.Discovered != 5 { // cert1+cert4 (fs), cert2 (token), cert3 (store), cert4 (k8s)
		t.Fatalf("recorded %d discoveries, want 5", rep.Discovered)
	}

	// All four distinct certificates are in the inventory.
	for i, c := range []string{dcert1, dcert2, dcert3, dcert4} {
		if certByFingerprint(t, ctx, s, dfp(t, c)).Fingerprint == "" {
			t.Errorf("cert %d not reconciled into inventory", i+1)
		}
	}
	// The certificate seen twice (filesystem + Kubernetes) is one row, not two.
	if n := countByFingerprint(t, ctx, s, dfp(t, dcert4)); n != 1 {
		t.Errorf("cross-source duplicate produced %d rows, want 1 (dedup by fingerprint)", n)
	}

	// Each discovery is tagged with the source that found it.
	sources := map[string]bool{}
	for _, c := range listCerts(t, ctx, s) {
		sources[c.Source] = true
	}
	for _, want := range []string{discovery.SourceFilesystem, discovery.SourcePKCS11, discovery.SourceWindowsCert, discovery.SourceKubernetes} {
		if !sources[want] {
			t.Errorf("no inventory row tagged source %q", want)
		}
	}
}
