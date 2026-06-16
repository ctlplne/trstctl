package cloudhttp_test

// This guard enforces CODE-006's invariant: every cloud provider family routes its
// JSON/REST round-trip through internal/cloudhttp, and none reintroduces a bespoke
// http round-trip. It is a source-level guard (it parses the provider packages'
// imports with go/parser and scans their source) so it fails fast in CI the moment a
// provider regresses to copy-pasted request/response plumbing — the exact duplication
// CODE-006 consolidated. The behavioural proof that the shared client is genuinely
// wired (a centrally-applied bound observed *through* a provider) lives in the
// per-provider tests and in observed_central_bound_test.go; this guard proves the
// *structure* stays shared.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// migratedProviders are the provider packages CODE-006 folds onto cloudhttp. The path
// is relative to this test file's directory (internal/cloudhttp). Keep this list in
// sync with the families that do a cloud JSON/REST round-trip; a new provider added
// here without adopting cloudhttp will fail the guard.
var migratedProviders = []struct {
	dir  string // relative to internal/cloudhttp
	file string // the package file carrying the round-trip
}{
	{"../kms/awskms", "awskms.go"},
	{"../kms/gcpkms", "gcpkms.go"},
	{"../kms/azurekv", "azurekv.go"},
	{"../dns/cloudflare", "cloudflare.go"},
	{"../dns/ns1", "ns1.go"},
	{"../dns/azuredns", "azuredns.go"},
	{"../dns/googledns", "googledns.go"},
	{"../dns/ultradns", "ultradns.go"},
	{"../dns/acmedns", "acmedns.go"},
	{"../dns/route53", "route53.go"},
	{"../dns/akamai", "akamai.go"},
}

const cloudhttpImport = "trstctl.com/trstctl/internal/cloudhttp"

// TestProvidersImportAndCallCloudhttp asserts every migrated provider imports
// internal/cloudhttp and calls cloudhttp.JSON for its round-trip — i.e. it actually
// uses the shared client rather than a bespoke http.Client.
func TestProvidersImportAndCallCloudhttp(t *testing.T) {
	for _, p := range migratedProviders {
		t.Run(p.dir, func(t *testing.T) {
			path := filepath.Join(p.dir, p.file)
			src := readFile(t, path)

			if !importsPath(t, p.file, src, cloudhttpImport) {
				t.Fatalf("%s does not import %s — it is not on the shared client (CODE-006)", p.file, cloudhttpImport)
			}
			// The round-trip is the shared client: cloudhttp.JSON sends the request,
			// bounds the read, normalises non-2xx, and decodes/drains. Every provider
			// invokes it exactly as `cloudhttp.JSON(`.
			if !strings.Contains(string(src), "cloudhttp.JSON(") {
				t.Fatalf("%s does not call cloudhttp.JSON — its round-trip is not the shared client (CODE-006)", p.file)
			}
		})
	}
}

// TestProvidersHaveNoBespokeRoundTrip asserts no migrated provider still hand-rolls
// the round-trip cloudhttp now owns: it must not call doer.Do directly, and it must
// not bound the body with the literal LimitReader caps the providers used to repeat.
// A provider that regresses to copy-pasted plumbing trips this guard.
func TestProvidersHaveNoBespokeRoundTrip(t *testing.T) {
	for _, p := range migratedProviders {
		t.Run(p.dir, func(t *testing.T) {
			src := string(readFile(t, filepath.Join(p.dir, p.file)))

			// A direct *.doer.Do( call is the bespoke send cloudhttp replaced. (The
			// providers keep an injectable HTTPDoer seam, but it is now handed to
			// cloudhttp.JSON, never called here.)
			if strings.Contains(src, ".doer.Do(") {
				t.Errorf("%s calls .doer.Do( directly — reintroduced a bespoke round-trip (CODE-006); send via cloudhttp.JSON", p.file)
			}
			// The hand-repeated bounded reads cloudhttp centralised. Their reappearance
			// means a provider is normalising errors / draining bodies on its own again.
			for _, lit := range []string{"io.LimitReader(resp.Body, 4096)", "io.LimitReader(resp.Body, 1<<20)"} {
				if strings.Contains(src, lit) {
					t.Errorf("%s contains the bespoke bound %q — that read is now cloudhttp's (CODE-006)", p.file, lit)
				}
			}
		})
	}
}

func readFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

// importsPath parses just the imports of src (named name for diagnostics) and reports
// whether it imports path.
func importsPath(t *testing.T, name string, src []byte, path string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse imports of %s: %v", name, err)
	}
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == path {
			return true
		}
	}
	return false
}
