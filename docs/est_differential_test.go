package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileContains reports whether the file at rel (relative to docs/) contains sub.
func fileContains(t *testing.T, rel, sub string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return strings.Contains(string(b), sub)
}

// anyTestFileHas reports whether any *_test.go file directly under dir contains sub.
func anyTestFileHas(t *testing.T, dir, sub string) bool {
	t.Helper()
	entries, err := os.ReadDir(filepath.FromSlash(dir))
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.FromSlash(dir + "/" + e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), sub) {
			return true
		}
	}
	return false
}

// TestESTReferenceDifferentialIsHonestAndCodeBound is the reality-bound disclosure
// for TEST-002: the EST reference-differential claim in limitations.md must match the
// code, in both directions.
//
//   - The "EST runs a differential against OpenSSL on every make test" claim is true
//     only while a REAL, non-skipped OpenSSL differential exists in the est package —
//     the prior stub merely t.Log-ed. So the test asserts TestESTDifferentialVsOpenSSL
//     (and its openssl pkcs7/verify drive) is present; if it is ever removed, the
//     claim would become an over-claim and this fails loudly.
//   - The SPIFFE Workload-API stock-client claim is true only while internal/server
//     declares tests that use real go-spiffe and spiffe-helper clients against the
//     served UDS, and while CI requires those tests.
func TestESTReferenceDifferentialIsHonestAndCodeBound(t *testing.T) {
	// (1) Code anchor: the EST package has a real OpenSSL differential (not a stub).
	// It must drive openssl's own pkcs7 parser AND chain verify — independent code.
	const estDir = "../internal/protocols/est"
	if !anyTestFileHas(t, estDir, "TestESTDifferentialVsOpenSSL") {
		t.Fatal("the EST OpenSSL differential (TestESTDifferentialVsOpenSSL) is gone; limitations.md claims EST has a real external-reference differential — restore it or correct the disclosure (TEST-002)")
	}
	for _, marker := range []string{`"pkcs7"`, `"verify"`} {
		if !anyTestFileHas(t, estDir, marker) {
			t.Errorf("the EST differential should drive openssl %s (an independent RFC 7030 implementation); the claim rests on it (TEST-002)", marker)
		}
	}

	// (2) limitations.md states the honest EST/ACME differential posture.
	lim := strings.ToLower(read(t, "limitations.md"))
	for _, marker := range []string{"openssl", "pebble", "differential"} {
		if !strings.Contains(lim, marker) {
			t.Errorf("limitations.md should describe the protocol reference differentials (missing %q) (TEST-002)", marker)
		}
	}

	// (3) Reality-bound SPIFFE stock-client proof. Comments or vendored protobufs are
	// not enough; the served server must be driven by stock client code and CI must
	// require that path.
	for _, testName := range []string{
		"TestServedSPIFFEGoSpiffeClient",
		"TestServedSPIFFESpiffeHelperWritesSVID",
	} {
		if !repoDeclaresTestUnder(t, "../internal/server", testName) {
			t.Fatalf("internal/server must declare %s; limitations.md claims SPIFFE has served stock-client conformance (INTEROP-002)", testName)
		}
	}
	servedSPIFFE := read(t, "../internal/server/protocols_served_spiffe_ssh_test.go")
	for _, marker := range []string{
		"runServedGoSpiffeClient(t, \"unix://\"+socket)",
		"TRSTCTL_REQUIRE_GOSPIFFE",
		"spiffe-helper",
		"TRSTCTL_REQUIRE_SPIFFE_HELPER",
		"servedReadPEMCert(t, svidPath)",
	} {
		if !strings.Contains(servedSPIFFE, marker) {
			t.Errorf("served SPIFFE stock-client tests must contain %q (INTEROP-002)", marker)
		}
	}
	goSpiffeClient := read(t, "../internal/server/testdata/gospiffe-client/main.go")
	for _, marker := range []string{
		"github.com/spiffe/go-spiffe/v2/workloadapi",
		"github.com/spiffe/go-spiffe/v2/spiffeid",
		"workloadapi.FetchX509Context",
		"workloadapi.WithAddr(os.Args[1])",
	} {
		if !strings.Contains(goSpiffeClient, marker) {
			t.Errorf("testdata go-spiffe client must contain %q (INTEROP-002)", marker)
		}
	}
	if !strings.Contains(read(t, "../internal/server/testdata/gospiffe-client/go.mod"), "github.com/spiffe/go-spiffe/v2 v2.8.1") {
		t.Error("testdata/gospiffe-client/go.mod must keep the pinned go-spiffe dependency used by TestServedSPIFFEGoSpiffeClient (INTEROP-002)")
	}
	if strings.Contains(lim, "no spiffe workload-api differential") {
		t.Error("limitations.md still says there is no SPIFFE Workload-API differential, but served go-spiffe/spiffe-helper tests now exist (INTEROP-002)")
	}
	for _, marker := range []string{"go-spiffe", "spiffe-helper", "served stock-client differential"} {
		if !strings.Contains(lim, marker) {
			t.Errorf("limitations.md must describe the served SPIFFE stock-client proof (missing %q) (INTEROP-002)", marker)
		}
	}
	if !strings.Contains(lim, "libest") {
		t.Error("limitations.md must describe the libest estclient differential (TEST-002)")
	}
	if strings.Contains(lim, "libest") && strings.Contains(lim, "opt-in/local only") {
		t.Error("limitations.md still says the libest estclient differential is opt-in/local only, but INTEROP-102 requires the CI job")
	}
	ci := read(t, "../.github/workflows/ci.yml")
	for _, marker := range []string{
		"est-libest-conformance:",
		"est client conformance (libest estclient)",
		"bash scripts/ci/install-libest.sh",
		"EST_LIBEST: ${{ runner.temp }}/libest/bin/estclient",
		"TRSTCTL_REQUIRE_LIBEST: \"1\"",
		"libest estclient simpleenroll against served EST endpoint",
		"TestESTDifferentialVsOpenSSL|TestServedESTLibestSimpleEnroll",
		"est-libest-simpleenroll-transcripts",
		"spiffe-workloadapi-conformance:",
		"spiffe workload api conformance (go-spiffe + helper)",
		"go install github.com/spiffe/spiffe-helper/cmd/spiffe-helper@v0.11.0",
		"TRSTCTL_REQUIRE_GOSPIFFE: \"1\"",
		"TRSTCTL_REQUIRE_SPIFFE_HELPER: \"1\"",
		"TestServedSPIFFEGoSpiffeClient|TestServedSPIFFESpiffeHelperWritesSVID",
	} {
		if !strings.Contains(ci, marker) {
			t.Errorf("ci.yml must require the served EST/SPIFFE stock-client marker %q (INTEROP-001/002)", marker)
		}
	}
	script := read(t, "../scripts/ci/install-libest.sh")
	for _, marker := range []string{
		"a464ba8a66717419ba71d289ef82c7b2315b2006",
		"2e5c46610f6a3c12c1916c8a84de77421a88c9722e776e862a716f4a48220f2a",
		"--enable-client-only",
		"--disable-safec",
		"FIPS_mode",
		"example_ossl_dump_ssl_errors",
		"-fcommon",
	} {
		if !strings.Contains(script, marker) {
			t.Errorf("install-libest.sh must keep pinned libest build marker %q (INTEROP-102)", marker)
		}
	}
	branchProtection := read(t, "branch-protection.md")
	if !strings.Contains(branchProtection, "est client conformance (libest estclient)") {
		t.Error("branch-protection.md must list the required libest EST conformance job (INTEROP-102)")
	}
	if !strings.Contains(branchProtection, "spiffe workload api conformance (go-spiffe + helper)") {
		t.Error("branch-protection.md must list the required SPIFFE go-spiffe/spiffe-helper conformance job (INTEROP-002)")
	}
	if !fileContains(t, "limitations.md", "EXC-WIRE-02") {
		t.Error("limitations.md must link the wire-in epic EXC-WIRE-02 for the outstanding reference differentials (TEST-002)")
	}
}

func repoDeclaresTestUnder(t *testing.T, root, name string) bool {
	t.Helper()
	needle := "func " + name + "("
	var found bool
	_ = filepath.Walk(filepath.FromSlash(root), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || found || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), needle) {
			found = true
		}
		return nil
	})
	return found
}
