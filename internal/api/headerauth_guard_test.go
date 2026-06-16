package api_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func apiRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = <root>/internal/api/headerauth_guard_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// TestProductionBinaryDoesNotLinkHeaderTrust is the B1 "not-linked" guard,
// mirroring the AN-4 signer static check: the insecure, header-trusting principal
// resolver exists only for tests and must be dead-code-eliminated from the
// shipped control-plane binary, because it is reachable only through the
// test-only WithInsecureHeaderResolver option, which production never calls.
func TestProductionBinaryDoesNotLinkHeaderTrust(t *testing.T) {
	if testing.Short() {
		t.Skip("builds cmd/trstctl; skipped in -short")
	}
	root := apiRepoRoot(t)
	bin := filepath.Join(t.TempDir(), "trstctl")
	build := exec.Command("go", "build", "-o", bin, "./cmd/trstctl")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/trstctl: %v\n%s", err, out)
	}
	nm := exec.Command("go", "tool", "nm", bin)
	nm.Dir = root
	out, err := nm.CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm: %v\n%s", err, out)
	}
	syms := string(out)
	for _, banned := range []string{"insecureHeaderResolver", "WithInsecureHeaderResolver"} {
		if strings.Contains(syms, banned) {
			t.Errorf("production binary links the header-trust path: symbol %q is present (it must be DCE'd)", banned)
		}
	}
	// Sanity: nm produced real symbols for the api package, so the absence above
	// is meaningful and not an empty/failed dump.
	if !strings.Contains(syms, "trstctl.com/trstctl/internal/api.") {
		t.Fatalf("nm output did not contain any internal/api symbols; the guard is not meaningful:\n%.500s", syms)
	}
}
