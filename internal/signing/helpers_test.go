package signing_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// repoRoot returns the module root, derived from this test file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = <root>/internal/signing/helpers_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// buildSigner compiles cmd/trstctl-signer to a temp path and returns it.
func buildSigner(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "trstctl-signer")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/trstctl-signer")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build trstctl-signer: %v\n%s", err, out)
	}
	return bin
}
