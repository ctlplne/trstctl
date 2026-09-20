// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"trstctl.com/trstctl/internal/signing"
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
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/trstctl-signer") // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build trstctl-signer: %v\n%s", err, out)
	}
	return bin
}

func devServeOptions() signing.ServeOptions {
	return signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"}
}

func devSignerArgs(extra ...string) []string {
	if runtime.GOOS == "linux" {
		return extra
	}
	return append([]string{"--allow-insecure-dev-nonlinux"}, extra...)
}
