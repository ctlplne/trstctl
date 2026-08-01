// SPDX-License-Identifier: MPL-2.0

package signing_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSignerBinaryFailsClosedUnlessNonLinuxDevOverride proves SIGNER-002 at the
// shipped process boundary: unsupported non-Linux hardening is not a library
// footnote; the trstctl-signer binary must refuse it unless the operator passes
// an explicit development-only override, and the control plane may pass that
// override only from config.
func TestSignerBinaryFailsClosedUnlessNonLinuxDevOverride(t *testing.T) {
	root := repoRoot(t)
	signerMain := readSource(t, root, "cmd/trstctl-signer/main.go")
	runPath := readSource(t, root, "internal/server/run.go")

	for _, want := range []string{
		`"allow-insecure-dev-nonlinux"`,
		"signing.ErrUnsupportedHardening",
		"errors.Is(err, signing.ErrUnsupportedHardening)",
	} {
		if !strings.Contains(signerMain, want) {
			t.Fatalf("cmd/trstctl-signer/main.go missing %q; non-Linux signer hardening can silently degrade", want)
		}
	}
	for _, want := range []string{
		"AllowInsecureDevNonLinux",
		`"--allow-insecure-dev-nonlinux"`,
	} {
		if !strings.Contains(runPath, want) {
			t.Fatalf("internal/server/run.go missing %q; child signer dev override is not explicit in config", want)
		}
	}
}

// TestNonLinuxHardeningSourceFailsClosed guards the fallback file directly. A
// return-nil implementation is the regression the audit found.
func TestNonLinuxHardeningSourceFailsClosed(t *testing.T) {
	src := readSource(t, repoRoot(t), "internal/signing/harden_other.go")
	if strings.Contains(src, "func Harden() error { return nil }") {
		t.Fatal("harden_other.go still makes non-Linux signer hardening a silent no-op")
	}
	if !strings.Contains(src, "ErrUnsupportedHardening") {
		t.Fatal("harden_other.go must return ErrUnsupportedHardening so callers can fail closed")
	}
}

func readSource(t *testing.T, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}
