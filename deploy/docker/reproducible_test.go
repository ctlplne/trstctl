package docker

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// moduleRoot walks up from the test's working directory to the module root (the
// directory containing go.mod).
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestControlPlaneBinaryBuildsReproducibly encodes "images build reproducibly":
// the control-plane binary, built twice with the shipped reproducible flags (CGO
// disabled, trimmed paths, a pinned/empty build id, and no VCS stamping), is
// byte-for-byte identical. The container image is a thin distroless wrapper over
// this binary, so a reproducible binary is the foundation of a reproducible
// image.
func TestControlPlaneBinaryBuildsReproducibly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	root := moduleRoot(t)

	// The same reproducible flags the Dockerfile and Makefile use, with fixed
	// version metadata so the test isolates toolchain determinism.
	const ldflags = "-s -w -buildid= " +
		"-X trstctl.com/trstctl/internal/buildinfo.version=test " +
		"-X trstctl.com/trstctl/internal/buildinfo.commit=test " +
		"-X trstctl.com/trstctl/internal/buildinfo.date=2026-01-01T00:00:00Z"

	build := func(out string) {
		cmd := exec.Command(goBin, "build", "-trimpath", "-buildvcs=false",
			"-ldflags", ldflags, "-o", out, "./cmd/trstctl")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, b)
		}
	}

	dir := t.TempDir()
	a := filepath.Join(dir, "trstctl.a")
	b := filepath.Join(dir, "trstctl.b")
	build(a)
	build(b)

	if !bytes.Equal(readFile(t, a), readFile(t, b)) {
		t.Fatal("control-plane binary is not reproducible: two builds differ")
	}
}
