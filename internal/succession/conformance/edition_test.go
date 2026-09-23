// SPDX-License-Identifier: BUSL-1.1

package conformance

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
			t.Fatal("go.mod not found above the test working directory")
		}
		dir = parent
	}
}

// pcasPackageDirs are the PCAS package trees. Every path is under internal/ with
// a BUSL-1.1 header (TestEdition_AllPCASPackagesAreCore) and the core-only build
// links the family (TestEdition_CoreBuildLinksPCASAndNoEE): since 2026-09-20 PCAS
// is part of the licensed work, not an ee/ feature.
var pcasPackageDirs = []string{"internal/succession", "internal/rpverify", "internal/translog"}

// TestEdition_CoreBuildLinksPCASAndNoEE pins the editions gate as a test: the
// dependency graph of the core-only (`trstctl_core`) build of cmd/trstctl links
// ZERO ee/ packages and DOES link internal/succession. This is the same proof as
// `make editions-gate`, asserted here so it runs in CI as a unit.
func TestEdition_CoreBuildLinksPCASAndNoEE(t *testing.T) {
	goBin := filepath.Join(goRoot(t), "bin", "go")
	cmd := exec.Command(goBin, "list", "-tags", "trstctl_core", "-deps", "trstctl.com/trstctl/cmd/trstctl") // #nosec G204 -- goBin is derived from runtime.GOROOT and every argument is fixed (CWE-78).
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list (core build graph): %v\n%s", err, out)
	}
	linked := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "trstctl.com/trstctl/ee/") {
			t.Fatalf("core-only build links an ee/ (edition) package: %q", line)
		}
		if line == "trstctl.com/trstctl/internal/succession" {
			linked = true
		}
	}
	if !linked {
		t.Fatal("core-only build does not link internal/succession; PCAS must attach in every build")
	}
}

// TestEdition_AllPCASPackagesAreCore proves every PCAS package path is under
// internal/ and every PCAS source file carries the BUSL-1.1 SPDX header: the
// family is part of the licensed work, fleet-wide, with no file left under the
// proprietary or the MPL header.
func TestEdition_AllPCASPackagesAreCore(t *testing.T) {
	root := moduleRoot(t)
	// Walk and read the PCAS trees through an os.Root handle on the module root. Every
	// path is resolved by the kernel relative to that handle, so a symlink or ".."
	// component inside a package tree cannot make this gate read (or report on) a file
	// outside the module.
	modRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("open module root %s: %v", root, err)
	}
	defer func() { _ = modRoot.Close() }()
	for _, d := range pcasPackageDirs {
		if !strings.HasPrefix(d, "internal/") {
			t.Fatalf("PCAS package tree %q is not under internal/", d)
		}
		err := fs.WalkDir(modRoot.FS(), d, func(path string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, err := modRoot.ReadFile(path)
			if err != nil {
				return err
			}
			first := firstNonBlankLine(string(b))
			if first != "// SPDX-License-Identifier: BUSL-1.1" {
				t.Fatalf("PCAS file %s: first line %q is not the BUSL-1.1 SPDX header",
					filepath.Join(root, path), first)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", d, err)
		}
	}
}

func firstNonBlankLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// goRoot returns the toolchain's GOROOT by asking the go command rather than
// reading runtime.GOROOT(), which is deprecated since Go 1.24: it reports the
// root used at BUILD time, which is meaningless once a test binary is copied to
// another machine.
//
// It FAILS rather than skips when the toolchain cannot be located. This is a
// conformance check: a skipped edition check would report green while proving
// nothing about the boundary
// it exists to police.
func goRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOROOT").Output() // #nosec G204 -- fixed argv, no user input (CWE-78)
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		t.Fatal("go env GOROOT is empty")
	}
	return root
}
