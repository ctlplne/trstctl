// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// pcasPackageDirs are the PCAS package trees. Every path is under ee/ (proven by
// TestEdition_AllPCASPackagesAreEE) and none is linked by the core-only build (proven
// by TestEdition_CoreBuildLinksNoPCAS).
var pcasPackageDirs = []string{"ee/succession", "ee/rpverify", "ee/translog"}

// TestEdition_CoreBuildLinksNoPCAS pins the G6 editions gate as a test: the dependency
// graph of the core-only (`trstctl_core`) build of cmd/trstctl links ZERO ee/ packages
// — in particular none of the PCAS packages. This is the same proof as `make
// editions-gate`, asserted here so it runs in CI as a unit.
func TestEdition_CoreBuildLinksNoPCAS(t *testing.T) {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBin, "list", "-tags", "trstctl_core", "-deps", "trstctl.com/trstctl/cmd/trstctl")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list (core build graph): %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "trstctl.com/trstctl/ee/") {
			t.Fatalf("core-only build links an ee/ (edition) package: %q", line)
		}
	}
}

// TestEdition_AllPCASPackagesAreEE proves every PCAS package path is under ee/ and
// every PCAS source file carries the proprietary SPDX header (the PCAS-07 §1.6 license
// decision, honored fleet-wide: no PCAS file is MPL-2.0).
func TestEdition_AllPCASPackagesAreEE(t *testing.T) {
	root := moduleRoot(t)
	for _, d := range pcasPackageDirs {
		if !strings.HasPrefix(d, "ee/") {
			t.Fatalf("PCAS package tree %q is not under ee/", d)
		}
		err := filepath.WalkDir(filepath.Join(root, d), func(path string, de os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			first := firstNonBlankLine(string(b))
			if first != "// SPDX-License-Identifier: LicenseRef-trstctl-EE" {
				t.Fatalf("PCAS file %s: first line %q is not the LicenseRef-trstctl-EE SPDX header", path, first)
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
