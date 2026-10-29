// SPDX-License-Identifier: BUSL-1.1
package pluginhost

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Compile the real production package, not its test-only method set. A compiler
// failure counts only when it names each forbidden raw method explicitly.
func TestProductionHostRejectsRawAdmissionAtCompileTime(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	module := fmt.Sprintf("module trstctl.com/trstctl/rawpathprobe\n\ngo 1.26.0\n\nrequire trstctl.com/trstctl v0.0.0\nreplace trstctl.com/trstctl => %q\n", root)
	source := []byte("package probe\nimport(\"context\";\"trstctl.com/trstctl/internal/pluginhost\")\nfunc raw(h *pluginhost.Host){_,_=h.Load(context.Background(),nil,pluginhost.NewGrant());_=h.Conformance(context.Background(),nil);_=h.ConformanceUnderGrant(context.Background(),nil,pluginhost.NewGrant())}\n")
	for name, data := range map[string][]byte{"go.mod": []byte(module), "probe.go": source} {
		if err := os.WriteFile(filepath.Join(fixture, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	sums, err := os.ReadFile(filepath.Join(root, "go.sum")) // #nosec G304 -- fixed repository checksum manifest, no external path input (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture, "go.sum"), sums, 0600); err != nil { // #nosec G703 -- writes fixed manifest name only under the owned t.TempDir (CWE-22).
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, tags string
		reject     bool
	}{{"production", "", true}, {"core", "trstctl_core", true}, {"conformance", "trstctl_conformance", false}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "go", "build", "-mod=mod", "-buildvcs=false", "-tags="+tc.tags, "-o", filepath.Join(fixture, tc.name+".a"), ".") // #nosec G204 -- fixed go build command, literal tag table, owned temp output; no shell or user arguments (CWE-78).
			command.Dir = fixture
			command.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "GOPROXY=off", "GOPRIVATE=github.com/ctlplne/*,trstctl.com/*", "GONOPROXY=github.com/ctlplne/*,trstctl.com/*", "GONOSUMDB=github.com/ctlplne/*,trstctl.com/*")
			output, err := command.CombinedOutput()
			if tc.reject {
				if err == nil {
					t.Fatal("production package exposes unsigned Load and conformance execution")
				}
				for _, method := range []string{"Load", "Conformance", "ConformanceUnderGrant"} {
					if !strings.Contains(string(output), "h."+method+" undefined") {
						t.Fatalf("failure did not prove missing %s: %v\n%s", method, err, output)
					}
				}
			} else if err != nil {
				t.Fatalf("explicit conformance build cannot use its raw test API: %v\n%s", err, output)
			}
		})
	}
}
