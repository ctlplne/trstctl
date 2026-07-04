// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAISurfacePlacementDecisionIsRecorded(t *testing.T) {
	body := read(t, "design/ai-surface-placement.md")
	low := strings.ToLower(body)
	for _, want := range []string{
		"decision: keep core",
		"internal/rca",
		"internal/aimodel",
		"internal/api/aisurface.go",
		"internal/mcpserver",
		"importer evidence",
		"go list -deps -tags trstctl_core ./internal/rca ./internal/aimodel ./internal/mcpserver",
	} {
		if !strings.Contains(low, want) {
			t.Errorf("AI surface placement decision missing %q", want)
		}
	}
}

func TestAISurfaceCorePackagesDoNotImportEE(t *testing.T) {
	for _, root := range []string{"../internal/rca", "../internal/aimodel", "../internal/mcpserver", "../internal/api"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			if root == "../internal/api" {
				name := filepath.Base(path)
				if !strings.HasPrefix(name, "aisurface") {
					return nil
				}
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(body), "trstctl.com/trstctl/ee") {
				t.Errorf("%s imports ee; AI surface placement decision says it stays core", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}
