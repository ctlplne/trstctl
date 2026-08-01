// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
			body, err := os.ReadFile(path) // #nosec G122 G304 -- test reads its own fixture/tempdir path (CWE-22, CWE-367)
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
