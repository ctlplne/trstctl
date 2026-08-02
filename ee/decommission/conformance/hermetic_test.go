// SPDX-License-Identifier: LicenseRef-trstctl-EE

package conformance

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// HERMETIC-001 - every test under ee/ must resolve its inputs from inside the
// module. A test that reads a sibling of the module root cannot reproduce for a
// cloner who does not have that sibling, so a local pass and a CI pass stop
// meaning the same thing; and the escaped path ships the author's private
// directory layout inside a tracked file. Vendor the input under testdata/ or
// derive it from tracked source instead.
var (
	hermeticRootEscape  = regexp.MustCompile(`filepath\.(Join|Abs)\(\s*(root|moduleRoot\(t\))\s*,\s*"\.\."`)
	hermeticMachinePath = regexp.MustCompile(`"/(Users|home)/`)
)

func TestHermetic_EESourcesResolveInputsInsideModule(t *testing.T) {
	root := moduleRoot(t)
	eeDir := filepath.Join(root, "ee")
	err := filepath.WalkDir(eeDir, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := readWalkedUnder(eeDir, path)
		if err != nil {
			return err
		}
		text := string(b)
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if hit := hermeticRootEscape.FindString(text); hit != "" {
			t.Fatalf("HERMETIC-001: %s reads outside the module root via %q; vendor the input under testdata/ or derive it from tracked source", rel, hit)
		}
		if hit := hermeticMachinePath.FindString(text); hit != "" {
			t.Fatalf("HERMETIC-001: %s hardcodes an absolute machine path starting %q; tracked ee/ source must not carry a local filesystem layout", rel, hit)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk ee tree: %v", err)
	}
}
