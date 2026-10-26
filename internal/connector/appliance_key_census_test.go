// SPDX-License-Identifier: BUSL-1.1

package connector_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// The appliance-key census must match the code in both directions (A122). A
// family listed without the method would accept key_generation=appliance and
// then fail every renewal on the relay; one that implements it unlisted would
// never be offered the mode, and the parity surface would keep reporting the
// device-generated CSR gate as outstanding for a family that meets it.
func TestApplianceKeyCensusMatchesTheImplementations(t *testing.T) {
	t.Parallel()
	declared := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(entry.Name(), "*.go"))
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				continue
			}
			for _, decl := range parsed.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "GenerateApplianceKey" {
					declared[familyForPackageDir(entry.Name())] = true
				}
			}
		}
	}
	listed := connector.ApplianceKeyFamilies()
	for name := range declared {
		if !slices.Contains(listed, name) {
			t.Errorf("connector %q generates keys on the appliance but is not in the appliance-key census", name)
		}
	}
	for _, name := range listed {
		if !declared[name] {
			t.Errorf("the appliance-key census lists %q, but its package declares no GenerateApplianceKey", name)
		}
		if !slices.Contains(connector.RelayVantageFamilies(), name) {
			t.Errorf("appliance-key family %q is not relay-executed; only a relay asks an appliance for its key", name)
		}
	}
}

// The parity surface reports the device-generated CSR gate met exactly for
// the families in the census, and outstanding for the other capable families.
func TestDeviceCSRGateFollowsTheApplianceKeyCensus(t *testing.T) {
	t.Parallel()
	for _, family := range []string{"f5", "netscaler", "a10", "cisco", "paloalto"} {
		status := connector.ParityStatusFor(family)
		outstanding := slices.Contains(status.Outstanding, connector.ParityGateDeviceCSR)
		if connector.ApplianceKeyFamily(family) == outstanding {
			t.Errorf("%s: appliance-key census %v but device_generated_csr outstanding %v",
				family, connector.ApplianceKeyFamily(family), outstanding)
		}
	}
}

func TestApplianceKeyObjectNameIsFixedPerJob(t *testing.T) {
	t.Parallel()
	if got := connector.ApplianceKeyObjectName("0F3C9A71-2D4E-4B8A-9C1D-5E6F7A8B9C0D", 77); got != "trstctl-0f3c9a71-j77" {
		t.Fatalf("object name = %q", got)
	}
	for _, empty := range []string{
		connector.ApplianceKeyObjectName("", 77), connector.ApplianceKeyObjectName("ab-12", 77),
		connector.ApplianceKeyObjectName("0f3c9a71-2d4e-4b8a-9c1d-5e6f7a8b9c0d", 0),
	} {
		if empty != "" {
			t.Fatalf("an object name without a destination or job = %q, want none", empty)
		}
	}
}
