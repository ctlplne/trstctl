// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestEveryMandatoryParserFamilyHasPropertyInvariants is intentionally separate
// from TestEveryUntrustedParserIsFuzzed. Fuzzing asks “can hostile bytes crash the
// decoder?” Property testing asks “does generated valid/invalid structure keep the
// parser's semantic promises?” One green denominator must never substitute for the
// other (AUD-81 / root AGENTS.md §6).
func TestEveryMandatoryParserFamilyHasPropertyInvariants(t *testing.T) {
	families := []struct {
		name  string
		dir   string
		tests []string
	}{
		{
			name: "policy",
			dir:  "../policy",
			tests: []string{
				"TestPolicyInvariantsBaseModule",
				"TestPolicyNeverPanicsOnArbitraryInput",
				"TestPolicyProfileMonotonicity",
			},
		},
		{
			name: "EST",
			dir:  "../protocols/est",
			tests: []string{
				"TestParseEnrollBodyRoundTrip",
				"TestParseEnrollBodyNeverBothOrPanic",
			},
		},
		{
			name: "ACME",
			dir:  "../protocols/acme",
			tests: []string{
				"TestPropertyACMEOrderRoundTripAndWireNormalization",
				"TestPropertyACMEOrderRejectsInvalidCrossFields",
			},
		},
		{
			name: "SCEP/CMS",
			dir:  ".",
			tests: []string{
				"TestPropertySCEPRequestResponseRoundTrip",
				"TestPropertySCEPRejectsCorruptedCSR",
			},
		},
		{
			name: "X.509/PKCS#10",
			dir:  ".",
			tests: []string{
				"TestPropertyX509CSRAndCertificateCanonicalization",
				"TestPropertyX509RejectsSignatureAndExtensionViolations",
			},
		},
		{
			name: "SSH",
			dir:  "sshkeys",
			tests: []string{
				"TestPropertySSHAuthorizedKnownHostsAndPublicKeyRoundTrips",
				"TestPropertySSHParsersRejectOrReturnWholeRecords",
			},
		},
	}

	for _, family := range families {
		family := family
		t.Run(family.name, func(t *testing.T) {
			found, importsQuick := propertyTestsInDir(t, family.dir)
			for _, name := range family.tests {
				if !found[name] {
					t.Errorf("mandatory %s property invariant %s is missing from %s (AUD-81)", family.name, name, family.dir)
				}
			}
			if !importsQuick {
				t.Errorf("mandatory %s property suite in %s does not import testing/quick", family.name, family.dir)
			}
		})
	}
}

func propertyTestsInDir(t *testing.T, dir string) (map[string]bool, bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read property-test directory %q: %v", dir, err)
	}
	found := map[string]bool{}
	importsQuick := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse property-test imports %s: %v", path, err)
		}
		for _, imp := range file.Imports {
			pathValue, err := strconv.Unquote(imp.Path.Value)
			if err == nil && pathValue == "testing/quick" {
				importsQuick = true
			}
		}

		file, err = parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse property-test declarations %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				found[fn.Name.Name] = true
			}
		}
	}
	return found, importsQuick
}
