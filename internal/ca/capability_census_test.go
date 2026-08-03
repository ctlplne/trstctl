// SPDX-License-Identifier: MPL-2.0

package ca_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/ca"
)

// The capability matrix must match the code, in both directions (epic R2).
//
// A matrix that drifts from the binary is worse than no matrix, because an
// operator plans around it — and the moment they plan around it is an incident,
// when a compromised key needs revoking now. So the claim is checked against
// the source: every issuer claiming revoke must declare a Revoke method, and
// every issuer that declares one must claim it.
func TestRevokeMatrixMatchesTheImplementations(t *testing.T) {
	t.Parallel()

	declared := issuersDeclaringRevoke(t)
	for _, row := range ca.IssuerCapabilityMatrix() {
		switch {
		case row.Revoke && !declared[row.Issuer]:
			t.Errorf("the capability matrix says %q can revoke, but its package declares no Revoke "+
				"method — an operator planning around this during an incident finds out at the "+
				"worst possible moment", row.Issuer)
		case !row.Revoke && declared[row.Issuer]:
			t.Errorf("%q implements Revoke but the matrix says it cannot; a capability the binary "+
				"has and does not advertise is one nobody will use", row.Issuer)
		}
	}
	for issuer := range declared {
		found := false
		for _, row := range ca.IssuerCapabilityMatrix() {
			if row.Issuer == issuer {
				found = true
			}
		}
		if !found {
			t.Errorf("issuer package %q implements Revoke but has no row in the capability matrix "+
				"at all", issuer)
		}
	}
}

// An issuer that cannot revoke must say WHERE to revoke instead. "Unsupported"
// with no reason tells an operator nothing they can act on, and the useful part
// is almost always the alternative.
func TestUnsupportedRevocationNamesTheAlternative(t *testing.T) {
	t.Parallel()
	for _, row := range ca.IssuerCapabilityMatrix() {
		if row.Revoke {
			if row.RevokeNote != "" {
				t.Errorf("%q supports revocation but carries a note explaining why it does not: %q",
					row.Issuer, row.RevokeNote)
			}
			continue
		}
		if strings.TrimSpace(row.RevokeNote) == "" {
			t.Errorf("%q cannot revoke and gives no reason; an operator reading this needs to know "+
				"where to go instead", row.Issuer)
		}
	}
}

// The matrix is sorted and complete: every row names a key-handling model and a
// validation model, because both decide whether an authority can be used at all
// for a given purpose.
func TestMatrixIsCompleteAndStable(t *testing.T) {
	t.Parallel()
	rows := ca.IssuerCapabilityMatrix()
	if len(rows) == 0 {
		t.Fatal("the capability matrix is empty")
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.Issuer)
		if row.KeyHandling == "" {
			t.Errorf("%q declares no key-handling model; where the private key is generated is a "+
				"capability an operator chooses on, not a footnote", row.Issuer)
		}
		if row.Validation == "" {
			t.Errorf("%q declares no validation model; it decides whether issuance can be "+
				"unattended at all", row.Issuer)
		}
		if !row.Issue {
			t.Errorf("%q is in the issuer matrix but claims it cannot issue", row.Issuer)
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("the matrix is not sorted: %v", names)
	}
}

// issuersDeclaringRevoke parses each issuer package and reports which declare a
// Revoke method on their plugin or backend type.
func issuersDeclaringRevoke(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read ca dir: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		issuer := entry.Name()
		// Not issuers: shared infrastructure that legitimately declares Revoke.
		// Named explicitly rather than pattern-matched, so a genuinely new
		// issuer cannot slip past by resembling one of them.
		switch issuer {
		case "revocation": // trstctl's own CRL/OCSP service for internally-issued certs
			continue
		case "catemplate": // the shared upstream-CA wrapper that forwards to a backend
			continue
		case "profilelint", "hierarchy", "example": // linting, internal hierarchy, docs sample
			continue
		}
		files, err := filepath.Glob(filepath.Join(issuer, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", issuer, err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				continue
			}
			for _, decl := range parsed.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Name.Name != "Revoke" {
					continue
				}
				out[issuer] = true
			}
		}
	}
	return out
}
