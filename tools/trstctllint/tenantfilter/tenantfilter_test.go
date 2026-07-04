// SPDX-License-Identifier: MPL-2.0

package tenantfilter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/tenantfilter"
)

// TestTenantFilter exercises AN-1: SQL data-manipulation queries in repository
// packages must FILTER on tenant_id — tenant_id must sit in a row-restricting
// predicate (WHERE / JOIN..ON / INSERT column list / ON CONFLICT target), not
// merely appear in the text. This covers the substring-check false-negatives
// closed by ARCH-003 / SEC-004 / TENANT-001 (comment-only, SELECT-list-only,
// cast-only, ORDER-BY-only), concatenation-aware judging, the strict
// statement-shape check (a bare "DELETE" method string is not SQL), the
// //trstctl:system-query exemption, and the default-on orchestrator package
// (fail-closed even without the //trstctl:repository marker, ARCH-004).
//
// Repository packages are recognized by living under internal/store, by carrying
// the //trstctl:repository marker, or by being a default-on raw-DML package
// (orchestrator). Outside such packages the rule is inactive, so SQL-looking
// prose is ignored.
func TestTenantFilter(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), tenantfilter.Analyzer,
		"trstctl.com/trstctl/internal/store",        // repository by path
		"trstctl.com/trstctl/internal/orchestrator", // default-on raw-DML pkg (no marker): fail-closed
		"repoelsewhere", // repository by marker directive
		"notstore",      // not a repository: ignored
	)
}

func TestBootstrapTokenSystemQueryFixture(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), tenantfilter.Analyzer,
		"trstctl.com/trstctl/internal/store",
	)
}

func TestTenantFilterLintGateFailsClosed(t *testing.T) {
	makefile, err := os.ReadFile(filepath.Join("..", "..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	body := string(makefile)
	for _, want := range []string{
		"lint: ## Run the full lint gate",
		"$(GO) build -o \"$$vettool\" ./tools/trstctllint",
		"$(GO) vet -vettool=\"$$vettool\" $(GO_PACKAGES)",
		"golangci-lint run $(GO_PACKAGE_DIRS)",
		"FAIL: golangci-lint is not installed",
		"FAIL: actionlint is not installed",
		"lint-partial",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Makefile no longer contains %q; tenantfilter may no longer be a fail-closed release gate", want)
		}
	}
}
