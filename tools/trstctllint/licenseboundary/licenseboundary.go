// SPDX-License-Identifier: MPL-2.0

// Package licenseboundary enforces PACKAGING-007: MPL-2.0 core files, proprietary
// ee/ files, no core imports of ee/, and a bounded PQC placement rule.
package licenseboundary

import (
	"go/ast"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	modulePath = "trstctl.com/trstctl"
	coreSPDX   = "SPDX-License-Identifier: MPL-2.0"
	eeSPDX     = "SPDX-License-Identifier: LicenseRef-trstctl-EE"
)

var Analyzer = &analysis.Analyzer{
	Name: "licenseboundary",
	Doc:  "PACKAGING-007: enforce MPL core, proprietary ee/, no core->ee imports, and PQC placement.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		filename := filepath.ToSlash(pass.Fset.File(file.Pos()).Name())
		if !isRepoGoFile(filename, pass.Pkg.Path()) {
			continue
		}
		bodyBytes, err := os.ReadFile(filename)
		if err != nil {
			continue
		}
		body := string(bodyBytes)
		isEE := isEEPath(filename) || strings.HasPrefix(pass.Pkg.Path(), modulePath+"/ee")
		checkSPDX(pass, file, isEE, body)
		if !isEE {
			checkCoreImports(pass, file, filename)
			checkCorePQCPlacement(pass, file, filename, body)
		}
	}
	return nil, nil
}

func checkSPDX(pass *analysis.Pass, file *ast.File, isEE bool, body string) {
	header := spdxHeaderWindow(body)
	if isEE {
		if strings.Contains(header, coreSPDX) {
			pass.Reportf(file.Package, "ee/ file must not carry MPL-2.0 SPDX; use %s", eeSPDX)
			return
		}
		if !strings.Contains(header, eeSPDX) {
			pass.Reportf(file.Package, "ee/ file must carry %s", eeSPDX)
		}
		return
	}
	if strings.Contains(header, eeSPDX) {
		pass.Reportf(file.Package, "core file must not carry proprietary EE SPDX; use %s", coreSPDX)
		return
	}
	if !strings.Contains(header, coreSPDX) {
		pass.Reportf(file.Package, "core file must carry %s", coreSPDX)
	}
}

func spdxHeaderWindow(body string) string {
	lines := strings.Split(body, "\n")
	if len(lines) > 8 {
		lines = lines[:8]
	}
	return strings.Join(lines, "\n")
}

func checkCoreImports(pass *analysis.Pass, file *ast.File, filename string) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(path, modulePath+"/ee") {
			continue
		}
		if isTaggedAttachSeam(filename) {
			continue
		}
		pass.Reportf(imp.Pos(), "core file imports %q; only cmd/trstctl/ee_attach.go may import ee/ behind the tagged attach seam", path)
	}
}

func checkCorePQCPlacement(pass *analysis.Pass, file *ast.File, filename, body string) {
	if pass.Pkg.Path() == modulePath+"/cmd/trstctl" {
		return
	}
	if isPQCAllowedCorePath(filename) {
		return
	}
	if term := forbiddenCorePQCTerm(body); term != "" {
		pass.Reportf(file.Package, "PQC algorithm or fleet-execution code (%s) belongs under ee/ for PACKAGING-007; move %s behind the proprietary boundary", term, shortPath(filename))
	}
}

// forbiddenCorePQCTerm distinguishes the owner-approved core campaign record
// from licensed algorithms and fleet execution. Campaigns are CBOM bookkeeping:
// they may name PQC, findings, and campaign state, but algorithm names and the
// non-campaign migration surface remain forbidden even in a campaign file.
func forbiddenCorePQCTerm(body string) string {
	upper := strings.ToUpper(body)
	for _, line := range strings.Split(upper, "\n") {
		if isCorePQCCampaignReference(line) &&
			(strings.Contains(line, "EXECUTOR") ||
				strings.Contains(line, "/EXECUTE") ||
				strings.Contains(line, "/RUN") ||
				strings.Contains(line, "/PLAN")) {
			return "PQC campaign fleet execution"
		}
	}
	for _, term := range []string{
		"ML-DSA",
		"ML-KEM",
		"SLH-DSA",
		"MLDSA",
		"MLKEM",
		"SLHDSA",
	} {
		if strings.Contains(upper, term) {
			return term
		}
	}
	coreCampaignTerms := strings.NewReplacer(
		"PQC_MIGRATION_CAMPAIGN", "",
		"PQC-MIGRATION-CAMPAIGN", "",
		"PQC.MIGRATION_CAMPAIGN", "",
		"PQC MIGRATION CAMPAIGN", "",
		"PQC MIGRATION TRACKING CAMPAIGN", "",
		"PQCMIGRATIONCAMPAIGN", "",
		"PQC_CAMPAIGN", "",
		"PQC-CAMPAIGN", "",
		"PQC CAMPAIGN", "",
		"PQCCAMPAIGN", "",
		"/PQC/CAMPAIGN", "",
		`"PQC", "CAMPAIGN`, "",
		"PQC_MIGRATION_FINDING", "",
		"PQC-MIGRATION-FINDING", "",
		"PQC MIGRATION FINDING", "",
		"PQCMIGRATIONFINDING", "",
		"PQC FINDING", "",
	)
	remaining := coreCampaignTerms.Replace(upper)
	for _, term := range []string{"POST-QUANTUM", "PQCMIGRATION", "PQC"} {
		if strings.Contains(remaining, term) {
			return term
		}
	}
	return ""
}

func isCorePQCCampaignReference(line string) bool {
	for _, marker := range []string{
		"PQCMIGRATIONCAMPAIGN",
		"PQC_MIGRATION_CAMPAIGN",
		"PQC-MIGRATION-CAMPAIGN",
		"PQC.MIGRATION_CAMPAIGN",
		"PQC MIGRATION CAMPAIGN",
		"PQCCAMPAIGN",
		"PQC_CAMPAIGN",
		"PQC-CAMPAIGN",
		"PQC CAMPAIGN",
		"/PQC/CAMPAIGN",
	} {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

func isEEPath(filename string) bool {
	return strings.HasPrefix(shortPath(filename), "ee/")
}

func isTaggedAttachSeam(filename string) bool {
	return strings.HasSuffix(filename, "/cmd/trstctl/ee_attach.go") ||
		strings.HasSuffix(filename, "/cmd/trstctl-signer/ee_attach.go") ||
		// The workload agent's co-sign seam (INT-16): the enterprise build serves the
		// ee/succession/agent CoSignerService; the core build stubs it out. Behind the
		// same !trstctl_core tag as the other attach seams.
		strings.HasSuffix(filename, "/cmd/trstctl-agent/cosign_attach.go")
}

func isPQCAllowedCorePath(filename string) bool {
	rel := shortPath(filename)
	for _, prefix := range []string{
		"tools/trstctllint/",
		// DoD census code verifies proprietary algorithms in externally built
		// shipped artifacts but is not linked into a product binary.
		"tools/dodcensus/",
		"docs/",
	} {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	switch rel {
	case
		"cmd/trstctl/ee_attach.go",
		"cmd/trstctl/ee_attach_test.go",
		"cmd/trstctl-signer/ee_attach.go",
		"internal/license/license.go",
		"internal/license/license_test.go",
		"internal/api/editions.go",
		"internal/api/editions_test.go",
		// The CLI is a thin HTTP client: this file holds route strings and help
		// text for operations only a licensed server serves, and no PQC code.
		// It exists apart from command.go precisely so this exemption covers a
		// route list instead of the whole command table.
		"internal/cli/command_licensed.go",
		"internal/featureparity/feature-map-backlog.go":
		return true
	}
	return false
}

func shortPath(filename string) string {
	filename = filepath.ToSlash(filename)
	if i := strings.LastIndex(filename, "/trstctl/"); i >= 0 {
		return filename[i+len("/trstctl/"):]
	}
	return filename
}

func isRepoGoFile(filename, pkgPath string) bool {
	if !strings.HasPrefix(pkgPath, modulePath) {
		return false
	}
	if !strings.HasSuffix(filename, ".go") {
		return false
	}
	for _, segment := range []string{"/node_modules/", "/vendor/", "/trstctl-gocache/"} {
		if strings.Contains(filename, segment) {
			return false
		}
	}
	return true
}
