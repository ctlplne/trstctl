// SPDX-License-Identifier: BUSL-1.1

// Package licenseboundary enforces PACKAGING-007: BUSL-1.1 core files, MPL-2.0
// client files under clients/, proprietary ee/ files, and no core imports of ee/.
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
	coreSPDX   = "SPDX-License-Identifier: BUSL-1.1"
	clientSPDX = "SPDX-License-Identifier: MPL-2.0"
	eeSPDX     = "SPDX-License-Identifier: LicenseRef-trstctl-EE"
	mitSPDX    = "SPDX-License-Identifier: MIT"
)

var Analyzer = &analysis.Analyzer{
	Name: "licenseboundary",
	Doc:  "PACKAGING-007: enforce BUSL-1.1 core, MPL-2.0 clients/, proprietary ee/, and no core->ee imports.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		filename := filepath.ToSlash(pass.Fset.File(file.Pos()).Name())
		if !isRepoGoFile(filename, pass.Pkg.Path()) {
			continue
		}
		sourcePath := repoSourcePath(filename, pass.Pkg.Path())
		bodyBytes, err := os.ReadFile(filename) // #nosec G304 -- developer tool reading the repo paths it is pointed at (CWE-22)
		if err != nil {
			continue
		}
		body := string(bodyBytes)
		isEE := isEEPath(sourcePath) || strings.HasPrefix(pass.Pkg.Path(), modulePath+"/ee")
		isClient := !isEE && (isClientPath(sourcePath) || strings.HasPrefix(pass.Pkg.Path(), modulePath+"/clients/"))
		checkSPDX(pass, file, sourcePath, isEE, isClient, body)
		if !isEE {
			checkCoreImports(pass, file, sourcePath)
		}
	}
	return nil, nil
}

// repoSourcePath derives a stable repository-relative filename from the Go
// package import path. Analyzer filenames may be absolute and may live under a
// worktree whose parent directories contain policy keywords. Those host path
// names are not source and must never influence edition classification.
func repoSourcePath(filename, pkgPath string) string {
	relPkg, ok := strings.CutPrefix(pkgPath, modulePath)
	if !ok {
		return shortPath(filename)
	}
	relPkg = strings.Trim(relPkg, "/")
	parts := strings.Split(relPkg, "/")
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		last = strings.TrimSuffix(last, ".test")
		last = strings.TrimSuffix(last, "_test")
		parts[len(parts)-1] = last
		relPkg = strings.Join(parts, "/")
	}
	base := filepath.Base(filename)
	if relPkg == "" {
		return base
	}
	return relPkg + "/" + base
}

func checkSPDX(pass *analysis.Pass, file *ast.File, sourcePath string, isEE, isClient bool, body string) {
	header := spdxHeaderWindow(body)
	if isEE {
		for _, wrong := range []string{coreSPDX, clientSPDX} {
			if strings.Contains(header, wrong) {
				pass.Reportf(file.Package, "ee/ file must not carry %s; use %s", wrong, eeSPDX)
				return
			}
		}
		if !strings.Contains(header, eeSPDX) {
			pass.Reportf(file.Package, "ee/ file must carry %s", eeSPDX)
		}
		return
	}
	if isEmbeddedPostgresSource(sourcePath) {
		if !strings.Contains(header, mitSPDX) || strings.Contains(header, coreSPDX) || strings.Contains(header, clientSPDX) || strings.Contains(header, eeSPDX) {
			pass.Reportf(file.Package, "embedded-postgres source file must preserve upstream %s", mitSPDX)
		}
		return
	}
	if isClient {
		// The client tree (SDKs, embedded client, GitHub Action) stays MPL-2.0 so it
		// can be embedded in a customer's own software without the core's BSL use
		// grant attaching to that software.
		for _, wrong := range []string{coreSPDX, eeSPDX} {
			if strings.Contains(header, wrong) {
				pass.Reportf(file.Package, "clients/ file must not carry %s; use %s", wrong, clientSPDX)
				return
			}
		}
		if !strings.Contains(header, clientSPDX) {
			pass.Reportf(file.Package, "clients/ file must carry %s", clientSPDX)
		}
		return
	}
	for _, wrong := range []string{eeSPDX, clientSPDX} {
		if strings.Contains(header, wrong) {
			pass.Reportf(file.Package, "core file must not carry %s; use %s", wrong, coreSPDX)
			return
		}
	}
	if !strings.Contains(header, coreSPDX) {
		pass.Reportf(file.Package, "core file must carry %s", coreSPDX)
	}
}

func isClientPath(sourcePath string) bool {
	return strings.HasPrefix(sourcePath, "clients/")
}

func isEmbeddedPostgresSource(sourcePath string) bool {
	return strings.HasPrefix(sourcePath, "third_party/embedded-postgres/")
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

func isEEPath(filename string) bool {
	return strings.HasPrefix(shortPath(filename), "ee/")
}

func isTaggedAttachSeam(filename string) bool {
	rel := strings.TrimPrefix(shortPath(filename), "/")
	// The workload agent's co-sign seam (cmd/trstctl-agent/cosign_attach.go) is
	// no longer listed: PCAS moved into the core on 2026-09-20, so it imports
	// nothing from ee/ and needs no fence.
	return rel == "cmd/trstctl/ee_attach.go" ||
		rel == "cmd/trstctl-signer/ee_attach.go"
}

func shortPath(filename string) string {
	filename = filepath.ToSlash(filename)
	if !strings.HasPrefix(filename, "/") {
		return strings.TrimPrefix(filename, "./")
	}
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
