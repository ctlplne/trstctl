// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const controlPlaneHotspotMaxLines = 140
const servedSurfaceMaxLines = 2000

// TestControlPlaneStartupHotspotsStaySplit is the CODE-001 guardrail: the
// control-plane boot, server assembly, and config validation paths must remain
// decomposed into named stages instead of drifting back into one huge function.
func TestControlPlaneStartupHotspotsStaySplit(t *testing.T) {
	root := moduleRoot(t)
	var findings []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipGoWalkEntry(d) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel := slashRel(t, root, path)
		if !isControlPlaneStartupPath(rel) || isGeneratedGo(t, path) {
			return nil
		}
		for _, fn := range parseFunctionLengths(t, path) {
			if fn.lines > controlPlaneHotspotMaxLines {
				findings = append(findings, fmt.Sprintf("%s:%d %s spans %d lines (limit %d)", rel, fn.line, fn.name, fn.lines, controlPlaneHotspotMaxLines))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("control-plane startup hotspots regressed; split these functions into named stages:\n%s", strings.Join(findings, "\n"))
	}
}

// TestServedSurfaceFilesStayWithinBudget is the ENGHEALTH-002 guardrail: large
// hand-written served surfaces must either be split by workflow or carry an
// explicit owner/rationale allowlist entry.
func TestServedSurfaceFilesStayWithinBudget(t *testing.T) {
	root := moduleRoot(t)
	allowlist := servedSurfaceSizeAllowlist()
	var findings []string
	seenAllowlist := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipServedSurfaceWalkEntry(d) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel := slashRel(t, root, path)
		if !isServedSurfacePath(rel) || isGeneratedServedSurface(t, path, rel) {
			return nil
		}
		lines := countFileLines(t, path)
		if entry, ok := allowlist[rel]; ok {
			seenAllowlist[rel] = true
			if entry.owner == "" || entry.rationale == "" {
				findings = append(findings, fmt.Sprintf("%s allowlist entry must include owner and rationale", rel))
			}
			if lines <= servedSurfaceMaxLines {
				findings = append(findings, fmt.Sprintf("%s allowlist entry is stale: %d lines <= limit %d", rel, lines, servedSurfaceMaxLines))
			}
			return nil
		}
		if lines > servedSurfaceMaxLines {
			findings = append(findings, fmt.Sprintf("%s has %d lines (limit %d); split by served workflow or add a reviewed allowlist entry", rel, lines, servedSurfaceMaxLines))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	for rel := range allowlist {
		if !seenAllowlist[rel] {
			findings = append(findings, fmt.Sprintf("%s allowlist entry is stale: file is missing or no longer in the served-surface scan", rel))
		}
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("served file size budget regressed:\n%s", strings.Join(findings, "\n"))
	}
}

type functionLength struct {
	name  string
	line  int
	lines int
}

func parseFunctionLengths(t *testing.T, path string) []functionLength {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var lengths []functionLength
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Pos()).Line
		end := fset.Position(fn.End()).Line
		lengths = append(lengths, functionLength{
			name:  functionDisplayName(fn),
			line:  start,
			lines: end - start + 1,
		})
	}
	return lengths
}

func functionDisplayName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(receiver)." + fn.Name.Name
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}

func slashRel(t *testing.T, root, path string) string {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("rel %s to %s: %v", path, root, err)
	}
	return filepath.ToSlash(rel)
}

func skipGoWalkEntry(d os.DirEntry) bool {
	name := d.Name()
	if d.IsDir() {
		switch name {
		case ".git", "bin", "dist", "node_modules", "testdata", "vendor":
			return true
		}
		return false
	}
	return strings.HasSuffix(name, "_test.go") || !strings.HasSuffix(name, ".go")
}

func isControlPlaneStartupPath(rel string) bool {
	for _, prefix := range []string{
		"cmd/trstctl/",
		"internal/config/",
		"internal/server/",
	} {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

func isGeneratedGo(t *testing.T, path string) bool {
	t.Helper()
	src, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(src) > 2048 {
		src = src[:2048]
	}
	head := string(src)
	return strings.Contains(head, "Code generated") && strings.Contains(head, "DO NOT EDIT")
}

type servedSurfaceSizeAllowlistEntry struct {
	owner     string
	rationale string
}

func servedSurfaceSizeAllowlist() map[string]servedSurfaceSizeAllowlistEntry {
	return map[string]servedSurfaceSizeAllowlistEntry{
		"internal/api/openapi.go": {
			owner:     "ENGHEALTH/api",
			rationale: "OpenAPI object model and route-registry renderer are kept together so the served contract remains mechanically consistent.",
		},
		"internal/projections/projections.go": {
			owner:     "ENGHEALTH/projections",
			rationale: "Projection dispatcher is the event-source composition table; splitting it without a generated registry is tracked separately.",
		},
		"internal/server/server.go": {
			owner:     "ENGHEALTH/server",
			rationale: "Control-plane composition root wires many lifecycle workers; function-level hotspot guards keep boot stages split.",
		},
		"web/src/pages/Discovery.tsx": {
			owner:     "ENGHEALTH/web",
			rationale: "Discovery page pre-dates this secrets-surface remediation and remains tracked by the served-surface budget.",
		},
		"web/src/pages/CAHierarchy.tsx": {
			owner:     "ENGHEALTH/web",
			rationale: "CA hierarchy workflow remains a single served page while the authority-table and leaf-issuance split is tracked separately.",
		},
		"web/src/pages/Secrets.tsx": {
			owner:     "ENGHEALTH/web",
			rationale: "Secrets workflow remains a single served page while store, engines, scan, and sync panels are split by follow-up remediation.",
		},
	}
}

func skipServedSurfaceWalkEntry(d os.DirEntry) bool {
	name := d.Name()
	if d.IsDir() {
		switch name {
		case ".git", "bin", "dist", "node_modules", "testdata", "vendor":
			return true
		}
		return false
	}
	return strings.HasSuffix(name, "_test.go") ||
		strings.HasSuffix(name, ".test.ts") ||
		strings.HasSuffix(name, ".test.tsx") ||
		(!strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".ts") && !strings.HasSuffix(name, ".tsx"))
}

func isServedSurfacePath(rel string) bool {
	for _, prefix := range []string{
		"internal/api/",
		"internal/projections/",
		"internal/server/",
		"web/src/components/",
		"web/src/lib/",
		"web/src/pages/",
	} {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

func isGeneratedServedSurface(t *testing.T, path, rel string) bool {
	t.Helper()
	name := filepath.Base(rel)
	if strings.Contains(name, ".gen.") {
		return true
	}
	if strings.HasSuffix(name, ".go") {
		return isGeneratedGo(t, path)
	}
	return false
}

func countFileLines(t *testing.T, path string) int {
	t.Helper()
	src, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(src) == 0 {
		return 0
	}
	lines := strings.Count(string(src), "\n")
	if src[len(src)-1] != '\n' {
		lines++
	}
	return lines
}
