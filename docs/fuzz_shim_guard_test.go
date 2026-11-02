// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ClusterFuzzLite builds every native fuzz target with a testing shim whose
// *testing.F implements only part of testing.TB (Go 1.26 added ArtifactDir,
// which the shim lacks). A fuzz target that hands its f to a helper declared
// with a testing.TB parameter compiles under go test and fails only in that
// build (CI 41508856233: internal/agent/sshkrl FuzzParseRevocations). Seed
// helpers take a narrow interface of the methods they use instead.
func TestFuzzTargetsDoNotHandFToTestingTBHelpers(t *testing.T) {
	helper := regexp.MustCompile(`func (\w+)\(\w+ testing\.TB\b`)
	target := regexp.MustCompile(`func (Fuzz\w+)\((\w+) \*testing\.F\)\s*\{`)
	byDir := map[string][]string{}
	for _, root := range []string{"../internal", "../ee", "../cmd", "../tools"} {
		_ = filepath.WalkDir(filepath.FromSlash(root), func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(path, "_test.go") {
				byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], path)
			}
			return nil
		})
	}
	var findings []string
	for _, files := range byDir {
		sources := map[string]string{}
		helpers := map[string]bool{}
		for _, path := range files {
			body := read(t, filepath.ToSlash(path))
			sources[path] = body
			for _, m := range helper.FindAllStringSubmatch(body, -1) {
				helpers[m[1]] = true
			}
		}
		if len(helpers) == 0 {
			continue
		}
		for path, src := range sources {
			for _, m := range target.FindAllStringSubmatchIndex(src, -1) {
				name, f := src[m[2]:m[3]], src[m[4]:m[5]]
				seeds := src[m[1]:]
				if end := strings.Index(seeds, f+".Fuzz("); end >= 0 {
					seeds = seeds[:end]
				}
				for h := range helpers {
					if regexp.MustCompile(`\b` + regexp.QuoteMeta(h) + `\(\s*` + regexp.QuoteMeta(f) + `\b`).MatchString(seeds) {
						findings = append(findings, filepath.ToSlash(path)+": "+name+" passes "+f+" to "+h+"(testing.TB)")
					}
				}
			}
		}
	}
	sort.Strings(findings)
	if len(findings) > 0 {
		t.Fatalf("fuzz targets hand *testing.F to testing.TB helpers (ClusterFuzzLite cannot compile them):\n%s", strings.Join(findings, "\n"))
	}
}
