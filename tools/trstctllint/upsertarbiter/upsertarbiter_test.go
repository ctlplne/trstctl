// SPDX-License-Identifier: BUSL-1.1

package upsertarbiter_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/upsertarbiter"
)

// The rule flags an ON CONFLICT upsert into a table with a second unique index
// unless the enclosing function (or a same-package helper it calls) serializes
// on an advisory lock or handles unique_violation; target-less DO NOTHING and
// single-unique tables are accepted; ON CONSTRAINT names and CREATE UNIQUE
// INDEX declarations resolve through the migrations.
func TestUpsertArbiter(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), upsertarbiter.Analyzer, "trstctl.com/trstctl/internal/store")
}

// The reviewed baseline is a ratchet, not an ignore: every entry must still be
// an unguarded dual-unique upsert in the real store (a fixed site must be
// removed from the list), and no unbaselined site may exist (a new site fails
// closed in `make lint`).
func TestReviewedBaselineIsNotStale(t *testing.T) {
	sites, err := upsertarbiter.ScanDir(filepath.Join("..", "..", "..", "internal", "store"))
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]map[string]bool{}
	if out := os.Getenv("UPSERTARBITER_BASELINE_OUT"); out != "" {
		byFile := map[string][]string{}
		for _, s := range sites {
			if !s.Guarded {
				byFile[s.File] = append(byFile[s.File], s.Func)
			}
		}
		var files []string
		for f := range byFile {
			files = append(files, f)
		}
		sort.Strings(files)
		var b strings.Builder
		b.WriteString("var reviewedUpserts = map[string]map[string]bool{\n")
		for _, f := range files {
			fns := byFile[f]
			sort.Strings(fns)
			seen := map[string]bool{}
			fmt.Fprintf(&b, "\t%q: {\n", f)
			for _, fn := range fns {
				if !seen[fn] {
					seen[fn] = true
					fmt.Fprintf(&b, "\t\t%q: true,\n", fn)
				}
			}
			b.WriteString("\t},\n")
		}
		b.WriteString("}\n")
		out = filepath.Clean(out)
		if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil { // #nosec G703 G304 -- test-only baseline dump to a path the operator chose via UPSERTARBITER_BASELINE_OUT (CWE-22)
			t.Fatal(err)
		}
	}
	for _, s := range sites {
		if s.Guarded {
			continue
		}
		if flagged[s.File] == nil {
			flagged[s.File] = map[string]bool{}
		}
		flagged[s.File][s.Func] = true
		if !s.Baselined {
			t.Errorf("unbaselined unguarded upsert: %s %s on %s (arbiter %v, also unique %v) — serialize or retry it, or review it into the baseline", s.File, s.Func, s.Table, s.Arbiter, s.Uncovered)
		}
	}
	for file, funcs := range upsertarbiter.ReviewedBaseline() {
		for _, fn := range funcs {
			if !flagged[file][fn] {
				t.Errorf("stale baseline entry %s %s: no longer an unguarded dual-unique upsert — remove it", file, fn)
			}
		}
	}
	if len(sites) == 0 {
		t.Fatal("scanned no upsert sites in internal/store — schema or scanner drift")
	}
}
