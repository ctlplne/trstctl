package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestDocsListEveryRegisteredAnalyzer is the ARCH-005 docs reality-test: it
// guards against the linter's own docs drifting from the binary. It parses the
// set of analyzers actually registered in main.go and asserts that BOTH doc.go
// and the README rules table describe exactly that set — so a reader can never
// conclude (as before) that AN-2/eventsource has no linter when the binary runs
// it. Adding or removing an analyzer without updating the docs fails this test.
func TestDocsListEveryRegisteredAnalyzer(t *testing.T) {
	registered := registeredAnalyzers(t)
	if len(registered) == 0 {
		t.Fatal("found no registered analyzers in main.go")
	}

	// doc.go must claim the right count and name each analyzer.
	doc := readFile(t, "doc.go")
	wantCount := numberWord(len(registered))
	if !strings.Contains(doc, wantCount+" analyzers") {
		t.Errorf("doc.go must say %q analyzers (found %d registered); got drift", wantCount, len(registered))
	}
	for _, a := range registered {
		if !strings.Contains(doc, a) {
			t.Errorf("doc.go does not mention registered analyzer %q", a)
		}
	}

	// The README rules table must have exactly one row per registered analyzer.
	readme := readmeRuleAnalyzers(t)
	if !equalStringSets(registered, readme) {
		t.Errorf("README rules table %v does not match registered analyzers %v", readme, registered)
	}
}

var (
	// matches `   cryptoboundary.Analyzer, // AN-3`
	registerRe = regexp.MustCompile(`(?m)^\s*([a-z][a-z0-9]*)\.Analyzer\s*,`)
	// matches a README table row whose first cell is `name` in backticks.
	readmeRowRe = regexp.MustCompile("(?m)^\\|\\s*`([a-z][a-z0-9]*)`\\s*\\|")
)

func registeredAnalyzers(t *testing.T) []string {
	t.Helper()
	src := readFile(t, "main.go")
	var names []string
	for _, m := range registerRe.FindAllStringSubmatch(src, -1) {
		names = append(names, m[1])
	}
	sort.Strings(names)
	return names
}

func readmeRuleAnalyzers(t *testing.T) []string {
	t.Helper()
	src := readFile(t, "README.md")
	var names []string
	for _, m := range readmeRowRe.FindAllStringSubmatch(src, -1) {
		names = append(names, m[1])
	}
	sort.Strings(names)
	return names
}

func readFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func numberWord(n int) string {
	words := map[int]string{
		1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
		6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten",
	}
	if w, ok := words[n]; ok {
		return w
	}
	return ""
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
