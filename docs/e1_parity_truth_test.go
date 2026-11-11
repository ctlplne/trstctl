// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// AUD-33: documentation must describe the same denominator and dispositions as
// the served parity program. A generated seven-row matrix plus prose saying E1
// was closed is the exact failure this guards against.
func TestE1DocsUseTheAcceptedDenominatorAndOpenStatuses(t *testing.T) {
	limitations := read(t, "limitations.md")
	limitationsWords := strings.Join(strings.Fields(limitations), " ")
	matrix := read(t, "features/connector-support-matrix.md")

	for _, stale := range []string{
		"E1, CLOSED BY SCOPE DECISION",
		"terminal rather than pending",
		"false for all seven families today",
	} {
		if strings.Contains(limitations, stale) {
			t.Errorf("limitations still contains narrowed E1 claim %q", stale)
		}
	}
	// The counts come from the parity program itself, so the prose cannot
	// keep a count the code has moved past (it said four/three/six while the
	// program reported eight/two/three).
	counts := map[connector.ParityDisposition]int{}
	for _, status := range connector.ParityProgram() {
		counts[status.Disposition]++
	}
	words := []string{"none", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen"}
	exceptions := words[counts[connector.ParityDispositionArchitectureException]] + " are open `architecture_exception` rows"
	if counts[connector.ParityDispositionArchitectureException] == 0 {
		exceptions = "none is an `architecture_exception` row"
	}
	for _, phrase := range []string{
		"thirteen-family source-plan denominator",
		words[counts[connector.ParityDispositionMigrated]] + " are `migrated`",
		exceptions,
		words[counts[connector.ParityDispositionUnimplemented]] + " are `unimplemented`",
	} {
		if !strings.Contains(limitationsWords, phrase) {
			t.Errorf("limitations missing E1 denominator truth %q", phrase)
		}
	}
	for _, status := range connector.ParityProgram() {
		if !strings.Contains(matrix, "## "+status.Family) {
			t.Errorf("generated support matrix omits accepted family %q", status.Family)
		}
		if !strings.Contains(matrix, "**E1 disposition:** `"+string(status.Disposition)+"`") {
			t.Errorf("support matrix omits %s disposition %q", status.Family, status.Disposition)
		}
	}
}
