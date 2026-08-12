// SPDX-License-Identifier: MPL-2.0

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
	for _, phrase := range []string{
		"thirteen-family source-plan denominator",
		"four are `migrated`",
		"three are open `architecture_exception` rows",
		"six are `unimplemented`",
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
