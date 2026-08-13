// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

// AUD-46: the limitations page is the operator's truth label. A bounded job is
// not the same thing as a bounded estate: it must say that jobs form one stable
// sweep, that only the short page proves completion, and that a restart keeps
// the committed boundary.
func TestCMDBPaginationLimitationNamesCoverageAndResumeAUD46(t *testing.T) {
	limitations := strings.Join(strings.Fields(read(t, "limitations.md")), " ")
	for _, required := range []string{
		"strict `sys_id` keyset order",
		"A short or empty page is the only terminal proof",
		"`read_count`, optional `expected_count`, `pages_completed`, `next_cursor`, `coverage_complete`",
		"Restart recovery derives the same idempotent next job from the event/checkpoint",
		"never a human attestation or later edit",
	} {
		if !strings.Contains(limitations, required) {
			t.Errorf("limitations.md omits AUD-46 coverage truth %q", required)
		}
	}
	for _, stale := range []string{
		"Each sync intentionally reads one bounded page",
		"successful last_run_at after dispatch",
	} {
		if strings.Contains(limitations, stale) {
			t.Errorf("limitations.md retains pre-AUD-46 partial-success claim %q", stale)
		}
	}
}
