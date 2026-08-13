// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

func TestTicketIntakeDocsNameBothDurableProviderContinuationsAUD47(t *testing.T) {
	body := read(t, "limitations.md")
	for _, want := range []string{
		"ServiceNow or Jira", "ascending `sys_id` keyset pages", "enhanced-search `nextPageToken`",
		"hard 100-ticket page bound", "`last_run_at`", "`coverage_complete=true`",
		"`read_count`, optional `expected_count`", "snapshot restore, and cold event rebuild",
		"no ServiceNow/Jira HTTP or token fallback",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("AUD-47 limitation truth is missing %q", want)
		}
	}
	for _, stale := range []string{
		"JIRA INTAKE IS NOT BUILT", "intake reads one page (100 tickets) per sweep",
	} {
		if strings.Contains(body, stale) {
			t.Errorf("AUD-47 documentation still claims %q", stale)
		}
	}
}
