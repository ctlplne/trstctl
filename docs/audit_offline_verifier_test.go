// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

func TestOfflineAuditVerifierRunbookNamesEveryFormatAndTrustBoundaryAUD53(t *testing.T) {
	t.Parallel()
	cliDoc := read(t, "cli.md")
	for _, marker := range []string{
		"Verify audit exports offline",
		"audit verification-keys",
		"audit verify",
		"--audit-jwks",
		"--tsa-root",
		"--max-anchor-delay",
		"jws", "csv", "ndjson", "splunk-hec", "sentinel",
		"PEM or DER",
		"before disconnecting",
		"never trusts",
		"archived prefix",
		"exit code 1",
	} {
		if !strings.Contains(cliDoc, marker) {
			t.Errorf("docs/cli.md offline verifier runbook missing %q", marker)
		}
	}

	limitations := read(t, "limitations.md")
	for _, marker := range []string{
		"`trstctl-cli audit verify`",
		"`GET /api/v1/audit/verification-keys`",
		"separately pinned",
		"maximum anchor delay",
	} {
		if !strings.Contains(limitations, marker) {
			t.Errorf("docs/limitations.md audit trust disclosure missing %q", marker)
		}
	}
}
