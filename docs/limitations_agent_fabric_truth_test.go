// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
)

// TestLimitationsAgentFabricClaimsStayCurrent locks AUD-23's documentation
// repair. ELI5: limitations.md is the product's "what really works" label. A
// later paragraph cannot cancel an older opposite claim because operators may
// stop at either one, so known pre-delivery wording must disappear completely.
func TestLimitationsAgentFabricClaimsStayCurrent(t *testing.T) {
	t.Parallel()
	limitations := read(t, "limitations.md")
	flat := strings.Join(strings.Fields(limitations), " ")

	for _, stale := range []string{
		"The agent job ledger: served fabric, no work yet",
		"connector execution remains control-plane-side",
		"agent-side executors are not served",
		"signed result receipts are not served",
		"automatic rollback is not served",
	} {
		if strings.Contains(strings.ToLower(flat), strings.ToLower(stale)) {
			t.Errorf("limitations.md retains obsolete AUD-23 claim %q", stale)
		}
	}

	for _, current := range []string{
		"### The agent job ledger: served executors and signed receipts",
		"The shipped agent census executes `connector.deploy`, `connector.test`, `connector.rollback`, `endpoint.renew`",
		"Agent-signed result receipts are served and verified",
		"Automatic rollback is served when a target explicitly sets",
		"Aggregate waiting and claimed counts are served on Operations",
		"Per-agent claim quotas beyond the shared agent bulkhead and attribution of each live claim on the Agents page remain unserved",
	} {
		if !strings.Contains(flat, current) {
			t.Errorf("limitations.md does not state the current AUD-23 boundary %q", current)
		}
	}
}

// TestLimitationsAgentFabricClaimsRemainLoadBearing ties the corrected prose to
// shipped constructors, handlers, UI reads, and assembled proofs. A renamed
// paragraph without these tokens would be a fresh unsupported claim.
func TestLimitationsAgentFabricClaimsRemainLoadBearing(t *testing.T) {
	t.Parallel()
	limitations := read(t, "limitations.md")
	start := strings.Index(limitations, "### The agent job ledger: served executors and signed receipts")
	if start < 0 {
		t.Fatal("cannot find the corrected agent job-ledger section")
	}
	end := strings.Index(limitations[start:], "\n### Served status vocabulary")
	if end < 0 {
		t.Fatal("cannot isolate the corrected agent job-ledger section")
	}
	ledgerSection := limitations[start : start+end]
	for _, shipped := range relay.ShippedJobKinds() {
		if !strings.Contains(ledgerSection, "`"+shipped.Kind+"`") {
			t.Errorf("agent job-ledger limitations section omits shipped kind %q", shipped.Kind)
		}
	}

	for _, tc := range []struct {
		file   string
		tokens []string
	}{
		{"../internal/agent/relay/shipped.go", []string{"func ShippedJobKinds()", "KindConnectorRollback", "KindEndpointVerify", "KindDiscoveryRun"}},
		{"../internal/server/agent_jobs.go", []string{"receipt_statement", "agent.job.receipt.rejected", "maybeAutoRollbackAfterVerifyFailure"}},
		{"../internal/server/verify_rollback.go", []string{"auto_rollback_on_verify_failure", "RequestConnectorRollback"}},
		{"../internal/api/agent_jobs.go", []string{"Claimed int", "Receipts AgentJobReceipts"}},
		{"../web/src/pages/operations/AgentJobLedgerPanel.tsx", []string{"queue.claimed", "receipts.verified", "receipts.rejected"}},
		{"../internal/server/agent_jobs_served_test.go", []string{"TestServedAgentClaimsExecutesAndReportsAJob"}},
		{"../internal/server/agent_job_receipts_served_test.go", []string{"TestAnAcceptedReceiptIsStoredAndIndependentlyVerifiable"}},
		{"../internal/server/host_agent_remote_served_test.go", []string{"TestServedHostRollbackG1AutomaticAndManualAcrossAgentRestartsAUD32"}},
	} {
		body := read(t, tc.file)
		for _, token := range tc.tokens {
			if !strings.Contains(body, token) {
				t.Errorf("%s no longer contains %q; limitations.md would lose its AUD-23 production proof", tc.file, token)
			}
		}
	}
}
