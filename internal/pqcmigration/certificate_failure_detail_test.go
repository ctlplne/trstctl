// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	eventspec "trstctl.com/trstctl/internal/events"
)

// B6-1: an exhausted host migration names the agent's closed refusal, and
// only a closed phrase ever reaches the finding.
func TestCertificateFailureCarriesTheAgentsClosedRefusal(t *testing.T) {
	if got := closedHostRenewalRefusal("  " + transport.RenewRefusedNoPQCProbe + " "); got != transport.RenewRefusedNoPQCProbe {
		t.Fatalf("closed refusal = %q", got)
	}
	if got := closedHostRenewalRefusal("permission denied opening /etc/nginx/site.key"); got != "" {
		t.Fatalf("free text leaked into the finding: %q", got)
	}
	p := NewProgressProjection(nil)
	ev := eventspec.Event{ID: "evt-1", Type: EventCertificateFindingFailed, TenantID: "t", Sequence: 7, Time: time.Now().UTC()}
	if err := p.applyCertificateFailure(ev, CertificateFindingFailure{RunID: "run", AssetID: "asset", Operation: "issue", Detail: transport.RenewRefusedNoPQCProbe}); err != nil {
		t.Fatal(err)
	}
	item := p.items[progressKey{tenantID: "t", runID: "run", assetID: "asset"}]
	if item.Status != TLSFindingFailed || !strings.HasPrefix(item.Failure, "Certificate issuance attempts exhausted: PQC host migration requires tls_probe_openssl") {
		t.Fatalf("finding = %+v", item)
	}
}
