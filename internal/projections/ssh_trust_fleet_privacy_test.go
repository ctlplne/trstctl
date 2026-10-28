// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

func TestSSHTrustFleetPrivacyRewritePreservesExactEffect(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const subject = "operator@example.test"
	public, fp, err := sshtrustrollout.CanonicalPublicCAKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt"))
	if err != nil {
		t.Fatal(err)
	}
	plan := sshtrustrollout.Plan{Name: subject, Reason: "Requested by " + subject, PublicCAKey: public, CAFingerprint: fp, ExpiresAt: time.Now().UTC().Add(time.Minute), Hosts: []sshtrustrollout.Host{{AgentID: "a2260000-0000-4000-8000-000000000001", State: "ready", ReadinessDigest: "sha256:" + strings.Repeat("a", 64)}}}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	started := SSHTrustFleetStarted{ID: "a2260000-0000-4000-8000-000000000002", Plan: plan, PlanDigest: digest, Approval: store.OperationApprovalUse{RequestID: "a2260000-0000-4000-8000-000000000003", IntentDigest: "sha256:" + strings.Repeat("b", 64), Requester: subject, ResourceKind: "ssh_trust_rollout", ResourceID: sshtrustrollout.ResourceID(digest), Action: "apply", FromState: "planned", ToState: "queued", TargetVersion: 1, RequiredApprovals: 2, Reason: plan.Reason, EvidenceRefs: []string{digest}}}
	raw, err := json.Marshal(started)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, changed, err := events.PseudonymizeEventDataForSubject(raw, tenant, subject, EventSSHTrustFleetStarted, 1)
	if err != nil || !changed {
		t.Fatalf("rewrite changed=%v err=%v", changed, err)
	}
	if strings.Contains(string(rewritten), subject) {
		t.Fatal("personal reviewer text remained")
	}
	var got SSHTrustFleetStarted
	if err := json.Unmarshal(rewritten, &got); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSSHTrustFleetStarted(got); err != nil {
		t.Fatalf("authorized privacy rewrite blocked event replay: %v", err)
	}
	if got.PlanDigest != digest || got.Plan.CAFingerprint != fp || got.Plan.Hosts[0] != plan.Hosts[0] {
		t.Fatal("privacy rewrite changed approved host effect")
	}
	if err := got.Plan.ExecutionWindow(time.Now().UTC()); err == nil {
		t.Fatal("erased historical metadata authorized a fresh review")
	}
}
