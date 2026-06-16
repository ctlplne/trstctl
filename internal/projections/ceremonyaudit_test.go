package projections_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/ca/hierarchy"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
)

// TestCeremonyApprovalIsInSignedAuditBundle is the PKIGOV-010 acceptance: each
// key-ceremony approval act is emitted as a ca.ceremony.approved event on the AN-2
// log, so the four-eyes trail is part of the signed, hash-chained, offline-verifiable
// audit-evidence bundle — not only a row in the ca_key_ceremonies read table. An
// exported bundle for a CA creation must (1) verify via VerifyBundle and (2) contain
// an approval event per custodian naming who approved. Pre-fix Approve emitted no
// event, so the bundle carried only ca.root.created (the ceremony id, not the
// approvers) and this fails.
func TestCeremonyApprovalIsInSignedAuditBundle(t *testing.T) {
	log := openLog(t)
	s := newStore(t)
	m := hierarchy.NewManager(s, log)
	ctx := context.Background()

	// A signed-bundle audit service over the same event log.
	sk, err := jose.GenerateRSASigningKey("ceremony-audit-key")
	if err != nil {
		t.Fatal(err)
	}
	svc := audit.NewService(log, sk)

	// Open a 2-of-n ceremony with a named opener, then approve with two DISTINCT
	// authenticated custodians (opener != approver), then create the root.
	openerCtx := events.ContextWithActor(ctx, events.Actor{Subject: "opener@corp"})
	ceremony, err := m.StartCeremony(openerCtx, tenantA, "root:Audited Root", 2)
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}
	for _, custodian := range []string{"alice@corp", "bob@corp"} {
		cctx := events.ContextWithActor(ctx, events.Actor{Subject: custodian})
		if _, err := m.Approve(cctx, tenantA, ceremony, custodian); err != nil {
			t.Fatalf("Approve(%s): %v", custodian, err)
		}
	}
	root, err := m.CreateRoot(ctx, tenantA, ceremony,
		hierarchy.CASpec{CommonName: "Audited Root CA", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	// Export the signed evidence bundle and verify it cryptographically + by chain.
	signed, err := svc.Export(ctx, audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	bundle, err := audit.VerifyBundle(signed, svc.VerificationKeys())
	if err != nil {
		t.Fatalf("VerifyBundle: %v (a CA-creation evidence bundle must verify)", err)
	}

	// The bundle must contain a ca.ceremony.approved event for EACH custodian, naming
	// the approver — that is the four-eyes trail an auditor needs without trusting the
	// live DB.
	approvers := map[string]bool{}
	sawRootCreated := false
	for _, rec := range bundle.Records {
		switch rec.Type {
		case "ca.ceremony.approved":
			for _, want := range []string{"alice@corp", "bob@corp"} {
				if strings.Contains(string(rec.Data), want) {
					approvers[want] = true
				}
			}
		case "ca.root.created":
			sawRootCreated = true
		}
	}
	if !sawRootCreated {
		t.Error("bundle does not contain the ca.root.created event")
	}
	if !approvers["alice@corp"] || !approvers["bob@corp"] {
		t.Errorf("bundle missing the four-eyes approval trail; approvers found = %v (PKIGOV-010)", approvers)
	}
	_ = root
}
