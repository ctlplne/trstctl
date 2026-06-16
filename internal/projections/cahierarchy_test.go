package projections_test

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca/hierarchy"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func caHierCSR(t *testing.T, cn string, sans []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: sans}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// quorum starts a ceremony and approves it with n distinct custodians.
func quorum(t *testing.T, m *hierarchy.Manager, tenantID, purpose string, threshold, approvals int) string {
	t.Helper()
	ctx := context.Background()
	id, err := m.StartCeremony(ctx, tenantID, purpose, threshold)
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}
	custodians := []string{"alice", "bob", "carol", "dave", "erin"}
	for i := 0; i < approvals; i++ {
		if _, err := m.Approve(ctx, tenantID, id, custodians[i]); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	}
	return id
}

// TestKeyCeremonyRequiresQuorum is the acceptance "the key ceremony requires
// quorum": creating a CA before the m-of-n threshold is met is rejected; once the
// threshold is met it succeeds.
func TestKeyCeremonyRequiresQuorum(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	ceremony := quorum(t, m, tenantA, "root:Acme Root CA", 3, 2) // only 2 of 3 approvals
	if _, err := m.CreateRoot(ctx, tenantA, ceremony, hierarchy.CASpec{CommonName: "Acme Root CA", TTL: 10 * 365 * 24 * time.Hour}); !errors.Is(err, hierarchy.ErrQuorumNotMet) {
		t.Fatalf("CreateRoot without quorum err = %v, want ErrQuorumNotMet", err)
	}

	if _, err := m.Approve(ctx, tenantA, ceremony, "carol"); err != nil { // the third approval
		t.Fatal(err)
	}
	root, err := m.CreateRoot(ctx, tenantA, ceremony, hierarchy.CASpec{CommonName: "Acme Root CA", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot with quorum: %v", err)
	}
	if root.ID == "" || root.Kind != "root" || root.Status != "active" {
		t.Fatalf("root = %+v", root)
	}
}

// TestKeyCeremonySeparationOfDuties is the PKIGOV-006 acceptance: a ceremony's
// opener may not approve their own ceremony (opener != approver), and an
// approval must carry a named, authenticated custodian — not an empty/anonymous
// string. The opener and approver identities are bound from the request context's
// actor, so they cannot be spoofed by a caller-chosen string on the served path.
//
// These checks FAIL on the pre-fix tree, which recorded no opener and accepted any
// custodian string (a single operator could open and self-approve, defeating
// m-of-n).
func TestKeyCeremonySeparationOfDuties(t *testing.T) {
	s := newStore(t)
	m := hierarchy.NewManager(s, openLog(t))

	// Alice opens the ceremony (actor bound from context).
	aliceCtx := events.ContextWithActor(context.Background(), events.Actor{Subject: "alice"})
	id, err := m.StartCeremony(aliceCtx, tenantA, "root:SoD Root", 2)
	if err != nil {
		t.Fatalf("StartCeremony: %v", err)
	}

	// The opener cannot approve their own ceremony: opener == approver is rejected.
	if _, err := m.Approve(aliceCtx, tenantA, id, "alice"); !errors.Is(err, store.ErrSelfApproval) {
		t.Fatalf("opener self-approval err = %v, want ErrSelfApproval", err)
	}
	// Confirm the rejected self-approval did NOT record an approval.
	cer, err := s.GetKeyCeremony(context.Background(), tenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	if cer.Approvals != 0 {
		t.Fatalf("a rejected self-approval was recorded: approvals = %d, want 0", cer.Approvals)
	}
	if cer.Opener != "alice" {
		t.Errorf("ceremony opener = %q, want alice (opener not bound)", cer.Opener)
	}

	// A distinct, authenticated custodian (bob) is accepted.
	bobCtx := events.ContextWithActor(context.Background(), events.Actor{Subject: "bob"})
	n, err := m.Approve(bobCtx, tenantA, id, "ignored-the-actor-wins")
	if err != nil {
		t.Fatalf("bob Approve: %v", err)
	}
	if n != 1 {
		t.Fatalf("after bob's approval count = %d, want 1", n)
	}

	// An anonymous approval (no actor, empty custodian) is rejected.
	if _, err := m.Approve(context.Background(), tenantA, id, ""); !errors.Is(err, store.ErrAnonymousApproval) {
		t.Errorf("anonymous approval err = %v, want ErrAnonymousApproval", err)
	}
}

// TestRootIntermediateAndEndEntity is the acceptance "create a root and an
// intermediate; issue an end-entity cert from the internal CA".
func TestRootIntermediateAndEndEntity(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root", 2, 2),
		hierarchy.CASpec{CommonName: "Acme Root CA", MaxPathLen: 1, TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	inter, err := m.CreateIntermediate(ctx, tenantA, quorum(t, m, tenantA, "intermediate", 2, 2), root.ID,
		hierarchy.CASpec{CommonName: "Acme Issuing CA", TTL: 5 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateIntermediate: %v", err)
	}
	if inter.Kind != "intermediate" || inter.ParentID == nil || *inter.ParentID != root.ID {
		t.Fatalf("intermediate = %+v", inter)
	}

	chain, err := m.IssueEndEntity(ctx, tenantA, inter.ID, caHierCSR(t, "svc.corp.internal", []string{"svc.corp.internal"}), 90*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueEndEntity: %v", err)
	}
	info, err := certinfo.Inspect(chain)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	found := false
	for _, n := range info.DNSNames {
		if n == "svc.corp.internal" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued cert SANs = %v, want svc.corp.internal", info.DNSNames)
	}
}

// TestInternalCAConstraintViolationRejected is the acceptance "constraints are
// enforced (a violating issuance is rejected)".
func TestInternalCAConstraintViolationRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root", 1, 1),
		hierarchy.CASpec{CommonName: "Corp Root CA", PermittedDNSDomains: []string{"corp.internal"}, TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	if _, err := m.IssueEndEntity(ctx, tenantA, root.ID, caHierCSR(t, "ok", []string{"ok.corp.internal"}), time.Hour); err != nil {
		t.Errorf("a permitted issuance was rejected: %v", err)
	}
	if _, err := m.IssueEndEntity(ctx, tenantA, root.ID, caHierCSR(t, "evil", []string{"evil.example.com"}), time.Hour); err == nil {
		t.Error("an issuance violating the name constraints was accepted")
	}
}

// TestCARotationCompletes is the acceptance "a CA-cert rotation completes".
func TestCARotationCompletes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root", 1, 1),
		hierarchy.CASpec{CommonName: "Rotate Root CA", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	fresh, err := m.Rotate(ctx, tenantA, root.ID, quorum(t, m, tenantA, "rotate", 1, 1))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if fresh.ID == root.ID || fresh.Status != "active" {
		t.Fatalf("rotated CA = %+v", fresh)
	}
	if fresh.ReplacesID == nil || *fresh.ReplacesID != root.ID {
		t.Errorf("rotated CA replaces_id = %v, want %s", fresh.ReplacesID, root.ID)
	}
	old, err := s.GetCAAuthority(ctx, tenantA, root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != "superseded" {
		t.Errorf("old CA status = %q, want superseded", old.Status)
	}
}

// TestCrossSignRequiresQuorum is the PKIGOV-003 acceptance: cross-signing is gated
// by the m-of-n key ceremony, like CreateRoot / CreateIntermediate / Rotate.
// Cross-signing below the threshold is refused with ErrQuorumNotMet; once the
// threshold is met it succeeds and produces a cross-certificate carrying the
// target CA's subject and public key. Before the fix CrossSign had no quorum gate,
// so a single caller could unilaterally extend trust — contradicting the docs.
func TestCrossSignRequiresQuorum(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	// Two independent roots: one is our signing CA, the other is the foreign CA we
	// will cross-sign.
	signer, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root:signer", 1, 1),
		hierarchy.CASpec{CommonName: "Signer Root CA", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot signer: %v", err)
	}
	foreign, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root:foreign", 1, 1),
		hierarchy.CASpec{CommonName: "Foreign Root CA", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot foreign: %v", err)
	}
	foreignDER := firstCertDER(t, foreign.CertificatePEM)

	// Below quorum: a 3-of-n cross-sign ceremony with only 2 approvals is refused.
	short := quorum(t, m, tenantA, "cross-sign", 3, 2)
	if _, err := m.CrossSign(ctx, tenantA, short, signer.ID, foreignDER); !errors.Is(err, hierarchy.ErrQuorumNotMet) {
		t.Fatalf("CrossSign below quorum err = %v, want ErrQuorumNotMet", err)
	}

	// The third approval reaches quorum; the cross-sign now succeeds.
	if _, err := m.Approve(ctx, tenantA, short, "carol"); err != nil {
		t.Fatal(err)
	}
	crossPEM, err := m.CrossSign(ctx, tenantA, short, signer.ID, foreignDER)
	if err != nil {
		t.Fatalf("CrossSign with quorum: %v", err)
	}
	info, err := certinfo.Inspect(crossPEM)
	if err != nil {
		t.Fatalf("inspect cross-cert: %v", err)
	}
	// The cross-certificate carries the foreign CA's subject (re-signed under ours).
	if info.Subject == "" || info.Subject != foreignSubject(t, foreignDER) {
		t.Errorf("cross-cert subject = %q, want the foreign CA subject", info.Subject)
	}
	if !info.IsCA {
		t.Error("a cross-certificate must be a CA certificate")
	}
}

// firstCertDER decodes the first PEM CERTIFICATE block (the CA's own cert) to DER.
func firstCertDER(t *testing.T, chainPEM string) []byte {
	t.Helper()
	blk, _ := pem.Decode([]byte(chainPEM))
	if blk == nil {
		t.Fatal("CA CertificatePEM has no PEM block")
	}
	return blk.Bytes
}

// foreignSubject inspects a CA cert (DER) and returns its subject for comparison.
func foreignSubject(t *testing.T, der []byte) string {
	t.Helper()
	info, err := certinfo.Inspect(der)
	if err != nil {
		t.Fatal(err)
	}
	return info.Subject
}

// TestCAHierarchyTenantIsolation is the AN-1 acceptance for the new tables: a CA
// created in one tenant is invisible to another.
func TestCAHierarchyTenantIsolation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, "root", 1, 1),
		hierarchy.CASpec{CommonName: "Tenant A Root", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	if cas, err := s.ListCAAuthorities(ctx, tenantB); err != nil {
		t.Fatal(err)
	} else if len(cas) != 0 {
		t.Errorf("tenant B sees %d CA authorities, want 0 (RLS must isolate)", len(cas))
	}
	if _, err := s.GetCAAuthority(ctx, tenantB, root.ID); !store.IsNotFound(err) {
		t.Errorf("tenant B could read tenant A's CA (err=%v); RLS must deny it", err)
	}
}
