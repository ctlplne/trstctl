package projections_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca/hierarchy"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
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

	spec := hierarchy.CASpec{CommonName: "Acme Root CA", TTL: 10 * 365 * 24 * time.Hour}
	ceremony := quorum(t, m, tenantA, hierarchy.PurposeRoot(spec), 3, 2) // only 2 of 3 approvals
	if _, err := m.CreateRoot(ctx, tenantA, ceremony, spec); !errors.Is(err, hierarchy.ErrQuorumNotMet) {
		t.Fatalf("CreateRoot without quorum err = %v, want ErrQuorumNotMet", err)
	}

	if _, err := m.Approve(ctx, tenantA, ceremony, "carol"); err != nil { // the third approval
		t.Fatal(err)
	}
	root, err := m.CreateRoot(ctx, tenantA, ceremony, spec)
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
	id, err := m.StartCeremony(aliceCtx, tenantA, hierarchy.PurposeRoot(hierarchy.CASpec{CommonName: "SoD Root", TTL: time.Hour}), 2)
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

	rootSpec := hierarchy.CASpec{CommonName: "Acme Root CA", MaxPathLen: 1, TTL: 10 * 365 * 24 * time.Hour}
	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, hierarchy.PurposeRoot(rootSpec), 2, 2), rootSpec)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	interSpec := hierarchy.CASpec{CommonName: "Acme Issuing CA", TTL: 5 * 365 * 24 * time.Hour}
	inter, err := m.CreateIntermediate(ctx, tenantA, quorum(t, m, tenantA, hierarchy.PurposeIntermediate(root.ID, interSpec), 2, 2), root.ID, interSpec)
	if err != nil {
		t.Fatalf("CreateIntermediate: %v", err)
	}
	if inter.Kind != "intermediate" || inter.ParentID == nil || *inter.ParentID != root.ID {
		t.Fatalf("intermediate = %+v", inter)
	}

	// PKIGOV-002: a hierarchy-issued leaf must carry the SAME served
	// certificate-profile shape as broker issuance — CRL DP, AIA (OCSP +
	// CA-issuers), certificatePolicies, SKI, AKI — not the bare legacy leaf.
	prof := crypto.LeafProfile{
		CRLDistributionPoints: []string{"http://crl.corp.internal/issuing.crl"},
		OCSPServers:           []string{"http://ocsp.corp.internal"},
		IssuingCertificateURL: []string{"http://pki.corp.internal/issuing.crt"},
		CertificatePolicyOIDs: []string{"1.3.6.1.4.1.59551.1.1"},
		MaxValidity:           398 * 24 * time.Hour,
	}
	chain, err := m.IssueEndEntity(ctx, tenantA, inter.ID, caHierCSR(t, "svc.corp.internal", []string{"svc.corp.internal"}), 90*24*time.Hour, prof)
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
	if info.SubjectKeyID == "" {
		t.Error("hierarchy leaf is missing the Subject Key Identifier (PKIGOV-002)")
	}
	if info.AuthorityKeyID == "" {
		t.Error("hierarchy leaf is missing the Authority Key Identifier (PKIGOV-002)")
	}
	if len(info.CRLDistributionPoints) == 0 {
		t.Error("hierarchy leaf is missing CRL distribution points (PKIGOV-002)")
	}
	if len(info.OCSPServers) == 0 {
		t.Error("hierarchy leaf is missing the OCSP AIA (PKIGOV-002)")
	}
	if len(info.IssuingCertificateURL) == 0 {
		t.Error("hierarchy leaf is missing the CA-issuers AIA (PKIGOV-002)")
	}
}

// TestInternalCAConstraintViolationRejected is the acceptance "constraints are
// enforced (a violating issuance is rejected)".
func TestInternalCAConstraintViolationRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	rootSpec := hierarchy.CASpec{CommonName: "Corp Root CA", PermittedDNSDomains: []string{"corp.internal"}, TTL: 10 * 365 * 24 * time.Hour}
	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, hierarchy.PurposeRoot(rootSpec), 1, 1), rootSpec)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	if _, err := m.IssueEndEntity(ctx, tenantA, root.ID, caHierCSR(t, "ok", []string{"ok.corp.internal"}), time.Hour, crypto.LeafProfile{}); err != nil {
		t.Errorf("a permitted issuance was rejected: %v", err)
	}
	if _, err := m.IssueEndEntity(ctx, tenantA, root.ID, caHierCSR(t, "evil", []string{"evil.example.com"}), time.Hour, crypto.LeafProfile{}); err == nil {
		t.Error("an issuance violating the name constraints was accepted")
	}
}

// TestCARotationCompletes is the acceptance "a CA-cert rotation completes".
func TestCARotationCompletes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	m := hierarchy.NewManager(s, openLog(t))

	rootSpec := hierarchy.CASpec{CommonName: "Rotate Root CA", TTL: 10 * 365 * 24 * time.Hour}
	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, hierarchy.PurposeRoot(rootSpec), 1, 1), rootSpec)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}

	fresh, err := m.Rotate(ctx, tenantA, root.ID, quorum(t, m, tenantA, hierarchy.PurposeRotate(root.ID), 1, 1))
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

func TestCAAuthorityRotatedEventProjectsReadModel(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	predecessor, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantA, CommonName: "rotation predecessor", Kind: "intermediate", Status: "active",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nPREDECESSOR\n-----END CERTIFICATE-----\n",
		SignerHandle:   "signer-predecessor", Serial: "predecessor-1", MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("insert predecessor: %v", err)
	}
	successor, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantA, CommonName: "rotation successor", Kind: "intermediate", Status: "active",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nSUCCESSOR\n-----END CERTIFICATE-----\n",
		SignerHandle:   "signer-successor", Serial: "successor-1", MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("insert successor: %v", err)
	}
	payload, err := json.Marshal(projections.CAAuthorityRotated{
		PredecessorCAID: predecessor.ID,
		SuccessorCAID:   successor.ID,
		Reason:          "projection regression",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, events.Event{
		Type:     projections.EventCAAuthorityRotated,
		TenantID: tenantA,
		Data:     payload,
	}); err != nil {
		t.Fatalf("apply rotation event: %v", err)
	}
	gotPredecessor, err := s.GetCAAuthority(ctx, tenantA, predecessor.ID)
	if err != nil {
		t.Fatal(err)
	}
	gotSuccessor, err := s.GetCAAuthority(ctx, tenantA, successor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotPredecessor.Status != "superseded" {
		t.Errorf("predecessor status = %q, want superseded", gotPredecessor.Status)
	}
	if gotSuccessor.ReplacesID == nil || *gotSuccessor.ReplacesID != predecessor.ID {
		t.Errorf("successor replaces_id = %v, want %s", gotSuccessor.ReplacesID, predecessor.ID)
	}
}

func TestCAAuthorityRekeyedEventProjectsReadModel(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	predecessor, err := s.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantA, CommonName: "re-key predecessor", Kind: "intermediate", Status: "active",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nPREDECESSOR\n-----END CERTIFICATE-----\n",
		SignerHandle:   "signer-predecessor", Serial: "predecessor-1", MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("insert predecessor: %v", err)
	}
	notAfter := time.Now().UTC().Add(365 * 24 * time.Hour)
	payload, err := json.Marshal(projections.CAAuthorityRekeyed{
		ID: "00000000-0000-4000-8000-000000000052", PredecessorCAID: predecessor.ID,
		CommonName: "re-key predecessor", Kind: "intermediate",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nSUCCESSOR\n-----END CERTIFICATE-----\n",
		SignerHandle:   "signer-rekeyed", Serial: "successor-1", NotAfter: notAfter,
		MaxPathLen: 0, PermittedDNSNames: []string{"example.test"}, EKUs: []string{"serverAuth"},
		CeremonyID: "00000000-0000-4000-8000-000000000053",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(s).Apply(ctx, events.Event{
		Type:     projections.EventCAAuthorityRekeyed,
		TenantID: tenantA,
		Time:     notAfter.Add(-time.Hour),
		Data:     payload,
	}); err != nil {
		t.Fatalf("apply re-key event: %v", err)
	}
	gotPredecessor, err := s.GetCAAuthority(ctx, tenantA, predecessor.ID)
	if err != nil {
		t.Fatal(err)
	}
	gotSuccessor, err := s.GetCAAuthority(ctx, tenantA, "00000000-0000-4000-8000-000000000052")
	if err != nil {
		t.Fatal(err)
	}
	if gotPredecessor.Status != "superseded" {
		t.Errorf("predecessor status = %q, want superseded", gotPredecessor.Status)
	}
	if gotSuccessor.ReplacesID == nil || *gotSuccessor.ReplacesID != predecessor.ID {
		t.Errorf("successor replaces_id = %v, want %s", gotSuccessor.ReplacesID, predecessor.ID)
	}
	if gotSuccessor.SignerHandle != "signer-rekeyed" || gotSuccessor.CertificatePEM == predecessor.CertificatePEM {
		t.Errorf("successor = %+v; want fresh signer/certificate", gotSuccessor)
	}
}

func TestCAAuthorityCreateReplaysFromEvent(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	now := time.Now().UTC().Truncate(time.Second)

	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "Acme"})
	rootCeremonyID := "10000000-0000-4000-8000-000000000801"
	intermediateCeremonyID := "10000000-0000-4000-8000-000000000802"
	importCeremonyID := "10000000-0000-4000-8000-000000000803"
	appendJSONEvent(t, log, projections.EventCACeremonyStarted, tenantA, projections.CACeremonyStarted{
		CeremonyID: rootCeremonyID, Purpose: "root:replay", Threshold: 1, Opener: "operator",
	})
	appendJSONEvent(t, log, projections.EventCACeremonyApproved, tenantA, projections.CACeremonyApproved{
		CeremonyID: rootCeremonyID, Custodian: "custodian",
	})
	appendJSONEvent(t, log, projections.EventCACeremonyStarted, tenantA, projections.CACeremonyStarted{
		CeremonyID: intermediateCeremonyID, Purpose: "intermediate:replay", Threshold: 1, Opener: "operator",
	})
	appendJSONEvent(t, log, projections.EventCACeremonyApproved, tenantA, projections.CACeremonyApproved{
		CeremonyID: intermediateCeremonyID, Custodian: "custodian",
	})
	appendJSONEvent(t, log, projections.EventCACeremonyStarted, tenantA, projections.CACeremonyStarted{
		CeremonyID: importCeremonyID, Purpose: "import:replay", Threshold: 1, Opener: "operator",
	})
	appendJSONEvent(t, log, projections.EventCACeremonyApproved, tenantA, projections.CACeremonyApproved{
		CeremonyID: importCeremonyID, Custodian: "custodian",
	})

	rootID := "00000000-0000-4000-8000-00000000c801"
	intermediateID := "00000000-0000-4000-8000-00000000c802"
	importedID := "00000000-0000-4000-8000-00000000c803"
	appendVersionedJSONEvent(t, log, projections.EventCARootCreated, tenantA, projections.CAAuthorityCreatedEventSchemaVersion, projections.CAAuthorityCreated{
		CAID: rootID, CommonName: "Replay Root", Kind: "root",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n",
		SignerHandle:   "ca-hierarchy-" + rootCeremonyID,
		Serial:         "root-serial", NotAfter: now.Add(365 * 24 * time.Hour), MaxPathLen: 1,
		PermittedDNSNames: []string{"svc.example.test"}, EKUs: []string{"serverAuth"}, CeremonyID: rootCeremonyID,
	})
	appendVersionedJSONEvent(t, log, projections.EventCAIntermediateCreated, tenantA, projections.CAAuthorityCreatedEventSchemaVersion, projections.CAAuthorityCreated{
		CAID: intermediateID, ParentID: &rootID, CommonName: "Replay Intermediate", Kind: "intermediate",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n",
		SignerHandle:   "ca-hierarchy-" + intermediateCeremonyID,
		Serial:         "intermediate-serial", NotAfter: now.Add(180 * 24 * time.Hour), MaxPathLen: 0,
		PermittedDNSNames: []string{"svc.example.test"}, EKUs: []string{"serverAuth"}, CeremonyID: intermediateCeremonyID,
	})
	appendVersionedJSONEvent(t, log, projections.EventCAAuthorityImported, tenantA, projections.CAAuthorityCreatedEventSchemaVersion, projections.CAAuthorityCreated{
		CAID: importedID, CommonName: "Imported Existing", Kind: "root",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nIMPORTED\n-----END CERTIFICATE-----\n",
		SignerHandle:   "imported-existing-handle",
		Serial:         "imported-serial", NotAfter: now.Add(90 * 24 * time.Hour), MaxPathLen: 0,
		CeremonyID: importCeremonyID, ChainSHA256: "imported-chain-digest",
	})

	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	for _, tc := range []struct {
		id           string
		kind         string
		cn           string
		signerHandle string
	}{
		{id: rootID, kind: "root", cn: "Replay Root", signerHandle: "ca-hierarchy-" + rootCeremonyID},
		{id: intermediateID, kind: "intermediate", cn: "Replay Intermediate", signerHandle: "ca-hierarchy-" + intermediateCeremonyID},
		{id: importedID, kind: "root", cn: "Imported Existing", signerHandle: "imported-existing-handle"},
	} {
		got, err := s.GetCAAuthority(ctx, tenantA, tc.id)
		if err != nil {
			t.Fatalf("GetCAAuthority(%s): %v", tc.id, err)
		}
		if got.Kind != tc.kind || got.CommonName != tc.cn || got.SignerHandle != tc.signerHandle || got.Status != "active" {
			t.Fatalf("rebuilt authority %s = %+v", tc.id, got)
		}
	}
	gotIntermediate, err := s.GetCAAuthority(ctx, tenantA, intermediateID)
	if err != nil {
		t.Fatalf("GetCAAuthority(intermediate): %v", err)
	}
	if gotIntermediate.ParentID == nil || *gotIntermediate.ParentID != rootID {
		t.Fatalf("rebuilt intermediate parent = %v, want %s", gotIntermediate.ParentID, rootID)
	}
	for _, ceremonyID := range []string{rootCeremonyID, intermediateCeremonyID, importCeremonyID} {
		got, err := s.GetKeyCeremony(ctx, tenantA, ceremonyID)
		if err != nil {
			t.Fatalf("GetKeyCeremony(%s): %v", ceremonyID, err)
		}
		if got.Status != "completed" {
			t.Fatalf("rebuilt ceremony %s status=%q, want completed", ceremonyID, got.Status)
		}
	}
}

func appendVersionedJSONEvent(t *testing.T, log *events.Log, typ, tenantID string, version int, payload any) events.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", typ, err)
	}
	ev, err := log.Append(context.Background(), events.Event{Type: typ, TenantID: tenantID, SchemaVersion: version, Data: data})
	if err != nil {
		t.Fatalf("append %s: %v", typ, err)
	}
	return ev
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
	signerSpec := hierarchy.CASpec{CommonName: "Signer Root CA", TTL: 10 * 365 * 24 * time.Hour}
	signer, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, hierarchy.PurposeRoot(signerSpec), 1, 1), signerSpec)
	if err != nil {
		t.Fatalf("CreateRoot signer: %v", err)
	}
	foreignSpec := hierarchy.CASpec{CommonName: "Foreign Root CA", TTL: 10 * 365 * 24 * time.Hour}
	foreign, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, hierarchy.PurposeRoot(foreignSpec), 1, 1), foreignSpec)
	if err != nil {
		t.Fatalf("CreateRoot foreign: %v", err)
	}
	foreignDER := firstCertDER(t, foreign.CertificatePEM)

	// Below quorum: a 3-of-n cross-sign ceremony with only 2 approvals is refused.
	short := quorum(t, m, tenantA, hierarchy.PurposeCrossSign(signer.ID, foreignDER), 3, 2)
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

	rootSpec := hierarchy.CASpec{CommonName: "Tenant A Root", TTL: 365 * 24 * time.Hour}
	root, err := m.CreateRoot(ctx, tenantA, quorum(t, m, tenantA, hierarchy.PurposeRoot(rootSpec), 1, 1), rootSpec)
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
