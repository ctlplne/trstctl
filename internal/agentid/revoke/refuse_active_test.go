// SPDX-License-Identifier: BUSL-1.1

package revoke_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agentid/delegation"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/agentid/revoke"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// TestRevoke_SignerRefusesWhileDirectiveActive: while a revocation directive is ACTIVE
// against a delegation record of a chain, the isolated signing process REFUSES any
// issuance OR renewal whose chain includes the subject (AGID-claim-20 / INV-A9). This REUSES
// the AGID-04 gate seam — the same signing.IssuanceGate the signer consults before any
// key op — with AGID-11's directive-backed RevocationReader supplied as the per-hop
// non-revocation reader. There is NO new internal/signing option and NO new gate check:
// the extension is entirely in what the reader answers. Instrumented as AGID-04b: the
// refusal names CheckRevocation and NO key op runs (an issued-key op would panic the fake
// keystore, so a bare refusal decision with zero key ops is the assertion).
//
// Renewal re-verifies the same chain, and terminal cascade completion leaves the
// revoked subject refused on all later attempts.
func TestRevoke_SignerRefusesWhileDirectiveActive(t *testing.T) {
	h := newHarness(t, "revoke_refuse_active")
	ctx := context.Background()

	// Build ONE real, signed, root-anchored delegation record: root -> agent "kill-subject".
	reg := (*delegation.ToolRegistry)(nil)
	be := crypto.NewSoftwareBackend()
	rootSigner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("root signer: %v", err)
	}
	rootDER := rootSigner.Public().DER

	rec := delegation.Record{
		TenantID:       tenantA,
		DelegatorID:    "root",
		DelegatorKey:   delegation.KeyRef{ID: "root-key", Algorithm: string(crypto.ECDSAP256)},
		DelegateID:     "kill-subject",
		Authority:      delegation.Authority{Scopes: []string{"read"}, Depth: 3},
		DepthRemaining: 3,
		Validity:       delegation.Window{}, // open window: always valid
		RootAnchor:     true,
	}
	signedRec, err := rec.Sign(rootSigner, reg)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}
	hopDigest, err := signedRec.Digest(reg)
	if err != nil {
		t.Fatalf("record digest: %v", err)
	}

	// Seed the AGID-02 delegation-record row whose record_digest == the hop digest and
	// whose delegate is the subject, so the directive-backed reader can map the hop to the
	// subject. (In production this row is folded from the ledger; here we seed it directly.)
	if err := h.repo.InsertDelegationRecord(ctx, tenantA, agidstore.DelegationRecord{
		RecordDigest:   hopDigest,
		RootAnchor:     true,
		DelegatorID:    "root",
		DelegateID:     "kill-subject",
		DepthRemaining: 3,
		Encoded:        []byte("seed"),
		Seq:            1,
	}); err != nil {
		t.Fatalf("seed delegation record row: %v", err)
	}

	// Record an ACTIVE (non-terminal) revocation directive naming the subject.
	const directiveID = "dir-active"
	if err := h.repo.InsertRevocationDirectiveWithJobs(ctx, tenantA, agidstore.RevocationDirective{
		DirectiveID: directiveID,
		SubjectID:   "kill-subject",
		Reason:      string(revoke.ReasonCompromise),
		Watermark:   1,
		Terminal:    false,
	}, nil); err != nil {
		t.Fatalf("seed active directive: %v", err)
	}

	// The directive-backed reader (CONTROL-PLANE, SQL-backed) is handed to the gate as the
	// per-hop non-revocation reader — the AGID-04 seam, no new core option.
	reader := revoke.NewDirectiveRevocationReader(h.repo, ctx)

	// Compile-time proof the reader satisfies the signer-facing interface (kept in the
	// test so the revoke package never imports the signer seam).
	var _ delegation.RevocationReader = reader

	// Build the gate exactly as AGID-04b does, with the directive-backed reader.
	refusalSigner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("refusal signer: %v", err)
	}
	gate, err := delegation.NewGate(delegation.Config{
		SignerID:      "test-signer",
		Roots:         delegation.NewTrustStore(map[string]delegation.RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: "fido2:root"}}),
		RefusalSigner: refusalSigner,
		Revocations:   reader,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	// Encode the issuance preconditions carrying the one-hop chain.
	pre, err := delegation.EncodePreconditionsBody(delegation.PreconditionsBody{
		Chain: []delegation.RecordEnvelope{{Record: signedRec, DelegatorPublicDER: rootDER}},
	})
	if err != nil {
		t.Fatalf("encode preconditions: %v", err)
	}
	req := signing.IssuancePreconditions{TenantID: tenantA, TrustAnchorRef: "kill-subject", Preconditions: pre}

	// ISSUANCE while the directive is active ⇒ refused INSIDE the gate at CheckRevocation,
	// with ZERO key ops (the gate returns before any keyOp; a key op is never reached).
	dec, err := gate.VerifyIssuancePreconditions(ctx, req)
	if err != nil {
		t.Fatalf("VerifyIssuancePreconditions (issuance): %v", err)
	}
	if dec.Approved {
		t.Fatal("issuance APPROVED while a directive is active against the subject (AGID-claim-20 violated)")
	}
	if len(dec.RefusalRecord) == 0 {
		t.Fatal("refused issuance carries no signed refusal record")
	}
	art, err := delegation.DecodeRefusal(dec.RefusalRecord)
	if err != nil {
		t.Fatalf("decode refusal: %v", err)
	}
	if art.FailedCheck != delegation.CheckRevocation {
		t.Fatalf("failed_check = %q, want %q (the active-directive refusal)", art.FailedCheck, delegation.CheckRevocation)
	}

	// RENEWAL is not exempt: a renewal re-verifies the SAME chain through the SAME gate, so
	// it is refused identically. We model renewal as the same precondition verification the
	// renewal path (AGID-07) runs — the gate has no separate "renew" entry; re-verifying
	// the chain IS the renewal check. It must refuse at CheckRevocation too.
	renewDec, err := gate.VerifyIssuancePreconditions(ctx, req)
	if err != nil {
		t.Fatalf("VerifyIssuancePreconditions (renewal): %v", err)
	}
	if renewDec.Approved {
		t.Fatal("RENEWAL approved while a directive is active against the subject (§7.4 violated)")
	}
	if renewArt, _ := delegation.DecodeRefusal(renewDec.RefusalRecord); renewArt.FailedCheck != delegation.CheckRevocation {
		t.Fatalf("renewal failed_check = %q, want %q", renewArt.FailedCheck, delegation.CheckRevocation)
	}

	// CR-053: terminal means the cascade finished; it must not restore the revoked
	// subject's authority to mint a new credential.
	flipDirectiveTerminal(t, h, tenantA, directiveID)

	afterDec, err := gate.VerifyIssuancePreconditions(ctx, req)
	if err != nil {
		t.Fatalf("VerifyIssuancePreconditions (post-terminal): %v", err)
	}
	if afterDec.Approved {
		t.Fatal("CR-053: terminal directive restored the revoked subject's issuance authority")
	}
	if a, _ := delegation.DecodeRefusal(afterDec.RefusalRecord); a.FailedCheck != delegation.CheckRevocation {
		t.Fatalf("post-terminal refusal failed_check = %q, want %q", a.FailedCheck, delegation.CheckRevocation)
	}
}

func TestCR053UnrecordedDescendantOfRevokedSubjectIsRefused(t *testing.T) {
	h := newHarness(t, "cr053_unrecorded_descendant")
	ctx := context.Background()
	be := crypto.NewSoftwareBackend()
	rootSigner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	refusalSigner, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	root := delegation.Record{
		TenantID: tenantA, DelegatorID: "revoked-root", DelegateID: "child",
		DelegatorKey:   delegation.KeyRef{ID: "root-key", Algorithm: string(crypto.ECDSAP256)},
		Authority:      delegation.Authority{Scopes: []string{"read"}, Depth: 3},
		DepthRemaining: 3, RootAnchor: true,
	}
	root, err = root.Sign(rootSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	// This signed hop is deliberately absent from the projection: an attacker can
	// present it straight to the signer after the directive was committed.
	if err := h.repo.InsertRevocationDirectiveWithJobs(ctx, tenantA, agidstore.RevocationDirective{
		DirectiveID: "cr053-root", SubjectID: "revoked-root", Reason: string(revoke.ReasonCompromise),
		Watermark: 1, Terminal: true,
	}, nil); err != nil {
		t.Fatal(err)
	}
	gate, err := delegation.NewGate(delegation.Config{
		SignerID: "test-signer", RefusalSigner: refusalSigner,
		Roots: delegation.NewTrustStore(map[string]delegation.RootAnchor{
			"root-key": {PublicDER: rootSigner.Public().DER, AuthRef: "fido2:root"},
		}),
		Revocations: revoke.NewDirectiveRevocationReader(h.repo, ctx),
	})
	if err != nil {
		t.Fatal(err)
	}
	pre, err := delegation.EncodePreconditionsBody(delegation.PreconditionsBody{
		Chain: []delegation.RecordEnvelope{{Record: root, DelegatorPublicDER: rootSigner.Public().DER}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := gate.VerifyIssuancePreconditions(ctx, signing.IssuancePreconditions{
		TenantID: tenantA, TrustAnchorRef: "child", Preconditions: pre,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Approved {
		t.Fatal("CR-053: unrecorded hop signed by a revoked subject was approved")
	}
	if a, _ := delegation.DecodeRefusal(dec.RefusalRecord); a.FailedCheck != delegation.CheckRevocation {
		t.Fatalf("failed_check = %q, want %q", a.FailedCheck, delegation.CheckRevocation)
	}

	// The subject's previously observed key must remain revoked even if that
	// same key signs a new root hop under a different textual subject ID.
	encoded, err := json.Marshal(delegation.RecordEnvelope{Record: root, DelegatorPublicDER: rootSigner.Public().DER})
	if err != nil {
		t.Fatal(err)
	}
	priorDigest, err := root.Digest(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.repo.InsertDelegationRecord(ctx, tenantA, agidstore.DelegationRecord{
		RecordDigest: priorDigest, RootAnchor: true, DelegatorID: "revoked-root", DelegateID: "child",
		DepthRemaining: 3, Encoded: encoded, Seq: 1,
	}); err != nil {
		t.Fatal(err)
	}
	alias := root
	alias.DelegatorID = "fresh-alias"
	alias.Signature = nil
	alias, err = alias.Sign(rootSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	aliasPre, err := delegation.EncodePreconditionsBody(delegation.PreconditionsBody{
		Chain: []delegation.RecordEnvelope{{Record: alias, DelegatorPublicDER: rootSigner.Public().DER}},
	})
	if err != nil {
		t.Fatal(err)
	}
	aliasDec, err := gate.VerifyIssuancePreconditions(ctx, signing.IssuancePreconditions{
		TenantID: tenantA, TrustAnchorRef: "child", Preconditions: aliasPre,
	})
	if err != nil {
		t.Fatal(err)
	}
	if aliasDec.Approved {
		t.Fatal("CR-053: revoked subject's key minted under a new subject alias")
	}
	reader := revoke.NewDirectiveRevocationReader(h.repo, ctx)
	otherTenantRevoked, err := reader.IsKeyRevoked(tenantB, delegation.DelegateKeyThumbprintOf(rootSigner.Public().DER))
	if err != nil || otherTenantRevoked {
		t.Fatalf("tenant B inherited tenant A's revoked key: revoked=%t err=%v", otherTenantRevoked, err)
	}
}

// flipDirectiveTerminal models the cascade's completed transition. It must not
// reauthorize the revoked identity.
func flipDirectiveTerminal(t *testing.T, h *harness, tenant, directiveID string) {
	t.Helper()
	err := h.core.WithTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		_, err := agidstore.MarkDirectiveTerminalTx(context.Background(), tx, directiveID, 1)
		return err
	})
	if err != nil {
		t.Fatalf("flip directive terminal: %v", err)
	}
}
