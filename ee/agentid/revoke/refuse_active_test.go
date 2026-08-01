// SPDX-License-Identifier: LicenseRef-trstctl-EE

package revoke_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/agentid/delegation"
	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/ee/agentid/revoke"
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
// It also asserts RENEWAL is not exempt: a renewal re-verifies the chain through this same
// gate, so a renewal whose chain includes the subject is refused exactly like a fresh
// issuance (§7.4). And it asserts the refusal is scoped to the ACTIVE window: once the
// directive is terminal (revoked-with-evidence), the reader lifts and a fresh chain over
// the same record is approved.
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

	// Scope check: once the directive is TERMINAL (revoked-with-evidence), the reader lifts
	// (its cascade has fully evidenced), so a fresh chain over the same record is approved —
	// the refusal is bounded to the ACTIVE window, not forever.
	flipDirectiveTerminal(t, h, tenantA, directiveID)

	afterDec, err := gate.VerifyIssuancePreconditions(ctx, req)
	if err != nil {
		t.Fatalf("VerifyIssuancePreconditions (post-terminal): %v", err)
	}
	if !afterDec.Approved {
		if a, _ := delegation.DecodeRefusal(afterDec.RefusalRecord); a.FailedCheck == delegation.CheckRevocation {
			t.Fatal("chain still refused at CheckRevocation after the directive went terminal (refusal not scoped to the active window)")
		}
		t.Fatalf("post-terminal issuance not approved (unexpected refusal): %+v", afterDec)
	}
}

// flipDirectiveTerminal marks a directive terminal via the AGID-02 store helper, so the
// directive-backed reader stops reporting the subject as under an active directive. It is
// the durable transition the terminal engine performs; the test flips it directly to
// assert the reader's active-window scoping without driving a full cascade.
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
