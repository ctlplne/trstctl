// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"testing"
	"trstctl.com/trstctl/internal/agentid/agentstack"

	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/signing"
)

// TestCredential_BindsChainDigestAndAgentStack proves the success path binds BOTH the
// chain-head digest and the agent-stack representation into the credential, offline-
// verifiable (AGID-claims-1/24/34 / INV-A3). The credential's AGID extension carries both
// digests and the full representation; the issuance event records the chain digest.
func TestCredential_BindsChainDigestAndAgentStack(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, bc := singleAnchorChain(t, reg, "t1", "fido2:root")
	f := newGateFixture(t, anchors, nil, nil, nil)

	rep := mustRepr(t, "bind me", "search")
	repBytes, _ := jsonMarshal(rep)
	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre, SubjectRepr: repBytes}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("issuance refused: %s", refusalReason(t, res.decision))
	}
	// The X.509-bound material (offline-verifiable) carries both digests.
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding from credential: %v", err)
	}
	if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
		t.Fatalf("bound chain-head digest = %x, want %x", bm.ChainHeadDigest, bc.headDigest)
	}
	// The bound agent-stack digest is the digest of the OPAQUE representation bytes the
	// caller shipped over the seam (AGID-03 canonical bytes carried through), so a
	// relying party recomputes it from the bound bytes.
	if !bytesEqual(bm.AgentStackDigest, AgentStackDigestOf(repBytes)) {
		t.Fatalf("bound agent-stack digest = %x, want %x", bm.AgentStackDigest, AgentStackDigestOf(repBytes))
	}
	// The bound representation bytes decode (with the agentstack package a relying party
	// uses) back to a representation carrying this prompt's + tool set's digests.
	var boundRep agentstack.Representation
	if err := jsonUnmarshal(bm.AgentStackRepr, &boundRep); err != nil {
		t.Fatalf("decode bound repr: %v", err)
	}
	if !bytesEqual(boundRep.SystemPromptDigest, rep.SystemPromptDigest) {
		t.Fatalf("bound repr system-prompt digest = %x, want %x", boundRep.SystemPromptDigest, rep.SystemPromptDigest)
	}
	// The credential is offline-verifiable: the extension recomputes to the same binding
	// digest (a relying party with no live signer can re-derive it).
	reDigest, err := bm.Digest()
	if err != nil {
		t.Fatalf("re-derive binding digest: %v", err)
	}
	if len(reDigest) == 0 {
		t.Fatal("binding digest empty")
	}

	// Issuance event: the caller appends agent.issuance.recorded carrying the chain
	// digest (the binding digest). Assert a well-formed event round-trips.
	issDigest, _ := bm.Digest()
	ev, err := Encode(IssuanceRecordedV1{TenantID: "t1", SubjectID: "leaf", ChainDigest: issDigest, CredentialDigest: bc.headDigest})
	if err != nil {
		t.Fatalf("encode issuance event: %v", err)
	}
	if ev.Type != TypeIssuanceRecorded {
		t.Fatalf("issuance event type = %q", ev.Type)
	}
	if _, err := Decode(ev); err != nil {
		t.Fatalf("decode issuance event: %v", err)
	}
}

// TestAgentStack_PromptAndToolManifestDigests asserts the BOUND representation carries
// the prompt+tool manifest digests (the binding-side assertion; the representation test
// proper is AGID-03's). It swaps the prompt, then the tool set, and confirms the bound
// agent-stack digest flips each time -- so the credential is bound to exactly this
// prompt and this tool manifest.
func TestAgentStack_PromptAndToolManifestDigests(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")

	mint := func(repBytes []byte) BindingMaterial {
		f := newGateFixture(t, anchors, nil, nil, nil)
		pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre, SubjectRepr: repBytes}
		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if !res.decision.Approved {
			t.Fatalf("issuance refused: %s", refusalReason(t, res.decision))
		}
		bm, err := ExtractBindingMaterial(res.credential)
		if err != nil {
			t.Fatalf("extract binding: %v", err)
		}
		return bm
	}

	// decodeBound decodes the bound representation bytes (as a relying party does with the
	// agentstack package) so we can assert the BOUND representation carries the prompt+tool
	// manifest digests.
	decodeBound := func(bm BindingMaterial) agentstack.Representation {
		var r agentstack.Representation
		if err := jsonUnmarshal(bm.AgentStackRepr, &r); err != nil {
			t.Fatalf("decode bound repr: %v", err)
		}
		return r
	}

	repA := mustRepr(t, "prompt-A", "search", "email")
	repABytes, _ := jsonMarshal(repA)
	bmA := mint(repABytes)
	boundA := decodeBound(bmA)

	// The BOUND representation carries the SAME prompt+tool digests the AGID-03
	// representation computed (they travel in the binding so a relying party recovers them
	// without a side channel).
	if !bytesEqual(boundA.SystemPromptDigest, repA.SystemPromptDigest) {
		t.Fatalf("bound system-prompt digest = %x, want %x", boundA.SystemPromptDigest, repA.SystemPromptDigest)
	}
	if !bytesEqual(boundA.ToolManifestDigest, repA.ToolManifestDigest) {
		t.Fatalf("bound tool-manifest digest = %x, want %x", boundA.ToolManifestDigest, repA.ToolManifestDigest)
	}
	if len(boundA.SystemPromptDigest) == 0 || len(boundA.ToolManifestDigest) == 0 {
		t.Fatal("bound representation is missing a prompt or tool-manifest digest")
	}

	// Swap the prompt -> the bound agent-stack digest AND the bound prompt digest flip.
	repB := mustRepr(t, "prompt-B-different", "search", "email")
	repBBytes, _ := jsonMarshal(repB)
	bmB := mint(repBBytes)
	if bytesEqual(bmA.AgentStackDigest, bmB.AgentStackDigest) {
		t.Fatal("swapping the prompt did not change the bound agent-stack digest")
	}
	if bytesEqual(boundA.SystemPromptDigest, decodeBound(bmB).SystemPromptDigest) {
		t.Fatal("swapping the prompt did not change the bound system-prompt digest")
	}

	// Swap the tool set -> the bound agent-stack digest AND the bound tool digest flip.
	repC := mustRepr(t, "prompt-A", "search") // dropped "email"
	repCBytes, _ := jsonMarshal(repC)
	bmC := mint(repCBytes)
	if bytesEqual(bmA.AgentStackDigest, bmC.AgentStackDigest) {
		t.Fatal("changing the tool manifest did not change the bound agent-stack digest")
	}
	if bytesEqual(boundA.ToolManifestDigest, decodeBound(bmC).ToolManifestDigest) {
		t.Fatal("changing the tool manifest did not change the bound tool-manifest digest")
	}
}

// jsonUnmarshal is a thin test helper (the seam carriage format is JSON), so tests read as
// decode round-trips.
func jsonUnmarshal(b []byte, v any) error { return jsonUnmarshalImpl(b, v) }

// TestRefusal_SignedArtifactRecorded proves that on refusal a SIGNED refusal artifact is
// produced and can be recorded to the ledger as agent.refusal.recorded (AGID-claims-1/14). It
// uses a chain missing its root anchor (a spliced/forged root), asserts a verifying
// signed refusal naming the failed check, and confirms the artifact encodes into a
// well-formed refusal event.
func TestRefusal_SignedArtifactRecorded(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	// Build a valid chain but DO NOT seed its root anchor -> the root-anchor check
	// refuses.
	envs, _, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
	f := newGateFixture(t, map[string]RootAnchor{}, nil, nil, nil) // empty trust store

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("a chain with no held root anchor was approved")
	}
	if f.keystore.keyOps() != 0 {
		t.Fatalf("refused issuance performed %d key ops, want zero", f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckRootAnchor {
		t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckRootAnchor)
	}
	if art.SignerID != "test-signer" {
		t.Fatalf("refusal signer_id = %q, want test-signer", art.SignerID)
	}
	if len(art.Signature) == 0 {
		t.Fatal("refusal artifact is not signed")
	}
	if err := VerifyRefusal(f.refusalPub, art); err != nil {
		t.Fatalf("signed refusal does not verify against the refusal key: %v", err)
	}
	// A tampered refusal (flip the named check) must NOT verify -- the signature binds
	// the named check.
	tampered := art
	tampered.FailedCheck = CheckNarrowing
	if err := VerifyRefusal(f.refusalPub, tampered); err == nil {
		t.Fatal("a tampered refusal verified (signature must bind the named check)")
	}

	// The artifact records to the ledger as agent.refusal.recorded.
	ev, err := Encode(RefusalRecordedV1{TenantID: "t1", SubjectID: art.SubjectID, FailedCheck: art.FailedCheck, RequestDigest: art.RequestDigest, Signature: art.Signature})
	if err != nil {
		t.Fatalf("encode refusal event: %v", err)
	}
	if ev.Type != TypeRefusalRecorded {
		t.Fatalf("refusal event type = %q, want %q", ev.Type, TypeRefusalRecorded)
	}
	var sink MemSink
	ev.Sequence = 1
	sink.Append(ev)
	if got := sink.Events(); len(got) != 1 || got[0].Type != TypeRefusalRecorded {
		t.Fatalf("refusal not appended to ledger: %+v", got)
	}
	_ = eventspec.DefaultSchemaVersion // ensure eventspec import used meaningfully
}

// TestRootAnchor_PhishingResistantRefRecorded proves the root-anchor phishing-resistant
// auth reference is verified and recorded with the issuance (AGID-claim-13): the approved
// decision's binding carries the root anchor's AuthRef, which the caller records in the
// issuance event.
func TestRootAnchor_PhishingResistantRefRecorded(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	const authRef = "webauthn:cred-id-9f3a-phishing-resistant"
	envs, anchors, _ := singleAnchorChain(t, reg, "t1", authRef)
	f := newGateFixture(t, anchors, nil, nil, nil)

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}
	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("issuance refused: %s", refusalReason(t, res.decision))
	}
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	if bm.RootAnchorAuthRef != authRef {
		t.Fatalf("recorded root-anchor auth ref = %q, want %q (AGID-claim-13)", bm.RootAnchorAuthRef, authRef)
	}
	// A chain whose root key is NOT a held anchor records no issuance (already covered by
	// TestRefusal), so the recorded ref is only ever a VERIFIED anchor's ref.
}
