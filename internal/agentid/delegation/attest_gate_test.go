// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/agentid/agentstack"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// attBody builds the opaque attestation body bytes for (method,payload).
func attBody(t *testing.T, method string, payload []byte) []byte {
	t.Helper()
	b, err := jsonMarshal(AttestationBody{Method: method, Payload: payload})
	if err != nil {
		t.Fatalf("encode attestation body: %v", err)
	}
	return b
}

// TestIssue_AttestationVerifiedBeforeKeygen proves the attestation is verified BEFORE any
// key op (AGID-claim-10 / INV-A1): the instrumented attestor records "attest-verified", the
// keystore records "keyop", and the log shows attestation strictly before keygen. A
// designated class requiring hardware-TPM is met by seeded hardware-TPM evidence.
func TestIssue_AttestationVerifiedBeforeKeygen(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")

	minClass := MinClassPolicy{"privileged": ClassHardwareTPM}
	f := newGateFixture(t, anchors, minClass, nil, nil)

	// Seed a hardware-TPM attestation the fake accepts for its exact payload.
	payload := []byte("tpm-quote-bytes")
	f.attestor.seed("tpm", payload, VerifiedAttestation{Subject: "instance-1", Method: "tpm"})

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs, DesignatedClass: "privileged"})
	req := signing.IssuancePreconditions{
		TenantID:          "t1",
		TrustAnchorRef:    "leaf",
		Preconditions:     pre,
		Attestation:       attBody(t, "tpm", payload),
		AttestationMethod: "tpm",
	}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("attested issuance refused: %s", refusalReason(t, res.decision))
	}
	ai, ki := f.log.index("attest-verified"), f.log.index("keyop")
	if ai < 0 {
		t.Fatal("attestation was never verified")
	}
	if ki < 0 {
		t.Fatal("keygen never ran")
	}
	if ai >= ki {
		t.Fatalf("call order = %v, want attestation verified BEFORE keygen (AGID-claim-10 / INV-A1)", f.log.snapshot())
	}
	// The bound material carries the attestation-evidence digest.
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	if len(bm.AttestationDigest) == 0 {
		t.Fatal("approved attested issuance bound no attestation digest")
	}
}

// TestAttestation_MinClassGate proves the min-attestation-class policy refuses below-class
// evidence NAMING the class not met (AGID-claim-10). A designated class requiring HSM is
// presented with only software-class evidence, which is refused; the refusal detail names
// the required class.
func TestAttestation_MinClassGate(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, _ := singleAnchorChain(t, reg, "t1", "fido2:root")
	minClass := MinClassPolicy{"vault-admin": ClassHSM}
	f := newGateFixture(t, anchors, minClass, nil, nil)

	// Seed only software-class evidence (below HSM).
	payload := []byte("software-attestation")
	f.attestor.seed("software", payload, VerifiedAttestation{Subject: "sw-1", Method: "software"})

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs, DesignatedClass: "vault-admin"})
	req := signing.IssuancePreconditions{
		TenantID:          "t1",
		TrustAnchorRef:    "leaf",
		Preconditions:     pre,
		Attestation:       attBody(t, "software", payload),
		AttestationMethod: "software",
	}
	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("below-class attestation was approved (AGID-claim-10 min-class gate failed)")
	}
	if f.keystore.keyOps() != 0 {
		t.Fatalf("below-class attestation performed %d key ops, want zero", f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckAttestation {
		t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckAttestation)
	}
	// Name the class not met: the detail must mention the required class "hsm".
	if !containsSubstr(art.Detail, ClassHSM.String()) {
		t.Fatalf("refusal detail %q does not name the class not met (%q)", art.Detail, ClassHSM.String())
	}
	if err := VerifyRefusal(f.refusalPub, art); err != nil {
		t.Fatalf("signed refusal does not verify: %v", err)
	}
}

// TestIssue_AttestationAgentStackNoChain proves fallback AGID-claim-32: verified attestation +
// an agent-stack representation with NO multi-hop chain yields a credential binding the
// agent-stack representation, verified in-signer before keygen. There is no chain; the
// binding carries the agent-stack digest and no chain-head digest.
func TestIssue_AttestationAgentStackNoChain(t *testing.T) {
	// No anchors needed: there is no chain. The gate still requires a (fail-closed)
	// trust store by construction; an empty one is fine here.
	minClass := MinClassPolicy{"agent": ClassVirtualTPM}
	f := newGateFixture(t, map[string]RootAnchor{}, minClass, nil, nil)

	payload := []byte("aws-iid-doc")
	f.attestor.seed("aws_iid", payload, VerifiedAttestation{Subject: "i-123", Method: "aws_iid"})

	rep := mustRepr(t, "you are a helpful agent", "search", "email")
	repBytes, err := jsonMarshal(rep)
	if err != nil {
		t.Fatalf("encode repr: %v", err)
	}
	// Precondition body carries only the designated class, no chain (AGID-claim-32).
	pre, _ := encodePreconditionsForTest(PreconditionsBody{DesignatedClass: "agent"})
	req := signing.IssuancePreconditions{
		TenantID:          "t1",
		TrustAnchorRef:    "agent-subject",
		Preconditions:     pre,
		SubjectRepr:       repBytes,
		Attestation:       attBody(t, "aws_iid", payload),
		AttestationMethod: "aws_iid",
	}
	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("attestation+agent-stack (no chain) refused: %s", refusalReason(t, res.decision))
	}
	// Attestation before keygen.
	if f.log.index("attest-verified") >= f.log.index("keyop") {
		t.Fatalf("call order = %v, want attestation before keygen (AGID-claim-32)", f.log.snapshot())
	}
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	if len(bm.ChainHeadDigest) != 0 {
		t.Fatalf("no-chain fallback bound a chain-head digest %x, want none (AGID-claim-32)", bm.ChainHeadDigest)
	}
	if len(bm.AgentStackDigest) == 0 {
		t.Fatal("no-chain fallback bound no agent-stack digest (AGID-claim-32)")
	}
	// The bound agent-stack digest is the digest of the OPAQUE representation bytes the
	// caller shipped (the gate binds exactly what it received, so a relying party
	// recomputes it from the bound bytes).
	if !bytesEqual(bm.AgentStackDigest, AgentStackDigestOf(repBytes)) {
		t.Fatalf("bound agent-stack digest = %x, want %x", bm.AgentStackDigest, AgentStackDigestOf(repBytes))
	}
	// And the bound bytes decode back to a representation carrying this prompt's digest.
	var boundRep agentstack.Representation
	if err := jsonUnmarshal(bm.AgentStackRepr, &boundRep); err != nil {
		t.Fatalf("decode bound repr: %v", err)
	}
	if !bytesEqual(boundRep.SystemPromptDigest, rep.SystemPromptDigest) {
		t.Fatalf("bound repr prompt digest = %x, want %x", boundRep.SystemPromptDigest, rep.SystemPromptDigest)
	}
}

// containsSubstr is a tiny substring test to avoid importing strings just for one check.
func containsSubstr(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// A150: with the signer's durable attestor floor as its verifier, the gate checks
// evidence against the requesting tenant's own attestors. The same evidence key
// presented on another tenant's request is refused before any key operation.
func TestIssue_AttestationUsesTheRequestingTenantsAttestors(t *testing.T) {
	minClass := MinClassPolicy{"agent": ClassHardwareTPM}
	f := newGateFixture(t, map[string]RootAnchor{}, minClass, nil, nil)
	floor := NewDurableAttestationTrustStore(t.TempDir())
	attestorKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := floor.ProvisionAgentAttestor(context.Background(), "t1", "tpm-verifier", attestorKey.Public().DER, "tpm"); err != nil {
		t.Fatal(err)
	}
	refusal, refusalDER := signerWithDER(t)
	gate, err := NewGate(Config{
		SignerID: "test-signer", Roots: NewTrustStore(map[string]RootAnchor{}), RefusalSigner: refusal,
		Revocations: NeverRevoked{}, Attestor: floor, MinClass: minClass,
	})
	if err != nil {
		t.Fatal(err)
	}
	rep := mustRepr(t, "you are a helpful agent", "search")
	repBytes, err := jsonMarshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	pre, _ := encodePreconditionsForTest(PreconditionsBody{DesignatedClass: "agent"})
	request := func(tenant, nonce string) signing.IssuancePreconditions {
		payload, err := SignAttestation(attestorKey, "tpm-verifier", "tpm", "instance-1", nil, []byte(nonce))
		if err != nil {
			t.Fatal(err)
		}
		return signing.IssuancePreconditions{
			TenantID: tenant, TrustAnchorRef: "agent-subject", Preconditions: pre, SubjectRepr: repBytes,
			Attestation: attBody(t, "tpm", payload), AttestationMethod: "tpm",
		}
	}
	if res := runGatedIssue(t, f.log, gate, request("t1", "n1"), f.mintKeyOp(t)); !res.decision.Approved {
		t.Fatalf("the tenant's own attestor was refused: %s", refusalReason(t, res.decision))
	}
	before := f.keystore.keyOps()
	res := runGatedIssue(t, f.log, gate, request("t2", "n2"), f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("another tenant's attestor vouched for this tenant's issuance")
	}
	if f.keystore.keyOps() != before {
		t.Fatal("a refused attestation still ran a key operation")
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckAttestation {
		t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckAttestation)
	}
	if err := VerifyRefusal(refusalDER, art); err != nil {
		t.Fatalf("signed refusal does not verify: %v", err)
	}
}
