// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/taskenv"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// taskenvelope_test.go proves AGID-05: when a delegation record references a task
// envelope (its TaskDigest is set), the in-signer gate verifies the referenced
// envelope's SIGNATURE and EXPIRY as a precondition of the key op (INV-A4, AGID-claim-2),
// reusing AGID-04b's refusal path on failure (zero key ops), and on success BINDS the
// task-envelope digest ALONGSIDE the chain-head digest + agent-stack representation
// (INV-A3 additive). It reuses the AGID-04b instrumented-keystore ordering harness
// (runGatedIssue / instrumentedKeystore / newGateFixture).

// requesterSignerWithDER generates an ephemeral requester signer + its public DER.
func requesterSignerWithDER(t *testing.T) (crypto.Signer, []byte) {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	s, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate requester key: %v", err)
	}
	return s, s.Public().DER
}

// sampleTaskEnvelope builds a well-formed, unsigned task envelope for a requester key id.
func sampleTaskEnvelope(keyID string) taskenv.Envelope {
	return taskenv.Envelope{
		RequesterID:  "requester-1",
		RequesterKey: taskenv.KeyRef{ID: keyID, Algorithm: "ECDSA-P256"},
		Task: taskenv.TaskIntent{
			Description: "summarize the quarterly report",
			InputCommitments: []taskenv.Commitment{
				{Name: "report", Digest: []byte("report-digest")},
			},
		},
		Expiry: taskenv.Window{NotBefore: 1000, NotAfter: 2000},
	}
}

// chainReferencingEnvelope builds a valid two-hop narrowing chain whose HEAD record
// references envDigest via its TaskDigest, returns the envelopes + anchors + head digest.
func chainReferencingEnvelope(t *testing.T, reg *ToolRegistry, tenantID, authRef string, envDigest []byte) ([]RecordEnvelope, map[string]RootAnchor, builtChain) {
	t.Helper()
	rootSigner, rootDER := signerWithDER(t)
	midSigner, midDER := signerWithDER(t)
	// Build the two records by hand so the HEAD carries TaskDigest before signing (the
	// digest must be inside the signed canonical bytes -- record.go binds TaskDigest).
	root := Record{
		TenantID: tenantID, DelegatorID: "root", DelegatorKey: KeyRef{ID: "root-key", Algorithm: "ECDSA-P256"},
		DelegateID: "mid", Authority: wideAuthority(), DepthRemaining: 3, Validity: openWindow(), RootAnchor: true,
	}
	rootSigned, err := root.Sign(rootSigner, reg)
	if err != nil {
		t.Fatalf("sign root: %v", err)
	}
	rootDigest, err := rootSigned.Digest(reg)
	if err != nil {
		t.Fatalf("digest root: %v", err)
	}
	head := Record{
		TenantID: tenantID, DelegatorID: "mid", DelegatorKey: KeyRef{ID: "mid-key", Algorithm: "ECDSA-P256"},
		DelegateID: "leaf", Authority: narrowerAuthority(), DepthRemaining: 2, Validity: openWindow(),
		ParentDigest: rootDigest, TaskDigest: envDigest,
	}
	headSigned, err := head.Sign(midSigner, reg)
	if err != nil {
		t.Fatalf("sign head: %v", err)
	}
	headDigest, err := headSigned.Digest(reg)
	if err != nil {
		t.Fatalf("digest head: %v", err)
	}
	envs := []RecordEnvelope{
		{Record: rootSigned, DelegatorPublicDER: rootDER},
		{Record: headSigned, DelegatorPublicDER: midDER},
	}
	anchors := map[string]RootAnchor{"root-key": {PublicDER: rootDER, AuthRef: authRef}}
	return envs, anchors, builtChain{envelopes: envs, rootKeyID: "root-key", rootDER: rootDER, headDigest: headDigest}
}

// taskEnvFixture builds a gate fixture whose task-envelope trust lookup resolves the one
// requester key, with the clock pinned so the envelope is unexpired at issuance time.
func taskEnvFixture(t *testing.T, anchors map[string]RootAnchor, requesterKeyID string, requesterDER []byte, now int64) gateFixture {
	t.Helper()
	lookup := func(keyID string) ([]byte, bool) {
		if keyID == requesterKeyID {
			return requesterDER, true
		}
		return nil, false
	}
	return newGateFixtureWithTaskEnv(t, anchors, nil, nil, fixedClock(now), lookup)
}

// TestTaskEnvelope_SignatureAndExpiryVerifiedInSigner is the canonical test (AGID-claim-2 /
// INV-A4): with the AGID-04b instrumented-keystore ordering harness, a VALID envelope
// verifies + binds (key op runs, strictly after the gate), while an EXPIRED envelope and
// a TAMPERED (bad-signature) envelope each perform ZERO key ops and mint a signed
// refusal naming the task_envelope check.
func TestTaskEnvelope_SignatureAndExpiryVerifiedInSigner(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	const now = 1500 // inside [1000,2000]

	// ---- valid envelope: verifies, binds, key op runs after the gate ----
	t.Run("valid-verifies-and-binds", func(t *testing.T) {
		reqSigner, reqDER := requesterSignerWithDER(t)
		env := sampleTaskEnvelope("req-key")
		signed, err := env.Sign(reqSigner)
		if err != nil {
			t.Fatalf("sign envelope: %v", err)
		}
		envDigest, _ := signed.Digest()
		envs, anchors, bc := chainReferencingEnvelope(t, reg, "t1", "fido2:root", envDigest)
		f := taskEnvFixture(t, anchors, "req-key", reqDER, now)

		pre, _ := encodePreconditionsWithEnvelope(t, PreconditionsBody{Chain: envs}, signed)
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if !res.decision.Approved {
			t.Fatalf("valid task-envelope issuance refused: %s", refusalReason(t, res.decision))
		}
		if !res.keyOpRan || f.keystore.keyOps() != 1 {
			t.Fatalf("expected exactly one key op after approval, got %d", f.keystore.keyOps())
		}
		// Ordering (INV-A1/A4): the gate consult strictly precedes the single key op.
		if gi, ki := f.log.index("gate"), f.log.index("keyop"); gi < 0 || ki < 0 || gi >= ki {
			t.Fatalf("call order = %v, want gate strictly before keyop", f.log.snapshot())
		}
		// The credential binds the task-envelope digest ALONGSIDE the chain-head digest.
		bm, err := ExtractBindingMaterial(res.credential)
		if err != nil {
			t.Fatalf("extract binding: %v", err)
		}
		if !bytesEqual(bm.TaskEnvelopeDigest, envDigest) {
			t.Fatalf("bound task-envelope digest = %x, want %x", bm.TaskEnvelopeDigest, envDigest)
		}
		if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
			t.Fatalf("bound chain-head digest = %x, want %x (INV-A3 additive)", bm.ChainHeadDigest, bc.headDigest)
		}
	})

	// ---- expired envelope: no key op + signed refusal naming task_envelope ----
	t.Run("expired-refuses-no-keyop", func(t *testing.T) {
		reqSigner, reqDER := requesterSignerWithDER(t)
		env := sampleTaskEnvelope("req-key")
		env.Expiry = taskenv.Window{NotBefore: 1000, NotAfter: 1200} // expires before now=1500
		signed, _ := env.Sign(reqSigner)
		envDigest, _ := signed.Digest()
		envs, anchors, _ := chainReferencingEnvelope(t, reg, "t1", "fido2:root", envDigest)
		f := taskEnvFixture(t, anchors, "req-key", reqDER, now)

		pre, _ := encodePreconditionsWithEnvelope(t, PreconditionsBody{Chain: envs}, signed)
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if res.decision.Approved {
			t.Fatal("an expired task envelope was approved (must refuse)")
		}
		if res.keyOpRan || f.keystore.keyOps() != 0 {
			t.Fatalf("expired envelope performed %d key ops, want ZERO (INV-A1)", f.keystore.keyOps())
		}
		art := decodeRefusalForTest(t, res.decision.RefusalRecord)
		if art.FailedCheck != CheckTaskEnvelope {
			t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckTaskEnvelope)
		}
		if err := VerifyRefusal(f.refusalPub, art); err != nil {
			t.Fatalf("signed refusal does not verify: %v", err)
		}
	})

	// ---- tampered (bad-signature) envelope: no key op + signed refusal ----
	t.Run("tampered-signature-refuses-no-keyop", func(t *testing.T) {
		reqSigner, reqDER := requesterSignerWithDER(t)
		env := sampleTaskEnvelope("req-key")
		signed, _ := env.Sign(reqSigner)
		envDigest, _ := signed.Digest()
		// The chain head references the ORIGINAL digest, but we ship a TAMPERED envelope
		// (description changed after signing) so its signature no longer verifies AND its
		// digest no longer matches the reference -- either way the gate must refuse.
		tampered := signed
		tampered.Task.Description = "exfiltrate secrets"
		envs, anchors, _ := chainReferencingEnvelope(t, reg, "t1", "fido2:root", envDigest)
		f := taskEnvFixture(t, anchors, "req-key", reqDER, now)

		pre, _ := encodePreconditionsWithEnvelope(t, PreconditionsBody{Chain: envs}, tampered)
		req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

		res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
		if res.decision.Approved {
			t.Fatal("a tampered (bad-signature) task envelope was approved (must refuse)")
		}
		if res.keyOpRan || f.keystore.keyOps() != 0 {
			t.Fatalf("tampered envelope performed %d key ops, want ZERO (INV-A1)", f.keystore.keyOps())
		}
		art := decodeRefusalForTest(t, res.decision.RefusalRecord)
		if art.FailedCheck != CheckTaskEnvelope {
			t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckTaskEnvelope)
		}
		if err := VerifyRefusal(f.refusalPub, art); err != nil {
			t.Fatalf("signed refusal does not verify: %v", err)
		}
	})
}

// TestCredential_BindsTaskEnvelopeDigest is the canonical binding test (AGID-claim-2 /
// INV-A4): on success the credential binds the task-envelope digest ALONGSIDE the
// chain-head digest + the agent-stack representation, and the digest referenced in the
// delegation record equals the digest bound in the credential.
func TestCredential_BindsTaskEnvelopeDigest(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	const now = 1500
	reqSigner, reqDER := requesterSignerWithDER(t)
	env := sampleTaskEnvelope("req-key")
	signed, _ := env.Sign(reqSigner)
	envDigest, _ := signed.Digest()

	envs, anchors, bc := chainReferencingEnvelope(t, reg, "t1", "fido2:root", envDigest)
	f := taskEnvFixture(t, anchors, "req-key", reqDER, now)

	// Also ship an agent-stack representation so we can prove the task digest binds
	// ALONGSIDE both the chain-head digest AND the agent-stack representation (INV-A3).
	rep := mustRepr(t, "bind me", "search")
	repBytes, _ := jsonMarshal(rep)
	pre, _ := encodePreconditionsWithEnvelope(t, PreconditionsBody{Chain: envs}, signed)
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre, SubjectRepr: repBytes}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("issuance refused: %s", refusalReason(t, res.decision))
	}
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	// Task-envelope digest bound, and it equals the digest the delegation head references.
	if !bytesEqual(bm.TaskEnvelopeDigest, envDigest) {
		t.Fatalf("bound task-envelope digest = %x, want %x", bm.TaskEnvelopeDigest, envDigest)
	}
	headRef := envs[len(envs)-1].Record.TaskDigest
	if !bytesEqual(bm.TaskEnvelopeDigest, headRef) {
		t.Fatalf("bound task digest %x != digest referenced in record %x", bm.TaskEnvelopeDigest, headRef)
	}
	// Bound ALONGSIDE (not instead of) the chain-head digest AND the agent-stack repr.
	if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
		t.Fatalf("chain-head digest not bound alongside task digest: %x, want %x", bm.ChainHeadDigest, bc.headDigest)
	}
	if !bytesEqual(bm.AgentStackDigest, AgentStackDigestOf(repBytes)) {
		t.Fatalf("agent-stack digest not bound alongside task digest: %x, want %x", bm.AgentStackDigest, AgentStackDigestOf(repBytes))
	}
	// The binding is offline-verifiable: the extension recomputes to a stable digest.
	if d, err := bm.Digest(); err != nil || len(d) == 0 {
		t.Fatalf("binding digest not derivable: %v", err)
	}
}

// TestTaskEnvelope_DigestMismatchRefused proves the referenced envelope digest MUST equal
// the record's TaskDigest: a well-signed, unexpired envelope whose digest does NOT match
// the record's reference is refused (no key op) -- a substituted envelope cannot be bound.
func TestTaskEnvelope_DigestMismatchRefused(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	const now = 1500
	reqSigner, reqDER := requesterSignerWithDER(t)

	// The record references envelope A's digest.
	envA := sampleTaskEnvelope("req-key")
	signedA, _ := envA.Sign(reqSigner)
	digestA, _ := signedA.Digest()

	// But we ship a DIFFERENT, also-valid envelope B (different task).
	envB := sampleTaskEnvelope("req-key")
	envB.Task.Description = "a completely different task"
	signedB, _ := envB.Sign(reqSigner)

	envs, anchors, _ := chainReferencingEnvelope(t, reg, "t1", "fido2:root", digestA)
	f := taskEnvFixture(t, anchors, "req-key", reqDER, now)

	pre, _ := encodePreconditionsWithEnvelope(t, PreconditionsBody{Chain: envs}, signedB)
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("a substituted task envelope (digest mismatch) was approved (must refuse)")
	}
	if f.keystore.keyOps() != 0 {
		t.Fatalf("digest-mismatch performed %d key ops, want ZERO", f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckTaskEnvelope {
		t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckTaskEnvelope)
	}
}

// TestTaskEnvelope_ReferencedButNotSupplied proves that when the record references a task
// envelope (TaskDigest set) but NO envelope is carried over the seam, the gate refuses
// fail-closed (no key op) -- a dangling reference cannot be silently ignored.
func TestTaskEnvelope_ReferencedButNotSupplied(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	const now = 1500
	_, reqDER := requesterSignerWithDER(t)
	envDigest := crypto.SHA256Sum([]byte("some-envelope-digest-the-record-points-at"))
	envs, anchors, _ := chainReferencingEnvelope(t, reg, "t1", "fido2:root", envDigest)
	f := taskEnvFixture(t, anchors, "req-key", reqDER, now)

	// No envelope in the body, but the head record references one.
	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("a dangling task-envelope reference was approved (must refuse)")
	}
	if f.keystore.keyOps() != 0 {
		t.Fatalf("dangling reference performed %d key ops, want ZERO", f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckTaskEnvelope {
		t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckTaskEnvelope)
	}
}

// TestNoTaskEnvelope_NoRegression proves the AGID-04b behavior is EXACTLY preserved when
// no task envelope is referenced: a valid narrowing chain with NO TaskDigest and NO
// carried envelope is approved, the key op runs after the gate, the credential binds the
// chain head, and NO task-envelope digest is bound (AGID-claim-31 chain-only fallback,
// unchanged). This is the "no envelope referenced ⇒ gate behaves exactly as AGID-04b"
// regression guard.
func TestNoTaskEnvelope_NoRegression(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, bc := singleAnchorChain(t, reg, "t1", "fido2:root")
	// Even with a task-envelope trust lookup configured, a chain that references no
	// envelope must behave identically to AGID-04b.
	f := taskEnvFixture(t, anchors, "req-key", []byte("unused"), 1500)

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}

	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("no-envelope chain refused (regression): %s", refusalReason(t, res.decision))
	}
	if !res.keyOpRan || f.keystore.keyOps() != 1 {
		t.Fatalf("no-envelope chain performed %d key ops, want exactly 1", f.keystore.keyOps())
	}
	if gi, ki := f.log.index("gate"), f.log.index("keyop"); gi < 0 || ki < 0 || gi >= ki {
		t.Fatal("no-envelope chain: keygen did not follow the gate (INV-A1)")
	}
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
		t.Fatalf("no-envelope chain bound head %x, want %x", bm.ChainHeadDigest, bc.headDigest)
	}
	if len(bm.TaskEnvelopeDigest) != 0 {
		t.Fatalf("no-envelope chain bound a task-envelope digest %x, want none", bm.TaskEnvelopeDigest)
	}
}

// TestNoTaskEnvelope_GateConstructedWithoutLookup proves that a gate constructed WITHOUT
// a task-envelope trust lookup (exactly the AGID-04b construction) still approves an
// envelope-free chain and binds no task digest -- the extension is inert when unused.
func TestNoTaskEnvelope_GateConstructedWithoutLookup(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	envs, anchors, bc := singleAnchorChain(t, reg, "t1", "fido2:root")
	f := newGateFixture(t, anchors, nil, nil, fixedClock(1500)) // no task-env lookup at all

	pre, _ := encodePreconditionsForTest(PreconditionsBody{Chain: envs})
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}
	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if !res.decision.Approved {
		t.Fatalf("04b-constructed gate refused an envelope-free chain: %s", refusalReason(t, res.decision))
	}
	bm, err := ExtractBindingMaterial(res.credential)
	if err != nil {
		t.Fatalf("extract binding: %v", err)
	}
	if len(bm.TaskEnvelopeDigest) != 0 {
		t.Fatalf("04b-constructed gate bound a task digest %x, want none", bm.TaskEnvelopeDigest)
	}
	if !bytesEqual(bm.ChainHeadDigest, bc.headDigest) {
		t.Fatalf("04b-constructed gate bound head %x, want %x", bm.ChainHeadDigest, bc.headDigest)
	}
}

// TestTaskEnvelope_ReferencedButNoLookupRefuses proves that if a record references a task
// envelope AND an envelope is supplied, but the gate holds NO task-envelope trust lookup
// (cannot resolve the requester key), the gate fails closed with a task_envelope refusal
// (no key op) -- it must not silently skip verification of a referenced envelope.
func TestTaskEnvelope_ReferencedButNoLookupRefuses(t *testing.T) {
	reg := (*ToolRegistry)(nil)
	reqSigner, _ := requesterSignerWithDER(t)
	env := sampleTaskEnvelope("req-key")
	signed, _ := env.Sign(reqSigner)
	envDigest, _ := signed.Digest()
	envs, anchors, _ := chainReferencingEnvelope(t, reg, "t1", "fido2:root", envDigest)
	f := newGateFixture(t, anchors, nil, nil, fixedClock(1500)) // NO task-env lookup

	pre, _ := encodePreconditionsWithEnvelope(t, PreconditionsBody{Chain: envs}, signed)
	req := signing.IssuancePreconditions{TenantID: "t1", TrustAnchorRef: "leaf", Preconditions: pre}
	res := runGatedIssue(t, f.log, f.gate, req, f.mintKeyOp(t))
	if res.decision.Approved {
		t.Fatal("a referenced envelope with no trust lookup was approved (must fail closed)")
	}
	if f.keystore.keyOps() != 0 {
		t.Fatalf("performed %d key ops, want ZERO", f.keystore.keyOps())
	}
	art := decodeRefusalForTest(t, res.decision.RefusalRecord)
	if art.FailedCheck != CheckTaskEnvelope {
		t.Fatalf("failed_check = %q, want %q", art.FailedCheck, CheckTaskEnvelope)
	}
}

// ---- test-only helpers for the task-envelope gate extension ----

// newGateFixtureWithTaskEnv is newGateFixture plus a task-envelope trust lookup, so the
// gate verifies referenced task envelopes. It mirrors newGateFixture exactly otherwise.
func newGateFixtureWithTaskEnv(t *testing.T, anchors map[string]RootAnchor, minClass MinClassPolicy, rev RevocationReader, clock func() time.Time, lookup taskenv.TrustLookup) gateFixture {
	t.Helper()
	log := &orderLog{}
	refusal, refusalDER := signerWithDER(t)
	attestor := newFakeAttestor(log)
	if rev == nil {
		rev = NeverRevoked{}
	}
	gate, err := NewGate(Config{
		SignerID:          "test-signer",
		Roots:             NewTrustStore(anchors),
		RefusalSigner:     refusal,
		Revocations:       rev,
		Attestor:          attestor,
		MinClass:          minClass,
		Clock:             clock,
		TaskEnvelopeTrust: lookup,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	caIssued, err := crypto.SelfSignedHierarchyCA(caKey, crypto.HierarchyCAProfile{CommonName: "AGID Test CA", TTL: time.Hour})
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	return gateFixture{
		gate:       gate,
		refusalPub: refusalDER,
		caCertDER:  caIssued.CertificateDER,
		caSigner:   caKey,
		log:        log,
		keystore:   &instrumentedKeystore{log: log},
		attestor:   attestor,
	}
}

// encodePreconditionsWithEnvelope marshals a PreconditionsBody carrying the encoded task
// envelope in its Envelope field (the opaque seam bytes).
func encodePreconditionsWithEnvelope(t *testing.T, body PreconditionsBody, env taskenv.Envelope) ([]byte, error) {
	t.Helper()
	encEnv, err := EncodeTaskEnvelope(env)
	if err != nil {
		t.Fatalf("encode task envelope: %v", err)
	}
	body.Envelope = encEnv
	return jsonMarshal(body)
}
