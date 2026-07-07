// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// issuancekeyop.go is the AGID-INT-WIRE in-signer after-approval KEY OP: the edition
// implementation of the core signing.IssuanceKeyOp seam. It is the second half of the
// gated-issuance mint over the transport (the first half is the gate's verify-before-keygen,
// verifier.go). The core signer's GatedIssue handler consults the gate BEFORE any key op
// (INV-A1) and, ONLY on an approving decision, invokes this key op INSIDE the boundary to:
//
//  1. GENERATE the agent credential key inside the signer's own custody (SignerCustody,
//     injected via UseSignerCustody) -- the private key is created in and stays in the
//     signer; it never crosses the boundary.
//  2. CERTIFY that agent key as a MINIMAL leaf under the signer-held issuing CA, stamping
//     the AGID binding extension (bind.MintCredential) that carries the gate's approved
//     BindingMaterial (chain-head digest + agent-stack representation + task-envelope digest).
//  3. Return ONLY public material: the credential's public DER + the issued certificate DER
//     (the opaque encoded record). No private key is ever placed in the result.
//
// AN-4/AN-8: this file is SIGNER-LINKED (the delegation package is what cmd/trstctl-signer
// attaches) and imports NO datastore / NATS / HTTP; it uses only internal/crypto (AN-3) and
// the core signing seam. The issuing CA private key is signer-held (a crypto.DigestSigner
// backed by locked material); only digests cross into the crypto boundary. When no issuing
// CA is provisioned at attach time, the key op bootstraps a signer-INTERNAL issuing CA
// (a locked key generated inside the boundary, self-signed) so gated issuance works
// end-to-end -- production provisions the real, durable issuing-CA handle (a remaining
// AGID-INT-WIRE hardening item), but issuance is never fail-OPEN: without a gate approval
// this key op is never reached.

// IssuanceKeyOpConfig configures the in-signer issuance key op at attach time. Every field
// is optional; the zero value yields a working key op that bootstraps a signer-internal
// issuing CA and generates ECDSA-P256 agent keys.
type IssuanceKeyOpConfig struct {
	// SignerID names this signer (used to derive the bootstrap issuing-CA common name).
	SignerID string
	// IssuingCACertDER + IssuingCASigner are the signer-held issuing CA the key op certifies
	// agent credentials under. Both must be set to use a provisioned CA; when either is
	// empty the key op bootstraps a signer-internal CA inside the boundary (locked material,
	// self-signed). The CA private key is signer-held: only digests cross into the crypto
	// boundary (AN-4).
	IssuingCACertDER []byte
	IssuingCASigner  crypto.DigestSigner
	// AgentKeyAlgorithm is the default algorithm for a generated agent credential key when
	// the request does not specify one. Defaults to ECDSA-P256.
	AgentKeyAlgorithm crypto.Algorithm
	// IssuingCAAlgorithm is the algorithm for the bootstrap signer-internal issuing CA key
	// (used only when no CA is provisioned). Defaults to ECDSA-P256.
	IssuingCAAlgorithm crypto.Algorithm
	// Clock supplies the current time (for the bootstrap CA validity). Defaults to time.Now.
	Clock func() time.Time
}

// IssuanceKeyOp is the edition after-approval issuance key op. It satisfies
// signing.IssuanceKeyOp and opts into signer custody (UseSignerCustody). Construct it with
// NewIssuanceKeyOp and attach it via signing.WithIssuanceKeyOp in cmd/trstctl-signer.
type IssuanceKeyOp struct {
	cfg IssuanceKeyOpConfig

	mu       sync.Mutex
	custody  signing.SignerCustody // injected by the signer at construction
	caDER    []byte
	caSigner crypto.DigestSigner
	caReady  bool
}

// Compile-time assertions that the key op satisfies the core seam and opts into custody.
var (
	_ signing.IssuanceKeyOp = (*IssuanceKeyOp)(nil)
)

// bootstrapCATTL is the validity of a bootstrap signer-internal issuing CA (used only when
// no durable CA is provisioned). Long enough to outlive short-lived agent credentials many
// times over; production replaces it with a provisioned CA.
const bootstrapCATTL = 90 * 24 * time.Hour

// NewIssuanceKeyOp builds the in-signer issuance key op with fail-closed defaults. It does
// NOT itself perform any key op; the agent keygen/certify happens per issuance inside
// MintApprovedCredential, only after the gate approved.
func NewIssuanceKeyOp(cfg IssuanceKeyOpConfig) *IssuanceKeyOp {
	if cfg.AgentKeyAlgorithm == "" {
		cfg.AgentKeyAlgorithm = crypto.ECDSAP256
	}
	if cfg.IssuingCAAlgorithm == "" {
		cfg.IssuingCAAlgorithm = crypto.ECDSAP256
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	op := &IssuanceKeyOp{cfg: cfg}
	if len(cfg.IssuingCACertDER) > 0 && cfg.IssuingCASigner != nil {
		op.caDER = cfg.IssuingCACertDER
		op.caSigner = cfg.IssuingCASigner
		op.caReady = true
	}
	return op
}

// UseSignerCustody binds the signer's own key custody into the key op so it can generate
// the agent key INSIDE the signer (the private key never leaves). Called once at
// construction by the signer (custodyAwareIssuanceKeyOp), before serving.
func (op *IssuanceKeyOp) UseSignerCustody(c signing.SignerCustody) {
	op.mu.Lock()
	op.custody = c
	op.mu.Unlock()
}

// MintApprovedCredential performs the after-approval key op for an APPROVED gated issuance
// (INV-A1's after-approval arm). It generates the agent key inside the signer, certifies it
// under the signer-held issuing CA with the AGID binding extension carrying the gate's
// approved binding material, and returns ONLY public material. It must never be called on a
// refusal (the core gatedIssue guarantees it is not).
func (op *IssuanceKeyOp) MintApprovedCredential(_ context.Context, req signing.IssuancePreconditions, decision signing.IssuanceDecision, alg crypto.Algorithm) (signing.IssuedCredential, error) {
	if !decision.Approved {
		// Defense in depth: never mint on a non-approving decision (the core seam already
		// guarantees this, but fail closed here too).
		return signing.IssuedCredential{}, fmt.Errorf("delegation: issuance key op invoked on a non-approving decision")
	}

	// Decode the gate's approved binding material (the chain-head + agent-stack + task
	// envelope digests). This is the exact binding the gate assembled after verifying the
	// chain/attestation; the key op only STAMPS it, never recomputes trust.
	bm, err := DecodeBindingMaterial(decision.BindingMaterial)
	if err != nil {
		return signing.IssuedCredential{}, fmt.Errorf("delegation: decode approved binding material: %w", err)
	}

	op.mu.Lock()
	custody := op.custody
	op.mu.Unlock()
	if custody == nil {
		// Fail closed: without signer custody we cannot generate the agent key inside the
		// boundary, and we must NEVER accept a caller-supplied private key (AN-4/AN-8).
		return signing.IssuedCredential{}, fmt.Errorf("delegation: issuance key op has no signer custody bound")
	}

	// Resolve (or bootstrap) the signer-held issuing CA.
	caDER, caSigner, err := op.issuingCA()
	if err != nil {
		return signing.IssuedCredential{}, err
	}

	// Choose the agent-key algorithm: the request's, else the configured default.
	agentAlg := alg
	if agentAlg == "" {
		agentAlg = op.cfg.AgentKeyAlgorithm
	}

	// Generate the agent credential key INSIDE the signer custody (private key stays in the
	// signer; sealed at rest when a key store is configured). The handle is derived from the
	// approved binding so it is stable per (subject, chain) and never guessable-collides.
	handle := op.agentKeyHandle(req, bm)
	agentSigner, err := custody.GenerateSuccessorKey(handle, agentAlg)
	if err != nil {
		return signing.IssuedCredential{}, fmt.Errorf("delegation: generate agent key inside signer: %w", err)
	}

	// Certify the agent key as a MINIMAL leaf under the issuing CA, stamping the AGID binding
	// extension carrying the approved binding material. Only digests cross into the crypto
	// boundary; the leaf is verified against the CA before return (bind.MintCredential fails
	// closed on an unverifiable signature).
	ttlSeconds := issuanceTTLSeconds(req, op.cfg.Clock())
	subjectCN := issuanceSubjectCN(req)
	agentDigestSigner, err := digestSignerOf(agentSigner)
	if err != nil {
		return signing.IssuedCredential{}, err
	}
	credDER, err := MintCredential(caDER, caSigner, agentDigestSigner, subjectCN, ttlSeconds, bm)
	if err != nil {
		return signing.IssuedCredential{}, fmt.Errorf("delegation: certify agent credential: %w", err)
	}

	return signing.IssuedCredential{
		CredentialPublicDER: agentSigner.Public().DER,
		EncodedRecord:       credDER,
	}, nil
}

// issuingCA returns the signer-held issuing CA (cert DER + signer), bootstrapping a
// signer-internal one the first time when none was provisioned. The bootstrap CA key is
// generated inside the signer boundary as locked material via custody; the returned signer
// is the custody's message-Signer view of it, so its private key never leaves the signer.
func (op *IssuanceKeyOp) issuingCA() ([]byte, crypto.DigestSigner, error) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.caReady {
		return op.caDER, op.caSigner, nil
	}
	if op.custody == nil {
		return nil, nil, fmt.Errorf("delegation: cannot bootstrap issuing CA without signer custody")
	}
	// Generate the bootstrap issuing-CA key inside the signer under a fixed handle so a
	// restart re-loads the SAME CA from the sealed key store (rather than rotating it).
	caSigner, err := op.custody.GenerateSuccessorKey(bootstrapCAHandle, op.cfg.IssuingCAAlgorithm)
	if err != nil {
		// If the handle already exists (a prior boot generated it), resolve it instead of
		// failing -- a restart-durable CA.
		resolved, rerr := op.custody.ResolvePredecessor(bootstrapCAHandle)
		if rerr != nil {
			return nil, nil, fmt.Errorf("delegation: bootstrap issuing CA key: %w", err)
		}
		caSigner = resolved
	}
	caDigestSigner, err := digestSignerOf(caSigner)
	if err != nil {
		return nil, nil, err
	}
	caDER, err := crypto.SelfSignedCACert(caDigestSigner, op.bootstrapCACommonName(), bootstrapCATTL)
	if err != nil {
		return nil, nil, fmt.Errorf("delegation: self-sign bootstrap issuing CA: %w", err)
	}
	op.caDER = caDER
	op.caSigner = caDigestSigner
	op.caReady = true
	return op.caDER, op.caSigner, nil
}

// bootstrapCAHandle is the fixed signer keystore handle for the bootstrap issuing-CA key,
// so a restart re-loads the same CA rather than rotating it.
const bootstrapCAHandle = "agid-issuing-ca"

func (op *IssuanceKeyOp) bootstrapCACommonName() string {
	id := op.cfg.SignerID
	if id == "" {
		id = "trstctl-signer"
	}
	return "AGID Issuing CA (" + id + ")"
}

// agentKeyHandle derives a stable, unguessable-collision-resistant keystore handle for the
// agent credential key from the approved binding and the request's subject. Deriving it from
// the binding keeps the same (subject, chain) mapping to the same handle so a retried
// issuance reuses the key rather than proliferating handles.
func (op *IssuanceKeyOp) agentKeyHandle(req signing.IssuancePreconditions, bm BindingMaterial) string {
	h := sha256.New()
	h.Write([]byte("agid/agentid/agent-key-handle/v1"))
	h.Write([]byte(req.TenantID))
	h.Write([]byte(req.TrustAnchorRef))
	h.Write(bm.ChainHeadDigest)
	h.Write(bm.AgentStackDigest)
	return "agid-agent:" + hex.EncodeToString(h.Sum(nil)[:16])
}

// digestSignerOf recovers the DIGEST-signing view of the custody's message-Signer so the
// X.509 CA/leaf helpers (which sign a pre-computed TBS digest) do not double-hash. The
// custody returns a crypto.Signer that is a thin message-view over an in-signer DigestSigner
// (crypto.SignerFromDigestSigner); crypto.DigestSignerFrom recovers that underlying
// DigestSigner without re-hashing and without the private key leaving the boundary. It fails
// closed rather than returning a re-hashing adapter that would produce invalid signatures.
func digestSignerOf(s crypto.Signer) (crypto.DigestSigner, error) {
	if ds, ok := crypto.DigestSignerFrom(s); ok {
		return ds, nil
	}
	return nil, fmt.Errorf("delegation: signer-held key does not expose a digest-signing view")
}

// issuanceTTLSeconds derives the credential validity in seconds from the request's asserted
// bounds when present (NotAfter - now), else falls back to the AGID default. The gate has
// already enforced the sub-hour ceiling for chain-bound issuance; this is the certify-time
// TTL and never widens the gate's decision.
func issuanceTTLSeconds(req signing.IssuancePreconditions, now time.Time) int64 {
	if req.NotAfter > 0 {
		if secs := req.NotAfter - now.Unix(); secs > 0 {
			return secs
		}
	}
	return CredentialTTL
}

// issuanceSubjectCN derives the leaf subject common name from the request's asserted trust
// anchor reference (the caller-asserted subject handle), falling back to a stable default so
// a certificate always has a subject. It is non-secret.
func issuanceSubjectCN(req signing.IssuancePreconditions) string {
	if req.TrustAnchorRef != "" {
		return req.TrustAnchorRef
	}
	return "agid-agent"
}
