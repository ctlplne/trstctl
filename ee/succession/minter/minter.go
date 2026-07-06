// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package minter implements PCAS succession minting inside the AN-4 isolated
// signer. It attaches to the core signer through the feature-neutral
// signing.WithSuccessionMinter seam. The predecessor and successor private keys
// live inside the signer boundary and never cross it: a mint returns only the
// successor public key and the encoded dual-signed record (INV-1). The
// per-identity epoch floor is durable signer state that survives restart
// (INV-3, mint-time half).
package minter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// Minter errors. They map to the signer's fail-closed refusals.
var (
	ErrPredecessorHandle     = errors.New("minter: unknown predecessor handle")
	ErrEpochNotCurrent       = errors.New("minter: asserted predecessor epoch is not the recorded high-water")
	ErrPolicyRequired        = errors.New("minter: a signed policy decision is required")
	ErrPolicyInvalid         = errors.New("minter: policy decision invalid")
	ErrAuthorizationRequired = errors.New("minter: a dual-control authorization is required")
	ErrAuthorizationInvalid  = errors.New("minter: authorization invalid")
	ErrKeygen                = errors.New("minter: successor key generation failed")
	ErrFloorPersist          = errors.New("minter: failed to persist epoch floor")
	ErrStrengthDowngrade     = errors.New("minter: refused forward succession to a weaker algorithm class absent break-glass")
)

// BreakGlassVerifier verifies a distinct, single-use, request-bound break-glass
// token authorizing a forward strength-downgrade succession, inside the signer
// (claim 17 / INV-8). It is separate from the dual-control AuthVerifier.
type BreakGlassVerifier interface {
	VerifyAndConsume(token []byte, req signing.MintRequest) error
}

// KeyResolver returns the predecessor signer for an opaque in-signer handle. The
// private key stays inside the signer; only the Signer handle is returned.
type KeyResolver interface {
	Resolve(handle string) (crypto.Signer, error)
}

// FloorStore is the durable per-identity epoch-floor state of the signer. Load
// returns the sealed floors at startup (so a restart preserves them); Advance
// durably records a new floor before the succession is considered minted
// (record-then-activate).
type FloorStore interface {
	Load() (map[string]uint64, error)
	Advance(identityID string, epoch uint64) error
}

// PolicyVerifier verifies that a signed policy decision authorizes (identity,
// target algorithm). When one is configured, minting requires a valid decision,
// verified BEFORE successor-key generation (claim 23).
type PolicyVerifier interface {
	Verify(decision []byte, identityID string, target crypto.Algorithm) error
}

// AuthVerifier verifies a single-use dual-control authorization token that binds
// the request, and marks it spent (claim 5). paramsDigest is the digest of the
// committed request parameters that exist before successor-key generation.
type AuthVerifier interface {
	VerifyAndConsume(token []byte, req signing.MintRequest, paramsDigest []byte) error
}

// Minter mints dual-signed successions inside the signer. It implements
// signing.SuccessionMinter.
type Minter struct {
	resolver    KeyResolver
	keygen      crypto.KeyGenerator
	floors      FloorStore
	policy      PolicyVerifier // optional
	auth        AuthVerifier   // optional
	requireAuth bool

	enforceStrength bool
	breakGlass      BreakGlassVerifier // optional; nil => downgrades always refused

	attestSigner crypto.Signer // optional; when set, every mint is countersigned and every refusal is a signed artifact (PCAS-20)
	signerID     string

	provenance PlanProvenanceVerifier // optional; verifies the policy-decision provenance chain before keygen (PCAS-21)

	mu    sync.Mutex
	floor map[string]uint64
}

// PlanProvenanceVerifier verifies the policy-decision provenance chain (finding ⟵
// plan ⟵ decision) carried in the request, inside the signer and BEFORE successor
// keygen (claims 24, 40, PCAS-21). ee/succession/policy.ProvenanceVerifier implements
// it.
type PlanProvenanceVerifier interface {
	Verify(req signing.MintRequest) error
}

// Option configures a Minter.
type Option func(*Minter)

// WithPolicy requires a policy-authority-signed decision on every mint (claim 23).
func WithPolicy(v PolicyVerifier) Option { return func(m *Minter) { m.policy = v } }

// WithDualControl requires a single-use authorization token on every mint (claim 5).
func WithDualControl(v AuthVerifier) Option {
	return func(m *Minter) {
		m.auth = v
		m.requireAuth = true
	}
}

// WithStrengthOrdering enforces the class partial order (PurePQ >= Hybrid >=
// Classical): a forward succession to a strictly weaker class is refused unless
// the request carries a valid break-glass token that bg verifies. A nil bg means
// downgrades are always refused (claim 17 / INV-8).
func WithStrengthOrdering(bg BreakGlassVerifier) Option {
	return func(m *Minter) {
		m.enforceStrength = true
		m.breakGlass = bg
	}
}

// WithPlanProvenance verifies the policy-decision provenance chain (finding ⟵ plan ⟵
// decision, its authority signatures, both digest bindings, the policy_ref = recorded-
// decision digest, and recording) inside the signer before successor keygen (claims
// 24, 40).
func WithPlanProvenance(v PlanProvenanceVerifier) Option {
	return func(m *Minter) { m.provenance = v }
}

// WithAttestation makes the signer countersign every minted record with its
// attestation key (claim 28) and emit a signed refusal artifact on every refusal
// (claim 41). Once configured there is no mint path that skips the countersignature
// (INV-13). signerID names the signer in both.
func WithAttestation(attestSigner crypto.Signer, signerID string) Option {
	return func(m *Minter) {
		m.attestSigner = attestSigner
		m.signerID = signerID
	}
}

// RefusalError wraps a refusal sentinel with the signer's signed refusal artifact
// (claim 41). errors.Is against the underlying sentinel still succeeds, so callers
// that match on ErrEpochNotCurrent, ErrStrengthDowngrade, etc. are unaffected.
type RefusalError struct {
	Artifact succession.RefusalArtifact
	sentinel error
}

func (e *RefusalError) Error() string { return "minter: refused — " + e.sentinel.Error() }
func (e *RefusalError) Unwrap() error { return e.sentinel }

// refuse builds a signed refusal artifact (when attestation is configured) and wraps
// the sentinel; otherwise it returns the sentinel unchanged (pre-PCAS-20 behavior).
func (m *Minter) refuse(constraint string, req signing.MintRequest, sentinel error) error {
	if m.attestSigner == nil {
		return sentinel
	}
	art, err := succession.SignRefusal(m.attestSigner, succession.RefusalArtifact{
		SignerID: m.signerID, IdentityID: req.IdentityID, TenantID: req.TenantID,
		RequestDigest: RequestParamsDigest(req), Constraint: constraint, IssuedAt: time.Now().Unix(),
	})
	if err != nil {
		return sentinel
	}
	return &RefusalError{Artifact: art, sentinel: sentinel}
}

// New builds a Minter, loading the sealed epoch floors from the store.
func New(resolver KeyResolver, keygen crypto.KeyGenerator, floors FloorStore, opts ...Option) (*Minter, error) {
	m := &Minter{resolver: resolver, keygen: keygen, floors: floors}
	for _, o := range opts {
		o(m)
	}
	loaded, err := floors.Load()
	if err != nil {
		return nil, fmt.Errorf("minter: load floors: %w", err)
	}
	if loaded == nil {
		loaded = map[string]uint64{}
	}
	m.floor = loaded
	return m, nil
}

var _ signing.SuccessionMinter = (*Minter)(nil)

// MintSuccessor verifies the request inside the signer, generates the successor
// key inside the boundary, forms the PCAS-04 commitment, dual-signs it with the
// predecessor and successor keys, durably advances the epoch floor, and returns
// only the successor public key + encoded record. Neither private key crosses the
// boundary.
func (m *Minter) MintSuccessor(ctx context.Context, req signing.MintRequest) (signing.MintResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Resolve the predecessor handle (its private key stays in the signer).
	pred, err := m.resolver.Resolve(req.PredecessorHandle)
	if err != nil {
		return signing.MintResult{}, fmt.Errorf("%w: %v", ErrPredecessorHandle, err)
	}

	// Epoch monotonicity: the asserted predecessor epoch must equal the recorded
	// floor. Stale, equal-but-already-advanced, or skipped epochs are refused
	// (claim 12 / INV-3).
	floor := m.floor[req.IdentityID]
	if req.AssertedPredecessorEpoch != floor {
		return signing.MintResult{}, m.refuse(succession.RefusalEpoch, req, ErrEpochNotCurrent)
	}
	epoch := floor + 1
	paramsDigest := RequestParamsDigest(req)

	// Strength ordering: refuse a FORWARD succession to a strictly weaker
	// algorithm class absent a valid, single-use break-glass token verified inside
	// the signer (claim 17 / INV-8). This is distinct from epoch rollback (INV-3).
	var breakGlassUsed bool
	if m.enforceStrength && succession.IsStrengthDowngrade(pred.Algorithm(), req.TargetAlgorithm) {
		if m.breakGlass == nil || len(req.BreakGlass) == 0 {
			return signing.MintResult{}, m.refuse(succession.RefusalStrength, req, ErrStrengthDowngrade)
		}
		if err := m.breakGlass.VerifyAndConsume(req.BreakGlass, req); err != nil {
			return signing.MintResult{}, m.refuse(succession.RefusalStrength, req, ErrStrengthDowngrade)
		}
		breakGlassUsed = true
	}

	// Policy verification BEFORE successor-key generation (claim 23).
	if m.policy != nil {
		if len(req.PolicyDecision) == 0 {
			return signing.MintResult{}, m.refuse(succession.RefusalPolicy, req, ErrPolicyRequired)
		}
		if err := m.policy.Verify(req.PolicyDecision, req.IdentityID, req.TargetAlgorithm); err != nil {
			return signing.MintResult{}, m.refuse(succession.RefusalPolicy, req, ErrPolicyInvalid)
		}
	}

	// Policy-decision provenance verification BEFORE successor-key generation (claims
	// 24, 40): the finding⟵plan⟵decision chain, its digest bindings, and the
	// policy_ref = recorded-decision digest are checked in-signer.
	if m.provenance != nil {
		if err := m.provenance.Verify(req); err != nil {
			return signing.MintResult{}, m.refuse(succession.RefusalPolicy, req, fmt.Errorf("%w: %v", ErrPolicyInvalid, err))
		}
	}

	// Dual-control verification BEFORE successor-key generation (claim 5).
	if m.requireAuth {
		if len(req.Authorization) == 0 {
			return signing.MintResult{}, m.refuse(succession.RefusalDualControl, req, ErrAuthorizationRequired)
		}
		if err := m.auth.VerifyAndConsume(req.Authorization, req, paramsDigest); err != nil {
			return signing.MintResult{}, m.refuse(succession.RefusalDualControl, req, ErrAuthorizationInvalid)
		}
	}

	// Generate the successor key INSIDE the boundary, only after all checks pass.
	succ, err := m.keygen.GenerateKey(req.TargetAlgorithm)
	if err != nil {
		return signing.MintResult{}, fmt.Errorf("%w: %v", ErrKeygen, err)
	}

	// Form the commitment (PCAS-04) and dual-sign it.
	fields := succession.CommitmentFields{
		DeploymentScope:  req.DeploymentScope,
		IdentityID:       req.IdentityID,
		TenantID:         req.TenantID,
		PredecessorEpoch: floor,
		Epoch:            epoch,
		PredecessorAlg:   pred.Algorithm(),
		PredecessorPub:   pred.Public().DER,
		SuccessorAlg:     succ.Algorithm(),
		SuccessorPub:     succ.Public().DER,
		PolicyRef:        req.PolicyRef,
		HashAlg:          succession.HashAlgSHA256,
		NotBefore:        req.NotBefore,
		NotAfter:         req.NotAfter,
	}
	commitment, err := succession.Commit(fields)
	if err != nil {
		return signing.MintResult{}, err
	}
	predSig, err := pred.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return signing.MintResult{}, fmt.Errorf("minter: predecessor sign: %w", err)
	}
	succSig, err := succ.Sign(commitment, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return signing.MintResult{}, fmt.Errorf("minter: successor sign: %w", err)
	}
	rec := succession.SuccessionRecord{
		Fields:         fields,
		PredecessorAtt: predSig,
		Possession:     succession.PossessionProof{Kind: succession.ProofSuccessorSignature, Signature: succSig},
	}
	if breakGlassUsed {
		// Mark the record as a break-glass succession; the RP requires this for any
		// weaker-class succession (claim 17). It is self-authenticating (authority
		// signature), so it needs no commitment binding.
		rec.BreakGlassAuth = cloneBytesBG(req.BreakGlass)
	}

	// authz_digest: bind a digest of the dual-control authorization artifact, so the
	// authorization is verifiable from the published record alone (claim 42).
	rec.AuthzDigest = succession.AuthzDigest(req.Authorization)

	// Signer attestation: countersign every record with the signer's attestation key
	// (claim 28 / INV-13). When attestation is configured there is no path here that
	// leaves a record unattested. It binds the commitment and authz_digest.
	if m.attestSigner != nil {
		att, err := succession.Attest(m.attestSigner, m.signerID, rec)
		if err != nil {
			return signing.MintResult{}, fmt.Errorf("minter: signer attestation: %w", err)
		}
		rec.SignerAttestation = att
	}

	encoded, err := EncodeRecord(rec)
	if err != nil {
		return signing.MintResult{}, err
	}

	// Record-then-activate: durably advance the sealed floor before returning, so
	// no succession can exist that the signer's own record does not evidence.
	if err := m.floors.Advance(req.IdentityID, epoch); err != nil {
		return signing.MintResult{}, fmt.Errorf("%w: %v", ErrFloorPersist, err)
	}
	m.floor[req.IdentityID] = epoch

	return signing.MintResult{
		Epoch:              epoch,
		SuccessorAlgorithm: succ.Algorithm(),
		SuccessorPublicDER: succ.Public().DER,
		EncodedRecord:      encoded,
	}, nil
}

type paramsForDigest struct {
	IdentityID               string
	TenantID                 string
	DeploymentScope          string
	AssertedPredecessorEpoch uint64
	TargetAlgorithm          crypto.Algorithm
	PolicyRef                string
}

// RequestParamsDigest is the digest of the committed request parameters that
// exist before successor-key generation (claim 5). An approval authority binds a
// dual-control token to this value; the minter recomputes and compares it.
func RequestParamsDigest(req signing.MintRequest) []byte {
	data, _ := json.Marshal(paramsForDigest{
		IdentityID:               req.IdentityID,
		TenantID:                 req.TenantID,
		DeploymentScope:          req.DeploymentScope,
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch,
		TargetAlgorithm:          req.TargetAlgorithm,
		PolicyRef:                req.PolicyRef,
	})
	return crypto.SHA256Sum(data)
}

// EncodeRecord / DecodeRecord serialize a succession record for transport as the
// opaque MintResult.EncodedRecord body.
func EncodeRecord(rec succession.SuccessionRecord) ([]byte, error) { return json.Marshal(rec) }

// DecodeRecord parses an encoded succession record.
func DecodeRecord(b []byte) (succession.SuccessionRecord, error) {
	var r succession.SuccessionRecord
	err := json.Unmarshal(b, &r)
	return r, err
}

// --- Concrete authority-signed verifiers -----------------------------------

type signedEnvelope struct {
	Payload json.RawMessage `json:"payload"`
	Sig     []byte          `json:"sig"`
}

// PolicyDecision is the payload an approval/policy authority signs to authorize a
// succession target.
type PolicyDecision struct {
	IdentityID      string           `json:"identity_id"`
	TargetAlgorithm crypto.Algorithm `json:"target_algorithm"`
}

// SignedPolicyAuthorizer verifies policy decisions signed by a policy authority
// whose public key the signer holds (claim 23).
type SignedPolicyAuthorizer struct{ AuthorityPubDER []byte }

// Verify checks the authority signature and that the decision authorizes the
// (identity, target) pair.
func (p SignedPolicyAuthorizer) Verify(decision []byte, identityID string, target crypto.Algorithm) error {
	var env signedEnvelope
	if err := json.Unmarshal(decision, &env); err != nil {
		return fmt.Errorf("policy decode: %w", err)
	}
	if err := crypto.VerifyMessage(p.AuthorityPubDER, env.Payload, env.Sig); err != nil {
		return fmt.Errorf("policy authority signature: %w", err)
	}
	var d PolicyDecision
	if err := json.Unmarshal(env.Payload, &d); err != nil {
		return err
	}
	if d.IdentityID != identityID {
		return fmt.Errorf("policy decision identity %q != %q", d.IdentityID, identityID)
	}
	if d.TargetAlgorithm != target {
		return fmt.Errorf("policy decision target %q != %q", d.TargetAlgorithm, target)
	}
	return nil
}

// AuthorizationToken is the single-use dual-control artifact an approval authority
// signs. The m-of-n approval is gathered OUTSIDE the signer; the signer verifies
// only this one artifact and never tallies per-approver approvals (claim 5).
type AuthorizationToken struct {
	IdentityID               string           `json:"identity_id"`
	TenantID                 string           `json:"tenant_id"`
	AssertedPredecessorEpoch uint64           `json:"asserted_predecessor_epoch"`
	TargetAlgorithm          crypto.Algorithm `json:"target_algorithm"`
	ParamsDigest             []byte           `json:"params_digest"`
	Nonce                    string           `json:"nonce"`
}

// SignedTokenAuthorizer verifies authority-signed AuthorizationTokens and enforces
// single-use by retaining spent nonces (claim 5).
type SignedTokenAuthorizer struct {
	AuthorityPubDER []byte
	mu              sync.Mutex
	spent           map[string]bool
}

// NewSignedTokenAuthorizer builds an authorizer trusting authorityPubDER.
func NewSignedTokenAuthorizer(authorityPubDER []byte) *SignedTokenAuthorizer {
	return &SignedTokenAuthorizer{AuthorityPubDER: authorityPubDER, spent: map[string]bool{}}
}

// VerifyAndConsume checks the authority signature, the binding to the request and
// params digest, and single-use.
func (a *SignedTokenAuthorizer) VerifyAndConsume(token []byte, req signing.MintRequest, paramsDigest []byte) error {
	var env signedEnvelope
	if err := json.Unmarshal(token, &env); err != nil {
		return fmt.Errorf("token decode: %w", err)
	}
	if err := crypto.VerifyMessage(a.AuthorityPubDER, env.Payload, env.Sig); err != nil {
		return fmt.Errorf("token authority signature: %w", err)
	}
	var t AuthorizationToken
	if err := json.Unmarshal(env.Payload, &t); err != nil {
		return err
	}
	if t.IdentityID != req.IdentityID || t.TenantID != req.TenantID ||
		t.AssertedPredecessorEpoch != req.AssertedPredecessorEpoch ||
		t.TargetAlgorithm != req.TargetAlgorithm || !bytes.Equal(t.ParamsDigest, paramsDigest) {
		return errors.New("token binding mismatch")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.spent[t.Nonce] {
		return errors.New("token already used (single-use)")
	}
	a.spent[t.Nonce] = true
	return nil
}

// SignEnvelope signs payload with authority and returns the {payload, sig}
// envelope both concrete verifiers accept. It is exported so orchestration and
// tests can mint policy decisions and authorization tokens.
func SignEnvelope(authority crypto.Signer, payload []byte) ([]byte, error) {
	sig, err := authority.Sign(payload, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedEnvelope{Payload: payload, Sig: sig})
}

// BreakGlassToken is the distinct, single-use m-of-n artifact an approval
// authority signs to authorize one forward strength-downgrade succession (claim
// 17). It binds the succession so it cannot be replayed or rebound.
type BreakGlassToken struct {
	IdentityID               string           `json:"identity_id"`
	TenantID                 string           `json:"tenant_id"`
	AssertedPredecessorEpoch uint64           `json:"asserted_predecessor_epoch"`
	TargetAlgorithm          crypto.Algorithm `json:"target_algorithm"`
	Nonce                    string           `json:"nonce"`
}

// SignedBreakGlassAuthorizer verifies authority-signed BreakGlassTokens and
// enforces single-use. The RP mirror (ee/rpverify) verifies the same token.
type SignedBreakGlassAuthorizer struct {
	AuthorityPubDER []byte
	mu              sync.Mutex
	spent           map[string]bool
}

// NewSignedBreakGlassAuthorizer builds an authorizer trusting authorityPubDER.
func NewSignedBreakGlassAuthorizer(authorityPubDER []byte) *SignedBreakGlassAuthorizer {
	return &SignedBreakGlassAuthorizer{AuthorityPubDER: authorityPubDER, spent: map[string]bool{}}
}

// VerifyAndConsume checks the authority signature, the binding to the request,
// and single-use.
func (a *SignedBreakGlassAuthorizer) VerifyAndConsume(token []byte, req signing.MintRequest) error {
	var env signedEnvelope
	if err := json.Unmarshal(token, &env); err != nil {
		return fmt.Errorf("break-glass decode: %w", err)
	}
	if err := crypto.VerifyMessage(a.AuthorityPubDER, env.Payload, env.Sig); err != nil {
		return fmt.Errorf("break-glass authority signature: %w", err)
	}
	var t BreakGlassToken
	if err := json.Unmarshal(env.Payload, &t); err != nil {
		return err
	}
	if t.IdentityID != req.IdentityID || t.TenantID != req.TenantID ||
		t.AssertedPredecessorEpoch != req.AssertedPredecessorEpoch || t.TargetAlgorithm != req.TargetAlgorithm {
		return errors.New("break-glass token binding mismatch")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.spent[t.Nonce] {
		return errors.New("break-glass token already used (single-use)")
	}
	a.spent[t.Nonce] = true
	return nil
}

func cloneBytesBG(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
