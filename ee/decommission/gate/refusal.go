// SPDX-License-Identifier: LicenseRef-trstctl-EE

package gate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// RefusalBody is the body of the VDEC-claim-21 signed refusal artifact: when the
// gate does not succeed, the signer names the requested destruction and at least
// one dependent for which no completion, release, or erasure designation is
// recorded, and the artifact is appended to the ledger.
type RefusalBody struct {
	TenantID           string               `json:"tenant_id"`
	SubjectRef         string               `json:"subject_ref"`
	RequestDigest      string               `json:"request_digest"`
	LedgerPosition     uint64               `json:"ledger_position"`
	AssertedFinalEpoch uint64               `json:"asserted_final_epoch"`
	RegisteredCount    int                  `json:"registered_count"`
	AccountedCount     int                  `json:"accounted_count"`
	UnaccountedCount   int                  `json:"unaccounted_count"`
	Unaccounted        []depstate.Dependent `json:"unaccounted,omitempty"`
	UnaccountedDigest  string               `json:"unaccounted_digest"`
	ViolatedConstraint string               `json:"violated_constraint"`
	Reason             string               `json:"reason"`
	RefusedAtUnix      int64                `json:"refused_at_unix"`
}

type RefusalArtifact struct {
	Body         RefusalBody      `json:"body"`
	AuthorityID  string           `json:"authority_id"`
	KeyID        string           `json:"key_id"`
	Algorithm    crypto.Algorithm `json:"algorithm"`
	PublicKeyDER []byte           `json:"public_key_der"`
	Signature    []byte           `json:"signature"`
}

func (b RefusalBody) CanonicalBytes() ([]byte, error) {
	if strings.TrimSpace(b.TenantID) == "" || strings.TrimSpace(b.SubjectRef) == "" || b.LedgerPosition == 0 || b.AssertedFinalEpoch == 0 {
		return nil, ErrInvalidEvidence
	}
	if b.UnaccountedCount == 0 || (len(b.Unaccounted) == 0 && strings.TrimSpace(b.UnaccountedDigest) == "") {
		return nil, ErrInvalidEvidence
	}
	body := b
	body.TenantID = strings.TrimSpace(body.TenantID)
	body.SubjectRef = strings.TrimSpace(body.SubjectRef)
	body.RequestDigest = strings.TrimSpace(body.RequestDigest)
	body.Unaccounted = sortedDependents(body.Unaccounted)
	body.UnaccountedDigest = strings.TrimSpace(body.UnaccountedDigest)
	body.ViolatedConstraint = strings.TrimSpace(body.ViolatedConstraint)
	body.Reason = strings.TrimSpace(body.Reason)
	if body.ViolatedConstraint == "" || body.Reason == "" || body.RefusedAtUnix == 0 {
		return nil, ErrInvalidEvidence
	}
	return json.Marshal(body)
}

func DecodeRefusalArtifact(raw []byte) (RefusalArtifact, error) {
	var artifact RefusalArtifact
	if len(raw) == 0 {
		return RefusalArtifact{}, ErrInvalidEvidence
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return RefusalArtifact{}, fmt.Errorf("%w: decode refusal: %v", ErrInvalidEvidence, err)
	}
	return artifact, nil
}

func (a RefusalArtifact) Verify(trusted map[string]crypto.PublicKey) error {
	if strings.TrimSpace(a.AuthorityID) == "" || strings.TrimSpace(a.KeyID) == "" || len(a.PublicKeyDER) == 0 || len(a.Signature) == 0 {
		return ErrInvalidEvidence
	}
	payload, err := a.Body.CanonicalBytes()
	if err != nil {
		return err
	}
	pub, ok := trusted[a.KeyID]
	if !ok {
		return fmt.Errorf("%w: untrusted refusal key %s", ErrInvalidEvidence, a.KeyID)
	}
	if pub.Algorithm != a.Algorithm || !bytes.Equal(pub.DER, a.PublicKeyDER) {
		return fmt.Errorf("%w: refusal public key mismatch", ErrInvalidEvidence)
	}
	digest := crypto.SHA256Sum(payload)
	if err := crypto.VerifyDigest(pub, digest, a.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: refusal signature: %v", ErrInvalidEvidence, err)
	}
	return nil
}

func (g *Gate) signRefusal(req signing.GatedDestroyRequest, state depstate.KeyState, unaccounted []depstate.Dependent) (RefusalArtifact, []byte, error) {
	body := RefusalBody{
		TenantID:           req.TenantID,
		SubjectRef:         req.SubjectRef,
		RequestDigest:      hex.EncodeToString(requestDigest(req)),
		LedgerPosition:     req.LedgerPosition,
		AssertedFinalEpoch: req.AssertedFinalEpoch,
		RegisteredCount:    len(state.Registered),
		AccountedCount:     accountedCount(state),
		UnaccountedCount:   len(unaccounted),
		Unaccounted:        sortedDependents(unaccounted),
		UnaccountedDigest:  hex.EncodeToString(dependentSetDigest(unaccounted)),
		ViolatedConstraint: refusalConstraint,
		Reason:             "registered set minus accounted set is not empty",
		RefusedAtUnix:      g.now().UTC().Unix(),
	}
	payload, err := body.CanonicalBytes()
	if err != nil {
		return RefusalArtifact{}, nil, err
	}
	digest := crypto.SHA256Sum(payload)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.key == nil {
		return RefusalArtifact{}, nil, fmt.Errorf("%w: refusal signer destroyed", ErrInvalidEvidence)
	}
	sig, err := g.key.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return RefusalArtifact{}, nil, fmt.Errorf("vdec gate: sign refusal: %w", err)
	}
	pub := g.key.Public()
	artifact := RefusalArtifact{
		Body:         body,
		AuthorityID:  g.signerID,
		KeyID:        g.keyID,
		Algorithm:    pub.Algorithm,
		PublicKeyDER: append([]byte(nil), pub.DER...),
		Signature:    append([]byte(nil), sig...),
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		return RefusalArtifact{}, nil, fmt.Errorf("vdec gate: encode refusal: %w", err)
	}
	return artifact, raw, nil
}

func requestDigest(req signing.GatedDestroyRequest) []byte {
	body := struct {
		TenantID             string `json:"tenant_id"`
		Handle               string `json:"handle"`
		SubjectRef           string `json:"subject_ref"`
		AssertedFinalEpoch   uint64 `json:"asserted_final_epoch"`
		LedgerPosition       uint64 `json:"ledger_position"`
		RequiredSet          []byte `json:"required_set,omitempty"`
		RequiredSetDigest    []byte `json:"required_set_digest,omitempty"`
		SatisfiedSet         []byte `json:"satisfied_set,omitempty"`
		SatisfactionEvidence []byte `json:"satisfaction_evidence,omitempty"`
		Authorization        []byte `json:"authorization,omitempty"`
		Approvals            []byte `json:"approvals,omitempty"`
		AuditChainHead       []byte `json:"audit_chain_head,omitempty"`
		Context              []byte `json:"context,omitempty"`
	}{
		TenantID:             req.TenantID,
		Handle:               req.Handle,
		SubjectRef:           req.SubjectRef,
		AssertedFinalEpoch:   req.AssertedFinalEpoch,
		LedgerPosition:       req.LedgerPosition,
		RequiredSet:          req.RequiredSet,
		RequiredSetDigest:    req.RequiredSetDigest,
		SatisfiedSet:         req.SatisfiedSet,
		SatisfactionEvidence: req.SatisfactionEvidence,
		Authorization:        req.Authorization,
		Approvals:            req.Approvals,
		AuditChainHead:       req.AuditChainHead,
		Context:              req.Context,
	}
	raw, _ := json.Marshal(body)
	return crypto.SHA256Sum(raw)
}

func dependentSetDigest(deps []depstate.Dependent) []byte {
	body := struct {
		Domain     string               `json:"domain"`
		Dependents []depstate.Dependent `json:"dependents"`
	}{
		Domain:     "trstctl/vdec/gated-destruction/unaccounted/v1",
		Dependents: sortedDependents(deps),
	}
	raw, _ := json.Marshal(body)
	return crypto.SHA256Sum(raw)
}

func accountedCount(state depstate.KeyState) int {
	seen := make(map[depstate.Dependent]struct{}, len(state.Accounted)+len(state.Released)+len(state.ErasureDesignated))
	for _, dep := range state.Accounted {
		seen[dep] = struct{}{}
	}
	for _, dep := range state.Released {
		seen[dep] = struct{}{}
	}
	for _, dep := range state.ErasureDesignated {
		seen[dep] = struct{}{}
	}
	return len(seen)
}
