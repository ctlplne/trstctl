// SPDX-License-Identifier: BUSL-1.1

package quarantine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/digest"
	xrecplan "trstctl.com/trstctl/internal/reconcile/plan"
	"trstctl.com/trstctl/internal/reconcile/witness"
)

// CompletionRequest carries the inputs for a reconciliation-completion record —
// the only thing that releases a quarantine (XREC-claim-5).
type CompletionRequest struct {
	IdempotencyKey    string                 `json:"idempotency_key"`
	Witness           witness.Evidence       `json:"witness"`
	Plan              xrecplan.SignedPlan    `json:"plan"`
	CompletingRoundID string                 `json:"completing_round_id"`
	CompletingDigests []digest.SignedDigest  `json:"completing_digests"`
	Records           []CompletedRecordProof `json:"records"`
}

type CompletedRecordProof struct {
	RecordKey canon.RecordKey  `json:"record_key"`
	Proofs    []CompletedProof `json:"proofs"`
}

type CompletedProof struct {
	AuthorityID string                 `json:"authority_id"`
	Proof       witness.InclusionProof `json:"proof"`
}

type Completed struct {
	CompletionID      string                    `json:"completion_id"`
	TenantID          string                    `json:"tenant_id"`
	WitnessID         string                    `json:"witness_id"`
	WitnessHash       string                    `json:"witness_hash"`
	PlanID            string                    `json:"plan_id"`
	PlanHash          string                    `json:"plan_hash"`
	CompletingRoundID string                    `json:"completing_round_id"`
	DigestRefs        []CompletionDigestRef     `json:"digest_refs"`
	Records           []CompletedRecordEvidence `json:"records"`
	CompletedAt       int64                     `json:"completed_at"`
}

type CompletionDigestRef struct {
	AuthorityID string           `json:"authority_id"`
	DigestHash  string           `json:"digest_hash"`
	MerkleRoot  string           `json:"merkle_root"`
	KeyID       string           `json:"key_id,omitempty"`
	Watermark   digest.Watermark `json:"watermark"`
}

type CompletedRecordEvidence struct {
	RecordKey           canon.RecordKey  `json:"record_key"`
	CanonicalRecordHash string           `json:"canonical_record_hash"`
	Proofs              []CompletedProof `json:"proofs"`
}

type Released struct {
	ReleaseID         string `json:"release_id"`
	TenantID          string `json:"tenant_id"`
	AuthorityID       string `json:"authority_id"`
	WitnessID         string `json:"witness_id"`
	FromState         State  `json:"from_state"`
	ToState           State  `json:"to_state"`
	Reason            string `json:"reason"`
	CompletionID      string `json:"completion_id,omitempty"`
	OverrideID        string `json:"override_id,omitempty"`
	JustificationRef  string `json:"justification_ref,omitempty"`
	ReleaseReasonText string `json:"release_reason_text,omitempty"`
	ReleasedAt        int64  `json:"released_at"`
}

type CompletionDecision struct {
	Completed     bool
	CompletionID  string
	Event         eventspec.Event
	Released      []Record
	ReleaseEvents []eventspec.Event
}

func (m *Manager) Complete(ctx context.Context, req CompletionRequest) (CompletionDecision, error) {
	if m == nil || m.log == nil || m.state == nil || strings.TrimSpace(req.IdempotencyKey) == "" {
		return CompletionDecision{}, ErrInvalidCompletion
	}
	payload, err := buildCompletion(req, m.now().Unix())
	if err != nil {
		return CompletionDecision{}, err
	}
	ev, err := m.append(ctx, "completion:"+strings.TrimSpace(req.IdempotencyKey), EventTypeCompleted, payload.TenantID, payload)
	if err != nil {
		return CompletionDecision{}, err
	}

	open := m.state.openByWitness(payload.TenantID, payload.WitnessID)
	decision := CompletionDecision{Completed: true, CompletionID: payload.CompletionID, Event: ev}
	for _, rec := range open {
		release := Released{
			ReleaseID:    releaseID(payload.TenantID, rec.AuthorityID, payload.WitnessID, payload.CompletionID, "completion"),
			TenantID:     payload.TenantID,
			AuthorityID:  rec.AuthorityID,
			WitnessID:    payload.WitnessID,
			FromState:    StateQuarantined,
			ToState:      StateConsistent,
			Reason:       "reconciliation_completion",
			CompletionID: payload.CompletionID,
			ReleasedAt:   payload.CompletedAt,
		}
		rev, err := m.append(ctx, "release:"+release.ReleaseID, EventTypeReleased, payload.TenantID, release)
		if err != nil {
			return CompletionDecision{}, err
		}
		if closed, ok := m.state.release(payload.TenantID, rec.AuthorityID, payload.WitnessID); ok {
			decision.Released = append(decision.Released, closed)
			decision.ReleaseEvents = append(decision.ReleaseEvents, rev)
		}
	}
	return decision, nil
}

func VerifyCompletionChain(evidence witness.Evidence, signedPlan xrecplan.SignedPlan, completed Completed) error {
	if _, err := evidence.CanonicalBytes(); err != nil {
		return fmt.Errorf("%w: witness: %v", ErrInvalidCompletion, err)
	}
	planHash, err := signedPlan.Plan.Hash()
	if err != nil {
		return fmt.Errorf("%w: plan: %v", ErrInvalidCompletion, err)
	}
	witnessHash := evidence.ContentHash()
	if completed.TenantID != strings.TrimSpace(evidence.Body.TenantID) ||
		completed.WitnessID != strings.TrimSpace(evidence.Body.WitnessID) ||
		completed.WitnessHash != hex.EncodeToString(witnessHash) ||
		completed.PlanID != strings.TrimSpace(signedPlan.Plan.PlanID) ||
		completed.PlanHash != hex.EncodeToString(planHash) {
		return ErrInvalidCompletion
	}
	if signedPlan.Plan.WitnessID != evidence.Body.WitnessID || !bytes.Equal(signedPlan.Plan.WitnessHash, witnessHash) {
		return ErrInvalidCompletion
	}
	roots := map[string][]byte{}
	for _, ref := range completed.DigestRefs {
		root, err := hex.DecodeString(ref.MerkleRoot)
		if err != nil || len(root) != 32 || strings.TrimSpace(ref.AuthorityID) == "" {
			return ErrInvalidCompletion
		}
		roots[strings.TrimSpace(ref.AuthorityID)] = root
	}
	for _, record := range completed.Records {
		if len(record.Proofs) != len(roots) {
			return ErrInvalidCompletion
		}
		keyBytes, err := digest.RecordKeyBytes(record.RecordKey)
		if err != nil {
			return fmt.Errorf("%w: record key: %v", ErrInvalidCompletion, err)
		}
		var material []byte
		seen := map[string]bool{}
		for _, proof := range record.Proofs {
			authorityID := strings.TrimSpace(proof.AuthorityID)
			root, ok := roots[authorityID]
			if !ok || seen[authorityID] || !bytes.Equal(proof.Proof.RecordKeyBytes, keyBytes) || !proof.Proof.Verify(root) {
				return ErrInvalidCompletion
			}
			seen[authorityID] = true
			cur, err := materialRecordBytes(proof.Proof.CanonicalRecordBytes)
			if err != nil {
				return ErrInvalidCompletion
			}
			if len(material) == 0 {
				material = cur
			} else if !bytes.Equal(material, cur) {
				return ErrInvalidCompletion
			}
		}
		hash := crypto.SHA256Sum(material)
		if record.CanonicalRecordHash != hex.EncodeToString(hash) {
			return ErrInvalidCompletion
		}
	}
	return nil
}

func buildCompletion(req CompletionRequest, completedAt int64) (Completed, error) {
	if _, err := req.Witness.CanonicalBytes(); err != nil {
		return Completed{}, fmt.Errorf("%w: witness: %v", ErrInvalidCompletion, err)
	}
	tenantID := strings.TrimSpace(req.Witness.Body.TenantID)
	witnessID := strings.TrimSpace(req.Witness.Body.WitnessID)
	roundID := strings.TrimSpace(req.CompletingRoundID)
	if tenantID == "" || witnessID == "" || roundID == "" || len(req.CompletingDigests) < 2 || len(req.Records) == 0 {
		return Completed{}, ErrInvalidCompletion
	}
	witnessHash := req.Witness.ContentHash()
	planHash, err := req.Plan.Plan.Hash()
	if err != nil {
		return Completed{}, fmt.Errorf("%w: plan: %v", ErrInvalidCompletion, err)
	}
	if !bytes.Equal(req.Plan.PlanHash, planHash) ||
		strings.TrimSpace(req.Plan.Plan.TenantID) != tenantID ||
		strings.TrimSpace(req.Plan.Plan.WitnessID) != witnessID ||
		!bytes.Equal(req.Plan.Plan.WitnessHash, witnessHash) {
		return Completed{}, ErrInvalidCompletion
	}

	digests := map[string]digest.SignedDigest{}
	refs := make([]CompletionDigestRef, 0, len(req.CompletingDigests))
	for _, signed := range req.CompletingDigests {
		body := signed.Body
		authorityID := strings.TrimSpace(body.AuthorityID)
		if authorityID == "" || strings.TrimSpace(body.TenantID) != tenantID {
			return Completed{}, ErrInvalidCompletion
		}
		if _, exists := digests[authorityID]; exists {
			return Completed{}, ErrInvalidCompletion
		}
		hash, err := body.DigestHash()
		if err != nil || !bytes.Equal(hash, signed.DigestHash) {
			return Completed{}, ErrInvalidCompletion
		}
		digests[authorityID] = signed
		refs = append(refs, CompletionDigestRef{
			AuthorityID: authorityID,
			DigestHash:  hex.EncodeToString(hash),
			MerkleRoot:  hex.EncodeToString(body.MerkleRoot),
			KeyID:       strings.TrimSpace(signed.KeyID),
			Watermark:   body.Watermark,
		})
	}

	requiredKeys, err := witnessRecordKeys(req.Witness.Body)
	if err != nil {
		return Completed{}, err
	}
	seenKeys := map[string]bool{}
	records := make([]CompletedRecordEvidence, 0, len(req.Records))
	for _, rec := range req.Records {
		keyID := recordKeyID(rec.RecordKey)
		if !requiredKeys[keyID] {
			return Completed{}, ErrInvalidCompletion
		}
		keyBytes, err := digest.RecordKeyBytes(rec.RecordKey)
		if err != nil {
			return Completed{}, fmt.Errorf("%w: record key: %v", ErrInvalidCompletion, err)
		}
		if len(rec.Proofs) != len(digests) {
			return Completed{}, ErrInvalidCompletion
		}
		var material []byte
		seenAuthorities := map[string]bool{}
		proofs := make([]CompletedProof, 0, len(rec.Proofs))
		for _, proof := range rec.Proofs {
			authorityID := strings.TrimSpace(proof.AuthorityID)
			signed, ok := digests[authorityID]
			if !ok || seenAuthorities[authorityID] || !bytes.Equal(proof.Proof.RecordKeyBytes, keyBytes) || !proof.Proof.Verify(signed.Body.MerkleRoot) {
				return Completed{}, ErrInvalidCompletion
			}
			seenAuthorities[authorityID] = true
			cur, err := materialRecordBytes(proof.Proof.CanonicalRecordBytes)
			if err != nil {
				return Completed{}, ErrInvalidCompletion
			}
			if len(material) == 0 {
				material = cur
			} else if !bytes.Equal(material, cur) {
				return Completed{}, ErrInvalidCompletion
			}
			proofs = append(proofs, copyCompletedProof(proof))
		}
		hash := crypto.SHA256Sum(material)
		records = append(records, CompletedRecordEvidence{
			RecordKey:           rec.RecordKey,
			CanonicalRecordHash: hex.EncodeToString(hash),
			Proofs:              proofs,
		})
		seenKeys[keyID] = true
	}
	for key := range requiredKeys {
		if !seenKeys[key] {
			return Completed{}, ErrInvalidCompletion
		}
	}

	completed := Completed{
		CompletionID:      completionID(tenantID, witnessID, req.Plan.Plan.PlanID, roundID, witnessHash, planHash),
		TenantID:          tenantID,
		WitnessID:         witnessID,
		WitnessHash:       hex.EncodeToString(witnessHash),
		PlanID:            strings.TrimSpace(req.Plan.Plan.PlanID),
		PlanHash:          hex.EncodeToString(planHash),
		CompletingRoundID: roundID,
		DigestRefs:        refs,
		Records:           records,
		CompletedAt:       completedAt,
	}
	if err := VerifyCompletionChain(req.Witness, req.Plan, completed); err != nil {
		return Completed{}, err
	}
	return completed, nil
}

func witnessRecordKeys(body witness.Body) (map[string]bool, error) {
	out := map[string]bool{}
	for _, entry := range body.Entries {
		key := entry.RecordKey
		if key.TenantID == "" && entry.Policy != nil {
			key = entry.Policy.RecordKey
		}
		if key.TenantID == "" || key.RecordType == "" || key.StableID == "" {
			return nil, ErrInvalidCompletion
		}
		out[recordKeyID(key)] = true
	}
	if len(out) == 0 {
		return nil, ErrInvalidCompletion
	}
	return out, nil
}

func completionID(tenantID, witnessID, planID, roundID string, witnessHash, planHash []byte) string {
	payload, _ := json.Marshal(struct {
		TenantID    string `json:"tenant_id"`
		WitnessID   string `json:"witness_id"`
		WitnessHash string `json:"witness_hash"`
		PlanID      string `json:"plan_id"`
		PlanHash    string `json:"plan_hash"`
		RoundID     string `json:"round_id"`
	}{
		TenantID:    strings.TrimSpace(tenantID),
		WitnessID:   strings.TrimSpace(witnessID),
		WitnessHash: hex.EncodeToString(witnessHash),
		PlanID:      strings.TrimSpace(planID),
		PlanHash:    hex.EncodeToString(planHash),
		RoundID:     strings.TrimSpace(roundID),
	})
	return hex.EncodeToString(crypto.SHA256Sum(payload))
}

func releaseID(tenantID, authorityID, witnessID, causeID, reason string) string {
	payload := strings.Join([]string{
		strings.TrimSpace(tenantID),
		strings.TrimSpace(authorityID),
		strings.TrimSpace(witnessID),
		strings.TrimSpace(causeID),
		strings.TrimSpace(reason),
	}, "\x00")
	return hex.EncodeToString(crypto.SHA256Sum([]byte(payload)))
}

func recordKeyID(key canon.RecordKey) string {
	return strings.Join([]string{strings.TrimSpace(key.TenantID), strings.TrimSpace(key.RecordType), strings.TrimSpace(key.StableID)}, "\x00")
}

func copyCompletedProof(in CompletedProof) CompletedProof {
	return CompletedProof{
		AuthorityID: strings.TrimSpace(in.AuthorityID),
		Proof: witness.InclusionProof{
			RecordKeyBytes:       append([]byte(nil), in.Proof.RecordKeyBytes...),
			CanonicalRecordBytes: append([]byte(nil), in.Proof.CanonicalRecordBytes...),
			Siblings:             copyWitnessNodes(in.Proof.Siblings),
		},
	}
}

func copyWitnessNodes(in []witness.ProofNode) []witness.ProofNode {
	out := make([]witness.ProofNode, len(in))
	for i, n := range in {
		out[i] = witness.ProofNode{Hash: append([]byte(nil), n.Hash...), Left: n.Left}
	}
	return out
}

func materialRecordBytes(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, ErrInvalidCompletion
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	delete(obj, "provenance")
	return json.Marshal(obj)
}
