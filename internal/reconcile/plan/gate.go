// SPDX-License-Identifier: BUSL-1.1

package plan

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/digest"
	"trstctl.com/trstctl/internal/reconcile/witness"
	"trstctl.com/trstctl/internal/signing"
)

type GateConfig struct {
	TrustedPlanKeys    map[string]crypto.PublicKey
	TrustedWitnessKeys map[string]crypto.PublicKey
	ArtifactSigner     signing.ArtifactSigner
	SignerID           string
	Policy             OperationPolicy
	Clock              func() time.Time
}

type OperationGate struct {
	planKeys    map[string]crypto.PublicKey
	witnessKeys map[string]crypto.PublicKey
	artifacts   signing.ArtifactSigner
	signerID    string
	policy      OperationPolicy
	clock       func() time.Time
}

type VerificationEnvelope struct {
	Recorded                witness.WitnessRecorded `json:"recorded"`
	Closed                  bool                    `json:"closed,omitempty"`
	RequiredCountersignFrom string                  `json:"required_countersign_from,omitempty"`
}

type AuthorizationRecord struct {
	TenantID     string `json:"tenant_id"`
	PlanID       string `json:"plan_id"`
	PlanHash     string `json:"plan_hash"`
	WitnessID    string `json:"witness_id"`
	WitnessHash  string `json:"witness_hash"`
	Operation    string `json:"operation"`
	SubjectRef   string `json:"subject_ref,omitempty"`
	AuthorizedAt int64  `json:"authorized_at"`
}

func NewOperationGate(cfg GateConfig) (*OperationGate, error) {
	if cfg.ArtifactSigner == nil {
		return nil, fmt.Errorf("%w: missing artifact signer", ErrInvalidPlan)
	}
	signerID := strings.TrimSpace(cfg.SignerID)
	if signerID == "" {
		signerID = "xrec-plan-gate"
	}
	policy := cfg.Policy
	if policy == nil {
		policy = DefaultOperationPolicy()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &OperationGate{
		planKeys:    copyTrust(cfg.TrustedPlanKeys),
		witnessKeys: copyTrust(cfg.TrustedWitnessKeys),
		artifacts:   cfg.ArtifactSigner,
		signerID:    signerID,
		policy:      policy,
		clock:       clock,
	}, nil
}

func (g *OperationGate) VerifyOperation(ctx context.Context, req signing.OperationRequest) (signing.OperationDecision, error) {
	if err := ctx.Err(); err != nil {
		return signing.OperationDecision{}, err
	}
	signedPlan, err := DecodeSignedPlan(req.Preconditions)
	if err != nil {
		return g.refuse(ctx, req, SignedPlan{}, CheckPlanSignature, err.Error())
	}
	if err := signedPlan.Verify(g.planKeys); err != nil {
		return g.refuse(ctx, req, signedPlan, CheckPlanSignature, err.Error())
	}
	if strings.TrimSpace(req.TenantID) != "" && strings.TrimSpace(req.TenantID) != signedPlan.Plan.TenantID {
		return g.refuse(ctx, req, signedPlan, CheckPlanSignature, "request tenant does not match signed plan")
	}
	env, err := DecodeVerificationEnvelope(req.Evidence)
	if err != nil {
		return g.refuse(ctx, req, signedPlan, CheckWitnessRecorded, err.Error())
	}
	evidence, err := g.verifyRecordedWitness(signedPlan, env)
	if err != nil {
		return g.refuse(ctx, req, signedPlan, checkForWitnessError(err), err.Error())
	}
	if env.Closed {
		return g.refuse(ctx, req, signedPlan, CheckWitnessClosed, "recorded witness is already closed")
	}
	if env.RequiredCountersignFrom != "" && !hasCountersignFrom(evidence, env.RequiredCountersignFrom) {
		return g.refuse(ctx, req, signedPlan, CheckCountersign, "required witness countersignature is absent")
	}
	if err := g.verifyActionScope(signedPlan, evidence, req); err != nil {
		return g.refuse(ctx, req, signedPlan, CheckActionScope, err.Error())
	}
	auth, err := g.authorization(req, signedPlan)
	if err != nil {
		return signing.OperationDecision{}, err
	}
	return signing.OperationDecision{Approved: true, Authorization: auth}, nil
}

func DecodeVerificationEnvelope(raw []byte) (VerificationEnvelope, error) {
	var env VerificationEnvelope
	if len(raw) == 0 {
		return VerificationEnvelope{}, fmt.Errorf("%w: missing witness evidence", ErrInvalidPlan)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return VerificationEnvelope{}, fmt.Errorf("%w: decode witness evidence: %v", ErrInvalidPlan, err)
	}
	return env, nil
}

func EncodeVerificationEnvelope(env VerificationEnvelope) ([]byte, error) {
	if strings.TrimSpace(env.Recorded.WitnessID) == "" {
		return nil, ErrInvalidPlan
	}
	return json.Marshal(env)
}

func (g *OperationGate) verifyRecordedWitness(signedPlan SignedPlan, env VerificationEnvelope) (witness.Evidence, error) {
	rec := env.Recorded
	if strings.TrimSpace(rec.WitnessID) == "" || strings.TrimSpace(rec.TenantID) == "" || strings.TrimSpace(rec.WitnessHash) == "" {
		return witness.Evidence{}, witnessCheckError{check: CheckWitnessRecorded, err: fmt.Errorf("%w: witness not recorded", ErrInvalidPlan)}
	}
	evidence := rec.Evidence
	if rec.WitnessID != evidence.Body.WitnessID || rec.TenantID != evidence.Body.TenantID || rec.WitnessID != signedPlan.Plan.WitnessID || rec.TenantID != signedPlan.Plan.TenantID {
		return witness.Evidence{}, witnessCheckError{check: CheckWitnessRecorded, err: fmt.Errorf("%w: recorded witness metadata mismatch", ErrInvalidPlan)}
	}
	if _, err := evidence.CanonicalBytes(); err != nil {
		return witness.Evidence{}, witnessCheckError{check: CheckWitnessRecorded, err: err}
	}
	recordedHash, err := hex.DecodeString(rec.WitnessHash)
	if err != nil {
		return witness.Evidence{}, witnessCheckError{check: CheckWitnessRecorded, err: fmt.Errorf("%w: recorded witness hash is not hex", ErrInvalidPlan)}
	}
	contentHash := evidence.ContentHash()
	if !bytes.Equal(recordedHash, contentHash) || !bytes.Equal(contentHash, signedPlan.Plan.WitnessHash) {
		return witness.Evidence{}, witnessCheckError{check: CheckWitnessHash, err: fmt.Errorf("%w: plan witness hash does not match recorded witness", ErrInvalidPlan)}
	}
	for _, sig := range evidence.Signatures {
		if err := sig.VerifyForBody(evidence.Body, g.witnessKeys); err != nil {
			return witness.Evidence{}, witnessCheckError{check: CheckWitnessSignature, err: err}
		}
	}
	for _, sig := range evidence.CounterSignatures {
		if err := sig.VerifyForBody(evidence.Body, g.witnessKeys); err != nil {
			return witness.Evidence{}, witnessCheckError{check: CheckWitnessSignature, err: err}
		}
	}
	return evidence, nil
}

func (g *OperationGate) verifyActionScope(signedPlan SignedPlan, evidence witness.Evidence, req signing.OperationRequest) error {
	op := strings.ToLower(strings.TrimSpace(req.Operation))
	if op == "" {
		return fmt.Errorf("%w: missing operation", ErrInvalidPlan)
	}
	for _, action := range signedPlan.Plan.Actions {
		if strings.ToLower(strings.TrimSpace(action.Operation)) != op {
			continue
		}
		if req.SubjectRef != "" && req.SubjectRef != RecordKeyRef(action.RecordKey) && req.SubjectRef != action.RecordKey.StableID {
			continue
		}
		entry, ok := findEntry(evidence.Body.Entries, action.RecordKey)
		if !ok {
			return fmt.Errorf("%w: plan action record key is outside witness", ErrInvalidPlan)
		}
		if !g.policy.Allows(entry.Class, op) {
			return fmt.Errorf("%w: operation %q is not allowed for divergence class %q", ErrInvalidPlan, op, entry.Class)
		}
		return nil
	}
	return fmt.Errorf("%w: no plan action authorizes operation", ErrInvalidPlan)
}

func (g *OperationGate) authorization(req signing.OperationRequest, signedPlan SignedPlan) ([]byte, error) {
	rec := AuthorizationRecord{
		TenantID:     signedPlan.Plan.TenantID,
		PlanID:       signedPlan.Plan.PlanID,
		PlanHash:     hex.EncodeToString(signedPlan.PlanHash),
		WitnessID:    signedPlan.Plan.WitnessID,
		WitnessHash:  hex.EncodeToString(signedPlan.Plan.WitnessHash),
		Operation:    strings.ToLower(strings.TrimSpace(req.Operation)),
		SubjectRef:   req.SubjectRef,
		AuthorizedAt: g.clock().UTC().Unix(),
	}
	return json.Marshal(rec)
}

func (g *OperationGate) refuse(ctx context.Context, req signing.OperationRequest, signedPlan SignedPlan, failedCheck, reason string) (signing.OperationDecision, error) {
	body := refusalBody(req, signedPlan, failedCheck, reason, g.clock().UTC().Unix())
	raw, err := signRefusal(ctx, g.artifacts, g.signerID, body)
	if err != nil {
		return signing.OperationDecision{}, err
	}
	return signing.OperationDecision{Approved: false, RefusalRecord: raw}, nil
}

func signRefusal(ctx context.Context, signer signing.ArtifactSigner, signerID string, body RefusalBody) ([]byte, error) {
	payload, err := body.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	res, err := signer.SignArtifact(ctx, signing.ArtifactSignRequest{
		Kind:        digest.ArtifactKindPlanRefusal,
		TenantID:    body.TenantID,
		AuthorityID: signerID,
		Payload:     payload,
	})
	if err != nil {
		return nil, err
	}
	record := RefusalRecord{
		Body:         body,
		AuthorityID:  signerID,
		KeyID:        res.KeyID,
		Algorithm:    res.Algorithm,
		PublicKeyDER: append([]byte(nil), res.PublicKeyDER...),
		Signature:    append([]byte(nil), res.Signature...),
	}
	return json.Marshal(record)
}

func findEntry(entries []witness.Entry, key canon.RecordKey) (witness.Entry, bool) {
	for _, entry := range entries {
		if recordKeyEqual(entry.RecordKey, key) {
			return entry, true
		}
		if entry.Policy != nil && recordKeyEqual(entry.Policy.RecordKey, key) {
			return entry, true
		}
	}
	return witness.Entry{}, false
}

func recordKeyEqual(a, b canon.RecordKey) bool {
	return a.TenantID == b.TenantID && a.RecordType == b.RecordType && a.StableID == b.StableID
}

func hasCountersignFrom(evidence witness.Evidence, authorityID string) bool {
	for _, sig := range evidence.CounterSignatures {
		if sig.AuthorityID == authorityID {
			return true
		}
	}
	return false
}

func copyTrust(in map[string]crypto.PublicKey) map[string]crypto.PublicKey {
	out := make(map[string]crypto.PublicKey, len(in))
	for keyID, pub := range in {
		out[keyID] = crypto.PublicKey{Algorithm: pub.Algorithm, DER: append([]byte(nil), pub.DER...)}
	}
	return out
}

type witnessCheckError struct {
	check string
	err   error
}

func (e witnessCheckError) Error() string { return e.err.Error() }

func checkForWitnessError(err error) string {
	if checked, ok := err.(witnessCheckError); ok {
		return checked.check
	}
	return CheckWitnessRecorded
}
