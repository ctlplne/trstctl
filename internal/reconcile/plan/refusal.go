// SPDX-License-Identifier: BUSL-1.1

package plan

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const (
	CheckPlanSignature    = "plan_signature"
	CheckWitnessRecorded  = "witness_recorded"
	CheckWitnessHash      = "witness_hash"
	CheckWitnessSignature = "witness_signature"
	CheckActionScope      = "action_scope"
	CheckWitnessClosed    = "witness_closed"
	CheckCountersign      = "countersign"
)

type RefusalBody struct {
	TenantID    string `json:"tenant_id"`
	PlanID      string `json:"plan_id,omitempty"`
	WitnessID   string `json:"witness_id,omitempty"`
	WitnessHash string `json:"witness_hash,omitempty"`
	Operation   string `json:"operation,omitempty"`
	SubjectRef  string `json:"subject_ref,omitempty"`
	FailedCheck string `json:"failed_check"`
	Reason      string `json:"reason"`
	RefusedAt   int64  `json:"refused_at"`
}

type RefusalRecord struct {
	Body         RefusalBody      `json:"body"`
	AuthorityID  string           `json:"authority_id"`
	KeyID        string           `json:"key_id"`
	Algorithm    crypto.Algorithm `json:"algorithm"`
	PublicKeyDER []byte           `json:"public_key_der"`
	Signature    []byte           `json:"signature"`
}

// CanonicalBytes renders the signable body of a refusal. A plan that fails
// signer-side verification produces one of these, signed, so the refusal is
// itself evidence (XREC-claim-13).
func (b RefusalBody) CanonicalBytes() ([]byte, error) {
	if strings.TrimSpace(b.TenantID) == "" || strings.TrimSpace(b.FailedCheck) == "" || strings.TrimSpace(b.Reason) == "" || b.RefusedAt == 0 {
		return nil, ErrInvalidPlan
	}
	content := struct {
		TenantID    string `json:"tenant_id"`
		PlanID      string `json:"plan_id,omitempty"`
		WitnessID   string `json:"witness_id,omitempty"`
		WitnessHash string `json:"witness_hash,omitempty"`
		Operation   string `json:"operation,omitempty"`
		SubjectRef  string `json:"subject_ref,omitempty"`
		FailedCheck string `json:"failed_check"`
		Reason      string `json:"reason"`
		RefusedAt   int64  `json:"refused_at"`
	}{
		TenantID:    strings.TrimSpace(b.TenantID),
		PlanID:      strings.TrimSpace(b.PlanID),
		WitnessID:   strings.TrimSpace(b.WitnessID),
		WitnessHash: strings.TrimSpace(b.WitnessHash),
		Operation:   strings.TrimSpace(b.Operation),
		SubjectRef:  strings.TrimSpace(b.SubjectRef),
		FailedCheck: strings.TrimSpace(b.FailedCheck),
		Reason:      strings.TrimSpace(b.Reason),
		RefusedAt:   b.RefusedAt,
	}
	return json.Marshal(content)
}

func DecodeRefusalRecord(raw []byte) (RefusalRecord, error) {
	var rec RefusalRecord
	if len(raw) == 0 {
		return RefusalRecord{}, ErrInvalidPlan
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return RefusalRecord{}, fmt.Errorf("%w: decode refusal: %v", ErrInvalidPlan, err)
	}
	return rec, nil
}

func (r RefusalRecord) Verify(trusted map[string]crypto.PublicKey) error {
	if strings.TrimSpace(r.AuthorityID) == "" || strings.TrimSpace(r.KeyID) == "" || len(r.PublicKeyDER) == 0 || len(r.Signature) == 0 {
		return ErrInvalidPlan
	}
	payload, err := r.Body.CanonicalBytes()
	if err != nil {
		return err
	}
	hash := crypto.SHA256Sum(payload)
	pub, ok := trusted[r.KeyID]
	if !ok {
		return fmt.Errorf("%w: untrusted refusal key %s", ErrInvalidPlan, r.KeyID)
	}
	if pub.Algorithm != r.Algorithm || !bytes.Equal(pub.DER, r.PublicKeyDER) {
		return fmt.Errorf("%w: refusal public key mismatch", ErrInvalidPlan)
	}
	if err := crypto.VerifyDigest(pub, hash, r.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: refusal signature: %v", ErrInvalidPlan, err)
	}
	return nil
}

func refusalBody(req signing.OperationRequest, signed SignedPlan, failedCheck, reason string, refusedAt int64) RefusalBody {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = signed.Plan.TenantID
	}
	return RefusalBody{
		TenantID:    tenantID,
		PlanID:      signed.Plan.PlanID,
		WitnessID:   signed.Plan.WitnessID,
		WitnessHash: hex.EncodeToString(signed.Plan.WitnessHash),
		Operation:   req.Operation,
		SubjectRef:  req.SubjectRef,
		FailedCheck: failedCheck,
		Reason:      reason,
		RefusedAt:   refusedAt,
	}
}
