// SPDX-License-Identifier: LicenseRef-trstctl-EE

package plan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/internal/crypto"
)

const defaultPlanKeyID = "xrec-plan-authority"

var ErrInvalidPlan = errors.New("plan: invalid remediation plan")

type Plan struct {
	PlanID      string     `json:"plan_id"`
	TenantID    string     `json:"tenant_id"`
	WitnessID   string     `json:"witness_id"`
	WitnessHash []byte     `json:"witness_hash"`
	Actions     []Action   `json:"actions"`
	Approvals   []Approval `json:"approvals,omitempty"`
	GeneratedAt int64      `json:"generated_at"`
}

type Action struct {
	AuthorityID string            `json:"authority_id"`
	RecordKey   canon.RecordKey   `json:"record_key"`
	Operation   string            `json:"operation"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

type Approval struct {
	AuthorityID string `json:"authority_id"`
	ApprovedAt  int64  `json:"approved_at"`
	Signature   []byte `json:"signature,omitempty"`
}

type SignedPlan struct {
	Plan         Plan             `json:"plan"`
	PlanHash     []byte           `json:"plan_hash"`
	AuthorityID  string           `json:"authority_id"`
	KeyID        string           `json:"key_id"`
	Algorithm    crypto.Algorithm `json:"algorithm"`
	PublicKeyDER []byte           `json:"public_key_der"`
	Signature    []byte           `json:"signature"`
	SignedAt     int64            `json:"signed_at"`
}

func Sign(ctx context.Context, signer crypto.DigestSigner, p Plan, authorityID, keyID string, signedAt int64) (SignedPlan, error) {
	if err := ctx.Err(); err != nil {
		return SignedPlan{}, err
	}
	if signer == nil || strings.TrimSpace(authorityID) == "" {
		return SignedPlan{}, ErrInvalidPlan
	}
	hash, err := p.Hash()
	if err != nil {
		return SignedPlan{}, err
	}
	if strings.TrimSpace(keyID) == "" {
		keyID = defaultPlanKeyID
	}
	if signedAt == 0 {
		signedAt = time.Now().UTC().Unix()
	}
	sig, err := signer.SignDigest(hash, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return SignedPlan{}, fmt.Errorf("plan: sign: %w", err)
	}
	pub := signer.Public()
	return SignedPlan{
		Plan:         p,
		PlanHash:     append([]byte(nil), hash...),
		AuthorityID:  strings.TrimSpace(authorityID),
		KeyID:        strings.TrimSpace(keyID),
		Algorithm:    pub.Algorithm,
		PublicKeyDER: append([]byte(nil), pub.DER...),
		Signature:    append([]byte(nil), sig...),
		SignedAt:     signedAt,
	}, nil
}

func (p Plan) Hash() ([]byte, error) {
	payload, err := p.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(payload), nil
}

func (p Plan) CanonicalBytes() ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	content := struct {
		PlanID      string     `json:"plan_id"`
		TenantID    string     `json:"tenant_id"`
		WitnessID   string     `json:"witness_id"`
		WitnessHash []byte     `json:"witness_hash"`
		Actions     []Action   `json:"actions"`
		Approvals   []Approval `json:"approvals,omitempty"`
		GeneratedAt int64      `json:"generated_at"`
	}{
		PlanID:      strings.TrimSpace(p.PlanID),
		TenantID:    strings.TrimSpace(p.TenantID),
		WitnessID:   strings.TrimSpace(p.WitnessID),
		WitnessHash: append([]byte(nil), p.WitnessHash...),
		Actions:     append([]Action(nil), p.Actions...),
		Approvals:   append([]Approval(nil), p.Approvals...),
		GeneratedAt: p.GeneratedAt,
	}
	return json.Marshal(content)
}

func (p Plan) validate() error {
	if strings.TrimSpace(p.PlanID) == "" || strings.TrimSpace(p.TenantID) == "" || strings.TrimSpace(p.WitnessID) == "" || len(p.WitnessHash) == 0 || p.GeneratedAt == 0 || len(p.Actions) == 0 {
		return ErrInvalidPlan
	}
	for _, action := range p.Actions {
		if strings.TrimSpace(action.AuthorityID) == "" || strings.TrimSpace(action.Operation) == "" {
			return ErrInvalidPlan
		}
		if strings.TrimSpace(action.RecordKey.TenantID) == "" || strings.TrimSpace(action.RecordKey.RecordType) == "" || strings.TrimSpace(action.RecordKey.StableID) == "" {
			return ErrInvalidPlan
		}
		if action.RecordKey.TenantID != p.TenantID {
			return ErrInvalidPlan
		}
	}
	return nil
}

func (s SignedPlan) Verify(trusted map[string]crypto.PublicKey) error {
	if strings.TrimSpace(s.AuthorityID) == "" || strings.TrimSpace(s.KeyID) == "" || len(s.Signature) == 0 || len(s.PublicKeyDER) == 0 {
		return ErrInvalidPlan
	}
	hash, err := s.Plan.Hash()
	if err != nil {
		return err
	}
	if !bytes.Equal(hash, s.PlanHash) {
		return fmt.Errorf("%w: plan hash mismatch", ErrInvalidPlan)
	}
	pub, ok := trusted[s.KeyID]
	if !ok {
		return fmt.Errorf("%w: untrusted plan key %s", ErrInvalidPlan, s.KeyID)
	}
	if pub.Algorithm != s.Algorithm || !bytes.Equal(pub.DER, s.PublicKeyDER) {
		return fmt.Errorf("%w: plan public key mismatch", ErrInvalidPlan)
	}
	if err := crypto.VerifyDigest(pub, hash, s.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: plan signature: %v", ErrInvalidPlan, err)
	}
	return nil
}

func EncodeSignedPlan(s SignedPlan) ([]byte, error) {
	if strings.TrimSpace(s.AuthorityID) == "" || strings.TrimSpace(s.KeyID) == "" || len(s.Signature) == 0 || len(s.PublicKeyDER) == 0 {
		return nil, ErrInvalidPlan
	}
	hash, err := s.Plan.Hash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(hash, s.PlanHash) {
		return nil, fmt.Errorf("%w: plan hash mismatch", ErrInvalidPlan)
	}
	return json.Marshal(s)
}

func DecodeSignedPlan(raw []byte) (SignedPlan, error) {
	var s SignedPlan
	if len(raw) == 0 {
		return SignedPlan{}, ErrInvalidPlan
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return SignedPlan{}, fmt.Errorf("%w: decode signed plan: %v", ErrInvalidPlan, err)
	}
	return s, nil
}

func RecordKeyRef(key canon.RecordKey) string {
	return strings.Join([]string{key.TenantID, key.RecordType, key.StableID}, "/")
}
