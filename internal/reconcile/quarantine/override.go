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
)

type OperatorOverride struct {
	TenantID          string           `json:"tenant_id"`
	AuthorityID       string           `json:"authority_id"`
	WitnessID         string           `json:"witness_id"`
	JustificationRef  string           `json:"justification_ref"`
	OperatorID        string           `json:"operator_id"`
	KeyID             string           `json:"key_id"`
	Algorithm         crypto.Algorithm `json:"algorithm"`
	PublicKeyDER      []byte           `json:"public_key_der"`
	Signature         []byte           `json:"signature"`
	SignedAt          int64            `json:"signed_at"`
	ReleaseReasonText string           `json:"release_reason_text"`
}

type OverrideDecision struct {
	Released bool
	Record   Record
	Event    eventspec.Event
}

func (o OperatorOverride) CanonicalBytes() ([]byte, error) {
	if strings.TrimSpace(o.TenantID) == "" || strings.TrimSpace(o.AuthorityID) == "" ||
		strings.TrimSpace(o.WitnessID) == "" || strings.TrimSpace(o.JustificationRef) == "" ||
		strings.TrimSpace(o.OperatorID) == "" || strings.TrimSpace(o.KeyID) == "" ||
		o.SignedAt == 0 || strings.TrimSpace(o.ReleaseReasonText) == "" {
		return nil, ErrInvalidOverride
	}
	return json.Marshal(struct {
		TenantID          string `json:"tenant_id"`
		AuthorityID       string `json:"authority_id"`
		WitnessID         string `json:"witness_id"`
		JustificationRef  string `json:"justification_ref"`
		OperatorID        string `json:"operator_id"`
		KeyID             string `json:"key_id"`
		SignedAt          int64  `json:"signed_at"`
		ReleaseReasonText string `json:"release_reason_text"`
	}{
		TenantID:          strings.TrimSpace(o.TenantID),
		AuthorityID:       strings.TrimSpace(o.AuthorityID),
		WitnessID:         strings.TrimSpace(o.WitnessID),
		JustificationRef:  strings.TrimSpace(o.JustificationRef),
		OperatorID:        strings.TrimSpace(o.OperatorID),
		KeyID:             strings.TrimSpace(o.KeyID),
		SignedAt:          o.SignedAt,
		ReleaseReasonText: strings.TrimSpace(o.ReleaseReasonText),
	})
}

func (m *Manager) OverrideRelease(ctx context.Context, idempotencyKey string, override OperatorOverride) (OverrideDecision, error) {
	if m == nil || m.log == nil || m.state == nil || strings.TrimSpace(idempotencyKey) == "" {
		return OverrideDecision{}, ErrInvalidOverride
	}
	if err := m.verifyOverride(override); err != nil {
		return OverrideDecision{}, err
	}
	rec, ok := m.state.Lookup(override.TenantID, override.AuthorityID)
	if !ok || !rec.Open || rec.State != StateQuarantined || rec.WitnessID != strings.TrimSpace(override.WitnessID) {
		return OverrideDecision{}, ErrInvalidOverride
	}
	overrideID := releaseID(override.TenantID, override.AuthorityID, override.WitnessID, override.KeyID, "operator_override")
	payload := Released{
		ReleaseID:         overrideID,
		TenantID:          strings.TrimSpace(override.TenantID),
		AuthorityID:       strings.TrimSpace(override.AuthorityID),
		WitnessID:         strings.TrimSpace(override.WitnessID),
		FromState:         StateQuarantined,
		ToState:           StateConsistent,
		Reason:            "operator_override",
		OverrideID:        overrideID,
		JustificationRef:  strings.TrimSpace(override.JustificationRef),
		ReleaseReasonText: strings.TrimSpace(override.ReleaseReasonText),
		ReleasedAt:        m.now().Unix(),
	}
	ev, err := m.append(ctx, "release-override:"+strings.TrimSpace(idempotencyKey), EventTypeReleased, payload.TenantID, payload)
	if err != nil {
		return OverrideDecision{}, err
	}
	closed, ok := m.state.release(payload.TenantID, payload.AuthorityID, payload.WitnessID)
	if !ok {
		return OverrideDecision{}, ErrInvalidOverride
	}
	return OverrideDecision{Released: true, Record: closed, Event: ev}, nil
}

func (m *Manager) verifyOverride(override OperatorOverride) error {
	payload, err := override.CanonicalBytes()
	if err != nil {
		return err
	}
	if len(override.Signature) == 0 || len(override.PublicKeyDER) == 0 || strings.TrimSpace(override.KeyID) == "" {
		return ErrInvalidOverride
	}
	trusted, ok := m.overrideKeys[strings.TrimSpace(override.KeyID)]
	if !ok {
		return ErrInvalidOverride
	}
	presented := crypto.PublicKey{Algorithm: override.Algorithm, DER: append([]byte(nil), override.PublicKeyDER...)}
	if presented.Algorithm != trusted.Algorithm || !bytes.Equal(presented.DER, trusted.DER) {
		return ErrInvalidOverride
	}
	d := crypto.SHA256Sum(payload)
	if err := crypto.VerifyDigest(trusted, d, override.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOverride, err)
	}
	return nil
}

func (o OperatorOverride) SignatureHash() (string, error) {
	payload, err := o.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.SHA256Sum(payload)), nil
}
