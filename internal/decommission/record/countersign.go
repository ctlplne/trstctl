// SPDX-License-Identifier: BUSL-1.1

package record

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

const (
	TypeRecordCountersigned = "destruction_record.countersigned"

	countersignDomain = "trstctl/vdec/destruction-record/countersignature/v1"
)

var ErrDistinctAuthorityRequired = errors.New("destruction record: countersignature authority must be distinct")

// Countersignature is the VDEC-claim-8 field: a countersignature by an authority
// distinct from the minting signer, recorded as a ledger event, separately
// verifiable by a relying party holding the authority's key, and absent from the
// commitment so the record stays verifiable without it.
type Countersignature struct {
	Version                int              `json:"version"`
	Domain                 string           `json:"domain"`
	AuthorityID            string           `json:"authority_id"`
	KeyID                  string           `json:"key_id"`
	Algorithm              crypto.Algorithm `json:"algorithm"`
	PublicKeyDER           []byte           `json:"public_key_der"`
	CommitmentDigest       []byte           `json:"commitment_digest"`
	MintingSignatureDigest []byte           `json:"minting_signature_digest"`
	SignedAtUnix           int64            `json:"signed_at_unix"`
	Signature              []byte           `json:"signature"`
}

type CountersignatureRequest struct {
	AuthorityID string
	KeyID       string
	Signer      crypto.DigestSigner
	Sink        CountersignatureAppendSink
	Now         func() time.Time
}

type CountersignatureAppendSink interface {
	Append(context.Context, eventspec.Event) (eventspec.Event, error)
}

type CountersignatureEvent struct {
	Version          int              `json:"version"`
	TenantID         string           `json:"tenant_id"`
	StableKeyID      string           `json:"stable_key_id"`
	FinalEpoch       uint64           `json:"final_epoch"`
	CommitmentDigest []byte           `json:"commitment_digest"`
	Countersignature Countersignature `json:"countersignature"`
}

func AttachCountersignature(ctx context.Context, rec SignedRecord, req CountersignatureRequest) (SignedRecord, error) {
	if err := ctx.Err(); err != nil {
		return SignedRecord{}, err
	}
	rec = normalizeRecord(rec)
	if err := validateBaseRecordForCountersign(rec); err != nil {
		return SignedRecord{}, err
	}
	if req.Signer == nil {
		return SignedRecord{}, fmt.Errorf("%w: authority signer is required", ErrInvalidRecord)
	}
	if req.Sink == nil {
		return SignedRecord{}, fmt.Errorf("%w: countersignature event sink is required", ErrInvalidRecord)
	}
	authorityID := strings.TrimSpace(req.AuthorityID)
	keyID := strings.TrimSpace(req.KeyID)
	if authorityID == "" || keyID == "" {
		return SignedRecord{}, fmt.Errorf("%w: authority id and key id are required", ErrInvalidRecord)
	}
	pub := req.Signer.Public()
	if err := requireDistinctAuthority(rec, authorityID, pub); err != nil {
		return SignedRecord{}, err
	}
	payload, err := CountersignaturePayload(rec)
	if err != nil {
		return SignedRecord{}, err
	}
	sig, err := crypto.SignMessage(req.Signer, payload)
	if err != nil {
		return SignedRecord{}, fmt.Errorf("destruction record: countersign: %w", err)
	}
	now := req.Now
	if now == nil {
		now = time.Now
	}
	cs := normalizeCountersignature(Countersignature{
		AuthorityID:            authorityID,
		KeyID:                  keyID,
		Algorithm:              pub.Algorithm,
		PublicKeyDER:           pub.DER,
		CommitmentDigest:       rec.CommitmentDigest,
		MintingSignatureDigest: crypto.SHA256Sum(rec.Signature),
		SignedAtUnix:           now().UTC().Unix(),
		Signature:              sig,
	})
	if err := VerifyCountersignature(rec, cs, pub); err != nil {
		return SignedRecord{}, err
	}
	event := CountersignatureEvent{
		Version:          SchemaV1,
		TenantID:         rec.Commitment.TenantID,
		StableKeyID:      rec.Commitment.StableKeyID,
		FinalEpoch:       rec.Commitment.FinalEpoch,
		CommitmentDigest: cloneBytes(rec.CommitmentDigest),
		Countersignature: cs,
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return SignedRecord{}, fmt.Errorf("destruction record: encode countersignature event: %w", err)
	}
	if _, err := req.Sink.Append(ctx, eventspec.Event{
		Type:          TypeRecordCountersigned,
		TenantID:      rec.Commitment.TenantID,
		SchemaVersion: SchemaV1,
		Data:          raw,
	}); err != nil {
		return SignedRecord{}, fmt.Errorf("destruction record: append countersignature event: %w", err)
	}
	rec.Countersignatures = append(cloneCountersignatures(rec.Countersignatures), cs)
	return normalizeRecord(rec), nil
}

func VerifyCountersignature(rec SignedRecord, cs Countersignature, trust crypto.PublicKey) error {
	rec = normalizeRecord(rec)
	cs = normalizeCountersignature(cs)
	if err := validateBaseRecordForCountersign(rec); err != nil {
		return err
	}
	if trust.Algorithm == "" || len(trust.DER) == 0 {
		return fmt.Errorf("%w: missing countersignature trust key", ErrUnverified)
	}
	if cs.Algorithm != trust.Algorithm || !bytes.Equal(cs.PublicKeyDER, trust.DER) {
		return fmt.Errorf("%w: countersignature key does not match trust root", ErrUnverified)
	}
	if err := requireDistinctAuthority(rec, cs.AuthorityID, trust); err != nil {
		return err
	}
	if !bytes.Equal(cs.CommitmentDigest, rec.CommitmentDigest) {
		return fmt.Errorf("%w: countersignature commitment digest mismatch", ErrUnverified)
	}
	if !bytes.Equal(cs.MintingSignatureDigest, crypto.SHA256Sum(rec.Signature)) {
		return fmt.Errorf("%w: countersignature minting signature digest mismatch", ErrUnverified)
	}
	payload, err := CountersignaturePayload(rec)
	if err != nil {
		return err
	}
	if err := crypto.VerifyMessage(trust.DER, payload, cs.Signature); err != nil {
		return fmt.Errorf("%w: countersignature: %v", ErrUnverified, err)
	}
	return nil
}

func VerifyCountersignatures(rec SignedRecord, trust map[string]crypto.PublicKey) error {
	for _, cs := range rec.Countersignatures {
		pub, ok := trust[cs.KeyID]
		if !ok {
			return fmt.Errorf("%w: untrusted countersignature key %s", ErrUnverified, cs.KeyID)
		}
		if err := VerifyCountersignature(rec, cs, pub); err != nil {
			return err
		}
	}
	return nil
}

func CountersignaturePayload(rec SignedRecord) ([]byte, error) {
	rec = normalizeRecord(rec)
	if err := validateBaseRecordForCountersign(rec); err != nil {
		return nil, err
	}
	body := struct {
		Domain                  string           `json:"domain"`
		RecordType              string           `json:"record_type"`
		RecordVersion           int              `json:"record_version"`
		CommitmentDigest        []byte           `json:"commitment_digest"`
		SignerID                string           `json:"signer_id"`
		AttestationAlgorithm    crypto.Algorithm `json:"attestation_algorithm"`
		AttestationPublicKeyDER []byte           `json:"attestation_public_key_der"`
		MintingSignature        []byte           `json:"minting_signature"`
	}{
		Domain:                  countersignDomain,
		RecordType:              rec.Type,
		RecordVersion:           rec.Version,
		CommitmentDigest:        cloneBytes(rec.CommitmentDigest),
		SignerID:                rec.SignerID,
		AttestationAlgorithm:    rec.AttestationAlgorithm,
		AttestationPublicKeyDER: cloneBytes(rec.AttestationPublicKeyDER),
		MintingSignature:        cloneBytes(rec.Signature),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("destruction record: encode countersignature payload: %w", err)
	}
	return raw, nil
}

func validateBaseRecordForCountersign(rec SignedRecord) error {
	if rec.Version != SchemaV1 || rec.Type != TypeDestructionRecord || len(rec.Signature) == 0 || len(rec.CommitmentDigest) == 0 {
		return fmt.Errorf("%w: base record is incomplete", ErrInvalidRecord)
	}
	digest, err := CommitmentDigest(rec.Commitment)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, rec.CommitmentDigest) {
		return fmt.Errorf("%w: base commitment digest mismatch", ErrUnverified)
	}
	return nil
}

func requireDistinctAuthority(rec SignedRecord, authorityID string, pub crypto.PublicKey) error {
	if strings.TrimSpace(authorityID) == strings.TrimSpace(rec.SignerID) {
		return ErrDistinctAuthorityRequired
	}
	if pub.Algorithm == rec.AttestationAlgorithm && bytes.Equal(pub.DER, rec.AttestationPublicKeyDER) {
		return ErrDistinctAuthorityRequired
	}
	return nil
}

func normalizeCountersignature(cs Countersignature) Countersignature {
	cs.Version = SchemaV1
	cs.Domain = countersignDomain
	cs.AuthorityID = strings.TrimSpace(cs.AuthorityID)
	cs.KeyID = strings.TrimSpace(cs.KeyID)
	cs.PublicKeyDER = cloneBytes(cs.PublicKeyDER)
	cs.CommitmentDigest = cloneBytes(cs.CommitmentDigest)
	cs.MintingSignatureDigest = cloneBytes(cs.MintingSignatureDigest)
	cs.Signature = cloneBytes(cs.Signature)
	return cs
}

func cloneCountersignatures(in []Countersignature) []Countersignature {
	if len(in) == 0 {
		return nil
	}
	out := make([]Countersignature, len(in))
	for i, cs := range in {
		out[i] = normalizeCountersignature(cs)
	}
	return out
}
