// SPDX-License-Identifier: BUSL-1.1

package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

const (
	TypeCeremonyBundleReplayed = "gated_destruction.ceremony_replayed"

	ceremonyBundleDomain = "trstctl/vdec/gated-destruction/ceremony-bundle/v1"
	defaultCeremonyKeyID = "vdec-gated-destruction-ceremony"
)

var ErrInvalidCeremonyBundle = errors.New("vdec ceremony: invalid bundle")

type CeremonyConfig struct {
	SignerID     string
	KeyID        string
	Algorithm    crypto.Algorithm
	QuorumPolicy QuorumPolicy
	Now          func() time.Time
}

type CeremonySigner struct {
	mu       sync.Mutex
	signerID string
	keyID    string
	key      *crypto.LockedSigner
	quorum   QuorumPolicy
	now      func() time.Time
}

type CeremonyRequest struct {
	TenantID                   string
	StableKeyID                string
	FinalEpoch                 uint64
	KeyClass                   string
	CompletionEventsDigest     []byte
	RequiredSetDigest          []byte
	RevocationCompletionDigest []byte
	DestructionEvidence        DestructionEvidence
	AuditChainHead             string
	QuorumApprovals            []byte
}

type CeremonyBundle struct {
	Version                    int                 `json:"version"`
	Domain                     string              `json:"domain"`
	TenantID                   string              `json:"tenant_id"`
	StableKeyID                string              `json:"stable_key_id"`
	FinalEpoch                 uint64              `json:"final_epoch"`
	KeyClass                   string              `json:"key_class"`
	CompletionEventsDigest     []byte              `json:"completion_events_digest"`
	RequiredSetDigest          []byte              `json:"required_set_digest,omitempty"`
	RevocationCompletionDigest []byte              `json:"revocation_completion_digest,omitempty"`
	DestructionEvidence        DestructionEvidence `json:"destruction_evidence"`
	AuditChainHead             string              `json:"audit_chain_head"`
	QuorumEvidence             QuorumEvidence      `json:"quorum_evidence"`
	ConductedAtUnix            int64               `json:"conducted_at_unix"`
	AuthorityID                string              `json:"authority_id"`
	KeyID                      string              `json:"key_id"`
	Algorithm                  crypto.Algorithm    `json:"algorithm"`
	PublicKeyDER               []byte              `json:"public_key_der"`
	Signature                  []byte              `json:"signature,omitempty"`
}

func NewCeremonySigner(cfg CeremonyConfig) (*CeremonySigner, error) {
	alg := cfg.Algorithm
	if alg == "" {
		alg = crypto.ECDSAP256
	}
	key, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, fmt.Errorf("vdec ceremony: keygen: %w", err)
	}
	signerID := strings.TrimSpace(cfg.SignerID)
	if signerID == "" {
		signerID = "trstctl-signer"
	}
	keyID := strings.TrimSpace(cfg.KeyID)
	if keyID == "" {
		keyID = defaultCeremonyKeyID
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &CeremonySigner{
		signerID: signerID,
		keyID:    keyID,
		key:      key,
		quorum:   cloneQuorumPolicy(cfg.QuorumPolicy),
		now:      now,
	}, nil
}

func (s *CeremonySigner) PublicKey() crypto.PublicKey {
	if s == nil {
		return crypto.PublicKey{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return crypto.PublicKey{}
	}
	pub := s.key.Public()
	pub.DER = append([]byte(nil), pub.DER...)
	return pub
}

func (s *CeremonySigner) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		s.key.Destroy()
		s.key = nil
	}
}

func (s *CeremonySigner) Bundle(ctx context.Context, req CeremonyRequest) (CeremonyBundle, error) {
	if err := ctx.Err(); err != nil {
		return CeremonyBundle{}, err
	}
	if s == nil {
		return CeremonyBundle{}, fmt.Errorf("%w: missing ceremony signer", ErrInvalidCeremonyBundle)
	}
	keyClass := strings.TrimSpace(req.KeyClass)
	if _, required := s.quorum.Requirement(keyClass); !required {
		return CeremonyBundle{}, fmt.Errorf("%w: no quorum policy for key class %s", ErrQuorumNotMet, keyClass)
	}
	quorumEvidence, err := s.quorum.VerifyApprovals(keyClass, req.QuorumApprovals)
	if err != nil {
		return CeremonyBundle{}, err
	}
	body := CeremonyBundle{
		Version:                    SchemaV1,
		Domain:                     ceremonyBundleDomain,
		TenantID:                   strings.TrimSpace(req.TenantID),
		StableKeyID:                strings.TrimSpace(req.StableKeyID),
		FinalEpoch:                 req.FinalEpoch,
		KeyClass:                   keyClass,
		CompletionEventsDigest:     cloneBytes(req.CompletionEventsDigest),
		RequiredSetDigest:          cloneBytes(req.RequiredSetDigest),
		RevocationCompletionDigest: cloneBytes(req.RevocationCompletionDigest),
		DestructionEvidence:        normalizeDestructionEvidence(req.DestructionEvidence),
		AuditChainHead:             strings.TrimSpace(req.AuditChainHead),
		QuorumEvidence:             quorumEvidence,
		ConductedAtUnix:            s.now().UTC().Unix(),
		AuthorityID:                s.signerID,
		KeyID:                      s.keyID,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return CeremonyBundle{}, fmt.Errorf("%w: ceremony signer destroyed", ErrInvalidCeremonyBundle)
	}
	pub := s.key.Public()
	body.Algorithm = pub.Algorithm
	body.PublicKeyDER = append([]byte(nil), pub.DER...)
	payload, err := body.CanonicalBytes()
	if err != nil {
		return CeremonyBundle{}, err
	}
	sig, err := crypto.SignMessage(s.key, payload)
	if err != nil {
		return CeremonyBundle{}, fmt.Errorf("vdec ceremony: sign bundle: %w", err)
	}
	body.Signature = sig
	return normalizeCeremonyBundle(body), nil
}

func (b CeremonyBundle) CanonicalBytes() ([]byte, error) {
	b = normalizeCeremonyBundle(b)
	if err := validateCeremonyBundleBody(b); err != nil {
		return nil, err
	}
	b.Signature = nil
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("vdec ceremony: encode bundle body: %w", err)
	}
	return raw, nil
}

func EncodeCeremonyBundle(b CeremonyBundle) ([]byte, error) {
	b = normalizeCeremonyBundle(b)
	if err := VerifyCeremonyBundleFields(b); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("vdec ceremony: encode bundle: %w", err)
	}
	return raw, nil
}

func DecodeCeremonyBundle(raw []byte) (CeremonyBundle, error) {
	if len(raw) == 0 {
		return CeremonyBundle{}, fmt.Errorf("%w: missing bundle", ErrInvalidCeremonyBundle)
	}
	var b CeremonyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return CeremonyBundle{}, fmt.Errorf("%w: decode bundle: %v", ErrInvalidCeremonyBundle, err)
	}
	return normalizeCeremonyBundle(b), nil
}

func NormalizeCeremonyBundleForRecord(b CeremonyBundle) CeremonyBundle {
	return normalizeCeremonyBundle(b)
}

func VerifyCeremonyBundle(b CeremonyBundle, trust crypto.PublicKey, policy QuorumPolicy) error {
	b = normalizeCeremonyBundle(b)
	if err := VerifyCeremonyBundleFields(b); err != nil {
		return err
	}
	if trust.Algorithm == "" || len(trust.DER) == 0 {
		return fmt.Errorf("%w: missing ceremony trust key", ErrInvalidCeremonyBundle)
	}
	if b.Algorithm != trust.Algorithm || !bytesEqual(b.PublicKeyDER, trust.DER) {
		return fmt.Errorf("%w: ceremony key does not match trust root", ErrInvalidCeremonyBundle)
	}
	payload, err := b.CanonicalBytes()
	if err != nil {
		return err
	}
	if err := crypto.VerifyMessage(trust.DER, payload, b.Signature); err != nil {
		return fmt.Errorf("%w: signature: %v", ErrInvalidCeremonyBundle, err)
	}
	if _, required := policy.Requirement(b.KeyClass); !required {
		return fmt.Errorf("%w: no quorum policy for key class %s", ErrQuorumNotMet, b.KeyClass)
	}
	if err := policy.VerifyEvidence(b.KeyClass, b.QuorumEvidence); err != nil {
		return err
	}
	return nil
}

func VerifyCeremonyBundleFields(b CeremonyBundle) error {
	if err := validateCeremonyBundleBody(b); err != nil {
		return err
	}
	if len(b.Signature) == 0 {
		return fmt.Errorf("%w: signature is required", ErrInvalidCeremonyBundle)
	}
	return nil
}

func ReconcileCeremonyBundle(ctx context.Context, b CeremonyBundle, trust crypto.PublicKey, policy QuorumPolicy, sink EvidenceAppendSink) (eventspec.Event, error) {
	if err := ctx.Err(); err != nil {
		return eventspec.Event{}, err
	}
	if sink == nil {
		return eventspec.Event{}, fmt.Errorf("%w: replay sink is required", ErrInvalidCeremonyBundle)
	}
	if err := VerifyCeremonyBundle(b, trust, policy); err != nil {
		return eventspec.Event{}, err
	}
	b = normalizeCeremonyBundle(b)
	raw, err := EncodeCeremonyBundle(b)
	if err != nil {
		return eventspec.Event{}, err
	}
	appended, err := sink.Append(ctx, eventspec.Event{
		Type:          TypeCeremonyBundleReplayed,
		TenantID:      b.TenantID,
		SchemaVersion: SchemaV1,
		Data:          raw,
	})
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("vdec ceremony: append replay event: %w", err)
	}
	return appended, nil
}

func validateCeremonyBundleBody(b CeremonyBundle) error {
	if b.Version != SchemaV1 || b.Domain != ceremonyBundleDomain {
		return fmt.Errorf("%w: unsupported bundle version or domain", ErrInvalidCeremonyBundle)
	}
	if strings.TrimSpace(b.TenantID) == "" || strings.TrimSpace(b.StableKeyID) == "" || b.FinalEpoch == 0 {
		return fmt.Errorf("%w: tenant, stable key id, and final epoch are required", ErrInvalidCeremonyBundle)
	}
	if strings.TrimSpace(b.KeyClass) == "" || len(b.CompletionEventsDigest) == 0 || strings.TrimSpace(b.AuditChainHead) == "" {
		return fmt.Errorf("%w: key class, completion digest, and audit head are required", ErrInvalidCeremonyBundle)
	}
	if strings.TrimSpace(b.AuthorityID) == "" || strings.TrimSpace(b.KeyID) == "" || b.Algorithm == "" || len(b.PublicKeyDER) == 0 || b.ConductedAtUnix == 0 {
		return fmt.Errorf("%w: signing authority metadata is required", ErrInvalidCeremonyBundle)
	}
	if b.DestructionEvidence.Kind == "" || len(b.DestructionEvidence.Digest) == 0 || len(b.DestructionEvidence.Record) == 0 || strings.TrimSpace(b.DestructionEvidence.AttestationClassID) == "" {
		return fmt.Errorf("%w: destruction evidence is required", ErrInvalidCeremonyBundle)
	}
	if err := ValidateQuorumEvidence(b.QuorumEvidence); err != nil {
		return err
	}
	return nil
}

func normalizeCeremonyBundle(b CeremonyBundle) CeremonyBundle {
	b.Version = SchemaV1
	b.Domain = ceremonyBundleDomain
	b.TenantID = strings.TrimSpace(b.TenantID)
	b.StableKeyID = strings.TrimSpace(b.StableKeyID)
	b.KeyClass = strings.TrimSpace(b.KeyClass)
	b.CompletionEventsDigest = cloneBytes(b.CompletionEventsDigest)
	b.RequiredSetDigest = cloneBytes(b.RequiredSetDigest)
	b.RevocationCompletionDigest = cloneBytes(b.RevocationCompletionDigest)
	b.DestructionEvidence = normalizeDestructionEvidence(b.DestructionEvidence)
	b.AuditChainHead = strings.TrimSpace(b.AuditChainHead)
	b.QuorumEvidence = NormalizeQuorumEvidence(b.QuorumEvidence)
	b.AuthorityID = strings.TrimSpace(b.AuthorityID)
	b.KeyID = strings.TrimSpace(b.KeyID)
	b.PublicKeyDER = cloneBytes(b.PublicKeyDER)
	b.Signature = cloneBytes(b.Signature)
	return b
}

func normalizeDestructionEvidence(e DestructionEvidence) DestructionEvidence {
	e.Kind = strings.TrimSpace(e.Kind)
	e.TenantID = strings.TrimSpace(e.TenantID)
	e.StableKeyID = strings.TrimSpace(e.StableKeyID)
	e.AttestationClassID = strings.TrimSpace(e.AttestationClassID)
	if e.AttestationClassID == "" && e.AttestationClass != ClassNone {
		e.AttestationClassID = e.AttestationClass.ID()
	}
	e.Record = cloneBytes(e.Record)
	e.Digest = cloneBytes(e.Digest)
	return e
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}
