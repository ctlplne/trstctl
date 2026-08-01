// SPDX-License-Identifier: LicenseRef-trstctl-EE

package record

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	SchemaV1              = 1
	TypeDestructionRecord = "destruction_record.minted"

	commitmentDomain = "trstctl/vdec/destruction-record/commitment/v1"
	vectorDomain     = "trstctl/vdec/destruction-record/vector/v1"
)

var (
	ErrInvalidRecord = errors.New("destruction record: invalid")
	ErrUnverified    = errors.New("destruction record: unverified")
)

type Config struct {
	SignerID  string
	Algorithm crypto.Algorithm
	Now       func() time.Time
}

type Minter struct {
	mu       sync.Mutex
	signerID string
	key      *crypto.LockedSigner
	now      func() time.Time
	minted   map[string]SignedRecord
}

func NewMinter(cfg Config) (*Minter, error) {
	alg := cfg.Algorithm
	if alg == "" {
		alg = crypto.ECDSAP256
	}
	key, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, fmt.Errorf("destruction record: generate attestation key: %w", err)
	}
	signerID := strings.TrimSpace(cfg.SignerID)
	if signerID == "" {
		signerID = "trstctl-signer"
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Minter{signerID: signerID, key: key, now: now, minted: map[string]SignedRecord{}}, nil
}

func (m *Minter) PublicKey() crypto.PublicKey {
	if m == nil {
		return crypto.PublicKey{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		return crypto.PublicKey{}
	}
	pub := m.key.Public()
	pub.DER = cloneBytes(pub.DER)
	return pub
}

func (m *Minter) Destroy() {
	if m == nil || m.key == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		return
	}
	m.key.Destroy()
	m.key = nil
}

type MintRequest struct {
	TenantID                    string
	StableKeyID                 string
	FinalEpoch                  uint64
	CompletionEventsDigest      []byte
	RequiredSetDigest           []byte
	QuorumEvidence              *gate.QuorumEvidence
	RevocationCompletionDigest  []byte
	DestructionEvidence         EvidenceBinding
	AuditSeed                   string
	AuditRecords                []auditchain.Record
	AuditChainHead              string
	Successors                  []SuccessorKey
	PolicyRef                   string
	PolicyDecisionDigest        []byte
	TransparencyLogID           string
	TransparencyRootDigest      []byte
	TransparencyInclusionProof  [][]byte
	TransparencyTreeSize        uint64
	TransparencyCheckpointEpoch uint64
}

type EvidenceBinding struct {
	Kind               string `json:"kind"`
	Digest             []byte `json:"digest"`
	RecordDigest       []byte `json:"record_digest,omitempty"`
	AttestationClassID string `json:"attestation_class_id"`
}

func EvidenceFromDestruction(e gate.DestructionEvidence) EvidenceBinding {
	return EvidenceBinding{
		Kind:               e.Kind,
		Digest:             cloneBytes(e.Digest),
		RecordDigest:       crypto.SHA256Sum(e.Record),
		AttestationClassID: e.AttestationClassID,
	}
}

type SuccessorKey struct {
	ID        string           `json:"id"`
	Epoch     uint64           `json:"epoch"`
	Algorithm crypto.Algorithm `json:"algorithm"`
	PublicDER []byte           `json:"public_der"`
	Digest    []byte           `json:"digest,omitempty"`
}

// Commitment binds the VDEC-claim-1 destruction-record fields: the stable key
// identifier, the final epoch, the digest of the recorded per-job completion
// events, the destruction evidence, and the audit-chain head.
type Commitment struct {
	Version                    int                  `json:"version"`
	Domain                     string               `json:"domain"`
	TenantID                   string               `json:"tenant_id"`
	StableKeyID                string               `json:"stable_key_id"`
	FinalEpoch                 uint64               `json:"final_epoch"`
	CompletionEventsDigest     []byte               `json:"completion_events_digest"`
	RequiredSetDigest          []byte               `json:"required_set_digest,omitempty"`
	QuorumEvidence             *gate.QuorumEvidence `json:"quorum_evidence,omitempty"`
	RevocationCompletionDigest []byte               `json:"revocation_completion_digest,omitempty"`
	DestructionEvidence        EvidenceBinding      `json:"destruction_evidence"`
	AuditChainHead             string               `json:"audit_chain_head"`
	Successors                 []SuccessorKey       `json:"successors,omitempty"`
	PolicyRef                  string               `json:"policy_ref,omitempty"`
	PolicyDecisionDigest       []byte               `json:"policy_decision_digest,omitempty"`
	MintedAtUnix               int64                `json:"minted_at_unix"`
	Transparency               TransparencyProof    `json:"transparency,omitempty"`
}

type TransparencyProof struct {
	LogID           string   `json:"log_id,omitempty"`
	TreeSize        uint64   `json:"tree_size,omitempty"`
	CheckpointEpoch uint64   `json:"checkpoint_epoch,omitempty"`
	LeafDigest      []byte   `json:"leaf_digest,omitempty"`
	RootDigest      []byte   `json:"root_digest,omitempty"`
	Proof           [][]byte `json:"proof,omitempty"`
}

type SignedRecord struct {
	Version                 int                `json:"version"`
	Type                    string             `json:"type"`
	Commitment              Commitment         `json:"commitment"`
	CommitmentDigest        []byte             `json:"commitment_digest"`
	SignerID                string             `json:"signer_id"`
	AttestationAlgorithm    crypto.Algorithm   `json:"attestation_algorithm"`
	AttestationPublicKeyDER []byte             `json:"attestation_public_key_der"`
	Signature               []byte             `json:"signature"`
	Countersignatures       []Countersignature `json:"countersignatures,omitempty"`
}

func (m *Minter) Mint(ctx context.Context, req MintRequest) (SignedRecord, error) {
	if err := ctx.Err(); err != nil {
		return SignedRecord{}, err
	}
	if m == nil {
		return SignedRecord{}, fmt.Errorf("%w: missing attestation key", ErrInvalidRecord)
	}
	c, err := commitmentFromRequest(req, m.now().UTC())
	if err != nil {
		return SignedRecord{}, err
	}
	key := mintKey(c.TenantID, c.StableKeyID, c.FinalEpoch)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		return SignedRecord{}, fmt.Errorf("%w: missing attestation key", ErrInvalidRecord)
	}
	if existing, ok := m.minted[key]; ok {
		return cloneRecord(existing), nil
	}
	digest, err := CommitmentDigest(c)
	if err != nil {
		return SignedRecord{}, err
	}
	c.Transparency.LeafDigest = cloneBytes(digest)
	sig, err := m.key.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return SignedRecord{}, fmt.Errorf("destruction record: sign commitment: %w", err)
	}
	pub := m.key.Public()
	rec := SignedRecord{
		Version:                 SchemaV1,
		Type:                    TypeDestructionRecord,
		Commitment:              c,
		CommitmentDigest:        digest,
		SignerID:                m.signerID,
		AttestationAlgorithm:    pub.Algorithm,
		AttestationPublicKeyDER: cloneBytes(pub.DER),
		Signature:               sig,
	}
	rec = normalizeRecord(rec)
	m.minted[key] = rec
	return cloneRecord(rec), nil
}

func commitmentFromRequest(req MintRequest, now time.Time) (Commitment, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	stableKeyID := strings.TrimSpace(req.StableKeyID)
	if tenantID == "" || stableKeyID == "" || req.FinalEpoch == 0 {
		return Commitment{}, fmt.Errorf("%w: tenant, stable key id, and final epoch are required", ErrInvalidRecord)
	}
	if len(req.CompletionEventsDigest) == 0 {
		return Commitment{}, fmt.Errorf("%w: completion-events digest is required", ErrInvalidRecord)
	}
	ev := normalizeEvidence(req.DestructionEvidence)
	if ev.Kind == "" || len(ev.Digest) == 0 || strings.TrimSpace(ev.AttestationClassID) == "" {
		return Commitment{}, fmt.Errorf("%w: destruction evidence digest and class are required", ErrInvalidRecord)
	}
	auditHead := strings.TrimSpace(req.AuditChainHead)
	if len(req.AuditRecords) != 0 {
		computed := SealAuditHead(req.AuditSeed, req.AuditRecords)
		if auditHead != "" && auditHead != computed {
			return Commitment{}, fmt.Errorf("%w: audit chain head mismatch", ErrInvalidRecord)
		}
		auditHead = computed
	}
	if auditHead == "" {
		return Commitment{}, fmt.Errorf("%w: audit chain head is required", ErrInvalidRecord)
	}
	quorumEvidence, err := normalizeQuorumEvidenceForRequest(req.QuorumEvidence)
	if err != nil {
		return Commitment{}, err
	}
	return Commitment{
		Version:                    SchemaV1,
		Domain:                     commitmentDomain,
		TenantID:                   tenantID,
		StableKeyID:                stableKeyID,
		FinalEpoch:                 req.FinalEpoch,
		CompletionEventsDigest:     cloneBytes(req.CompletionEventsDigest),
		RequiredSetDigest:          cloneBytes(req.RequiredSetDigest),
		QuorumEvidence:             quorumEvidence,
		RevocationCompletionDigest: cloneBytes(req.RevocationCompletionDigest),
		DestructionEvidence:        ev,
		AuditChainHead:             auditHead,
		Successors:                 normalizeSuccessors(req.Successors),
		PolicyRef:                  strings.TrimSpace(req.PolicyRef),
		PolicyDecisionDigest:       cloneBytes(req.PolicyDecisionDigest),
		MintedAtUnix:               now.Unix(),
		Transparency: TransparencyProof{
			LogID:           strings.TrimSpace(req.TransparencyLogID),
			TreeSize:        req.TransparencyTreeSize,
			CheckpointEpoch: req.TransparencyCheckpointEpoch,
			RootDigest:      cloneBytes(req.TransparencyRootDigest),
			Proof:           clone2D(req.TransparencyInclusionProof),
		},
	}, nil
}

func CommitmentDigest(c Commitment) ([]byte, error) {
	raw, err := CanonicalCommitmentBytes(c)
	if err != nil {
		return nil, err
	}
	body := struct {
		Domain     string `json:"domain"`
		Commitment []byte `json:"commitment"`
	}{Domain: commitmentDomain, Commitment: raw}
	wrapped, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("destruction record: encode digest domain: %w", err)
	}
	return crypto.SHA256Sum(wrapped), nil
}

func CanonicalCommitmentBytes(c Commitment) ([]byte, error) {
	c = normalizeCommitment(c)
	// LeafDigest is derived from the commitment digest, so it is excluded from
	// the bytes being committed to avoid a circular self-reference.
	c.Transparency.LeafDigest = nil
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("destruction record: encode commitment: %w", err)
	}
	return raw, nil
}

func EncodeRecord(rec SignedRecord) ([]byte, error) {
	rec = normalizeRecord(rec)
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("destruction record: encode signed record: %w", err)
	}
	return raw, nil
}

func DecodeRecord(raw []byte) (SignedRecord, error) {
	if len(raw) == 0 {
		return SignedRecord{}, fmt.Errorf("%w: missing encoded record", ErrInvalidRecord)
	}
	var rec SignedRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return SignedRecord{}, fmt.Errorf("%w: decode signed record: %v", ErrInvalidRecord, err)
	}
	return normalizeRecord(rec), nil
}

func VerifyRecord(rec SignedRecord, trust crypto.PublicKey) error {
	rec = normalizeRecord(rec)
	if rec.Version != SchemaV1 || rec.Type != TypeDestructionRecord {
		return fmt.Errorf("%w: unsupported record type or version", ErrInvalidRecord)
	}
	if trust.Algorithm == "" || len(trust.DER) == 0 {
		return fmt.Errorf("%w: missing verification key", ErrUnverified)
	}
	if rec.AttestationAlgorithm != trust.Algorithm || !bytes.Equal(rec.AttestationPublicKeyDER, trust.DER) {
		return fmt.Errorf("%w: attestation key does not match trust root", ErrUnverified)
	}
	digest, err := CommitmentDigest(rec.Commitment)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, rec.CommitmentDigest) {
		return fmt.Errorf("%w: commitment digest mismatch", ErrUnverified)
	}
	if !bytes.Equal(rec.Commitment.Transparency.LeafDigest, nil) && !bytes.Equal(rec.Commitment.Transparency.LeafDigest, digest) {
		return fmt.Errorf("%w: transparency leaf mismatch", ErrUnverified)
	}
	if err := crypto.VerifyDigest(trust, digest, rec.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: %v", ErrUnverified, err)
	}
	return nil
}

func VerifyEncoded(raw []byte, trust crypto.PublicKey) (SignedRecord, error) {
	rec, err := DecodeRecord(raw)
	if err != nil {
		return SignedRecord{}, err
	}
	return rec, VerifyRecord(rec, trust)
}

func SealAuditHead(seed string, records []auditchain.Record) string {
	cloned := make([]auditchain.Record, len(records))
	for i, r := range records {
		cloned[i] = r
		cloned[i].Data = append([]byte(nil), r.Data...)
		if r.Actor != nil {
			actor := *r.Actor
			actor.Roles = append([]string(nil), r.Actor.Roles...)
			cloned[i].Actor = &actor
		}
	}
	return auditchain.SealFrom(seed, cloned)
}

type PublishedVector struct {
	Version                 int              `json:"version"`
	Domain                  string           `json:"domain"`
	Name                    string           `json:"name"`
	EncodedRecord           []byte           `json:"encoded_record"`
	EncodedRecordDigest     []byte           `json:"encoded_record_digest"`
	AttestationAlgorithm    crypto.Algorithm `json:"attestation_algorithm"`
	AttestationPublicKeyDER []byte           `json:"attestation_public_key_der"`
}

func Vector(name string, rec SignedRecord) (PublishedVector, error) {
	encoded, err := EncodeRecord(rec)
	if err != nil {
		return PublishedVector{}, err
	}
	return PublishedVector{
		Version:                 SchemaV1,
		Domain:                  vectorDomain,
		Name:                    strings.TrimSpace(name),
		EncodedRecord:           encoded,
		EncodedRecordDigest:     crypto.SHA256Sum(encoded),
		AttestationAlgorithm:    rec.AttestationAlgorithm,
		AttestationPublicKeyDER: cloneBytes(rec.AttestationPublicKeyDER),
	}, nil
}

func normalizeRecord(rec SignedRecord) SignedRecord {
	rec.Version = SchemaV1
	if rec.Type == "" {
		rec.Type = TypeDestructionRecord
	}
	rec.Commitment = normalizeCommitment(rec.Commitment)
	rec.CommitmentDigest = cloneBytes(rec.CommitmentDigest)
	rec.AttestationPublicKeyDER = cloneBytes(rec.AttestationPublicKeyDER)
	rec.Signature = cloneBytes(rec.Signature)
	rec.Countersignatures = cloneCountersignatures(rec.Countersignatures)
	return rec
}

func normalizeCommitment(c Commitment) Commitment {
	c.Version = SchemaV1
	c.Domain = commitmentDomain
	c.TenantID = strings.TrimSpace(c.TenantID)
	c.StableKeyID = strings.TrimSpace(c.StableKeyID)
	c.CompletionEventsDigest = cloneBytes(c.CompletionEventsDigest)
	c.RequiredSetDigest = cloneBytes(c.RequiredSetDigest)
	c.QuorumEvidence = cloneQuorumEvidence(c.QuorumEvidence)
	c.RevocationCompletionDigest = cloneBytes(c.RevocationCompletionDigest)
	c.DestructionEvidence = normalizeEvidence(c.DestructionEvidence)
	c.AuditChainHead = strings.TrimSpace(c.AuditChainHead)
	c.Successors = normalizeSuccessors(c.Successors)
	c.PolicyRef = strings.TrimSpace(c.PolicyRef)
	c.PolicyDecisionDigest = cloneBytes(c.PolicyDecisionDigest)
	c.Transparency.LogID = strings.TrimSpace(c.Transparency.LogID)
	c.Transparency.LeafDigest = cloneBytes(c.Transparency.LeafDigest)
	c.Transparency.RootDigest = cloneBytes(c.Transparency.RootDigest)
	c.Transparency.Proof = clone2D(c.Transparency.Proof)
	return c
}

func normalizeEvidence(e EvidenceBinding) EvidenceBinding {
	return EvidenceBinding{
		Kind:               strings.TrimSpace(e.Kind),
		Digest:             cloneBytes(e.Digest),
		RecordDigest:       cloneBytes(e.RecordDigest),
		AttestationClassID: strings.TrimSpace(e.AttestationClassID),
	}
}

func normalizeQuorumEvidenceForRequest(in *gate.QuorumEvidence) (*gate.QuorumEvidence, error) {
	if in == nil {
		return nil, nil
	}
	ev := gate.NormalizeQuorumEvidence(*in)
	if err := gate.ValidateQuorumEvidence(ev); err != nil {
		return nil, fmt.Errorf("%w: quorum evidence: %v", ErrInvalidRecord, err)
	}
	return cloneQuorumEvidence(&ev), nil
}

func cloneQuorumEvidence(in *gate.QuorumEvidence) *gate.QuorumEvidence {
	if in == nil {
		return nil
	}
	ev := gate.NormalizeQuorumEvidence(*in)
	ev.Approvers = append([]string(nil), ev.Approvers...)
	ev.ApproverDigest = cloneBytes(ev.ApproverDigest)
	return &ev
}

func normalizeSuccessors(in []SuccessorKey) []SuccessorKey {
	out := make([]SuccessorKey, 0, len(in))
	for _, s := range in {
		s.ID = strings.TrimSpace(s.ID)
		s.PublicDER = cloneBytes(s.PublicDER)
		s.Digest = cloneBytes(s.Digest)
		if len(s.Digest) == 0 {
			body := struct {
				ID        string           `json:"id"`
				Epoch     uint64           `json:"epoch"`
				Algorithm crypto.Algorithm `json:"algorithm"`
				PublicDER []byte           `json:"public_der"`
			}{ID: s.ID, Epoch: s.Epoch, Algorithm: s.Algorithm, PublicDER: s.PublicDER}
			raw, _ := json.Marshal(body)
			s.Digest = crypto.SHA256Sum(raw)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Epoch != out[j].Epoch {
			return out[i].Epoch < out[j].Epoch
		}
		if out[i].Algorithm != out[j].Algorithm {
			return out[i].Algorithm < out[j].Algorithm
		}
		return bytes.Compare(out[i].PublicDER, out[j].PublicDER) < 0
	})
	return out
}

func cloneRecord(in SignedRecord) SignedRecord { return normalizeRecord(in) }

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}

func clone2D(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = cloneBytes(in[i])
	}
	return out
}

func mintKey(tenantID, stableKeyID string, epoch uint64) string {
	return strings.TrimSpace(tenantID) + "\x00" + strings.TrimSpace(stableKeyID) + "\x00" + fmt.Sprint(epoch)
}
