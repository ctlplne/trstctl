// SPDX-License-Identifier: LicenseRef-trstctl-EE

package aggregate

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

	"trstctl.com/trstctl/ee/decommission/record"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	SchemaV1            = 1
	TypeAggregateRecord = "aggregate_decommissioning_record.minted"

	commitmentDomain = "trstctl/vdec/aggregate-decommissioning-record/commitment/v1"
	vectorDomain     = "trstctl/vdec/aggregate-decommissioning-record/vector/v1"
)

var (
	ErrInvalidRecord = errors.New("aggregate decommissioning record: invalid")
	ErrUnverified    = errors.New("aggregate decommissioning record: unverified")
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

// NewMinter builds the minter for the VDEC-claim-9 tenant-scope aggregate
// decommissioning record, which binds the tenant identifier, the digests of the
// per-key destruction records, and the audit head after the last destroyed key.
// VDEC-claim-18 accepts verification of this aggregate record in place of
// recomputing the per-key completion digest.
func NewMinter(cfg Config) (*Minter, error) {
	alg := cfg.Algorithm
	if alg == "" {
		alg = crypto.ECDSAP256
	}
	key, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, fmt.Errorf("aggregate decommissioning record: generate attestation key: %w", err)
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
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key != nil {
		m.key.Destroy()
		m.key = nil
	}
}

type MintRequest struct {
	TenantID                string
	Records                 []LeafInput
	AuditChainHead          string
	InventoryLedgerPosition uint64
	InventoryKeyIDs         []string
	InventoryDigest         []byte
	Campaign                *CampaignBinding
	SanitizationClaims      []SanitizationClaim
	GovernanceEvidenceRefs  []string
}

type LeafInput struct {
	KeyClass string
	Record   record.SignedRecord
}

type Leaf struct {
	TenantID         string `json:"tenant_id"`
	StableKeyID      string `json:"stable_key_id"`
	FinalEpoch       uint64 `json:"final_epoch"`
	KeyClass         string `json:"key_class"`
	RecordDigest     []byte `json:"record_digest"`
	CommitmentDigest []byte `json:"commitment_digest"`
}

type KeyClassCount struct {
	KeyClass string `json:"key_class"`
	Count    int    `json:"count"`
}

type InventoryCompleteness struct {
	LedgerPosition uint64 `json:"ledger_position"`
	KeyCount       int    `json:"key_count"`
	Digest         []byte `json:"digest"`
	Exhausted      bool   `json:"exhausted"`
}

type Commitment struct {
	Version                int                   `json:"version"`
	Domain                 string                `json:"domain"`
	TenantID               string                `json:"tenant_id"`
	Leaves                 []Leaf                `json:"leaves"`
	LeafRoot               []byte                `json:"leaf_root"`
	KeyClassCounts         []KeyClassCount       `json:"key_class_counts,omitempty"`
	AuditChainHead         string                `json:"audit_chain_head"`
	Inventory              InventoryCompleteness `json:"inventory"`
	Campaign               *CampaignBinding      `json:"campaign,omitempty"`
	SanitizationClaims     []SanitizationClaim   `json:"sanitization_claims,omitempty"`
	GovernanceEvidenceRefs []string              `json:"governance_evidence_refs,omitempty"`
	MintedAtUnix           int64                 `json:"minted_at_unix"`
}

type SignedRecord struct {
	Version                 int              `json:"version"`
	Type                    string           `json:"type"`
	Commitment              Commitment       `json:"commitment"`
	CommitmentDigest        []byte           `json:"commitment_digest"`
	SignerID                string           `json:"signer_id"`
	AttestationAlgorithm    crypto.Algorithm `json:"attestation_algorithm"`
	AttestationPublicKeyDER []byte           `json:"attestation_public_key_der"`
	Signature               []byte           `json:"signature"`
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
	key := mintKey(c.TenantID, c.Inventory.LedgerPosition, c.LeafRoot)
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
	sig, err := m.key.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return SignedRecord{}, fmt.Errorf("aggregate decommissioning record: sign commitment: %w", err)
	}
	pub := m.key.Public()
	rec := normalizeRecord(SignedRecord{
		Version:                 SchemaV1,
		Type:                    TypeAggregateRecord,
		Commitment:              c,
		CommitmentDigest:        digest,
		SignerID:                m.signerID,
		AttestationAlgorithm:    pub.Algorithm,
		AttestationPublicKeyDER: cloneBytes(pub.DER),
		Signature:               sig,
	})
	m.minted[key] = rec
	return cloneRecord(rec), nil
}

func commitmentFromRequest(req MintRequest, now time.Time) (Commitment, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return Commitment{}, fmt.Errorf("%w: tenant id is required", ErrInvalidRecord)
	}
	leaves, err := leavesFromInputs(tenantID, req.Records)
	if err != nil {
		return Commitment{}, err
	}
	root, err := LeafRoot(leaves)
	if err != nil {
		return Commitment{}, err
	}
	auditHead := strings.TrimSpace(req.AuditChainHead)
	if auditHead == "" {
		return Commitment{}, fmt.Errorf("%w: audit chain head after last destruction is required", ErrInvalidRecord)
	}
	inventory, err := inventoryFromRequest(tenantID, req.InventoryLedgerPosition, req.InventoryKeyIDs, req.InventoryDigest, leaves)
	if err != nil {
		return Commitment{}, err
	}
	return normalizeCommitment(Commitment{
		Version:                SchemaV1,
		Domain:                 commitmentDomain,
		TenantID:               tenantID,
		Leaves:                 leaves,
		LeafRoot:               root,
		KeyClassCounts:         keyClassCounts(leaves),
		AuditChainHead:         auditHead,
		Inventory:              inventory,
		Campaign:               cloneCampaign(req.Campaign),
		SanitizationClaims:     normalizeClaims(req.SanitizationClaims),
		GovernanceEvidenceRefs: sortedStrings(req.GovernanceEvidenceRefs),
		MintedAtUnix:           now.Unix(),
	}), nil
}

func leavesFromInputs(tenantID string, inputs []LeafInput) ([]Leaf, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("%w: at least one per-key destruction record is required", ErrInvalidRecord)
	}
	leaves := make([]Leaf, 0, len(inputs))
	seen := map[string]struct{}{}
	for _, in := range inputs {
		rec := in.Record
		if rec.Commitment.TenantID != tenantID {
			return nil, fmt.Errorf("%w: per-key record tenant %q outside aggregate tenant %q", ErrInvalidRecord, rec.Commitment.TenantID, tenantID)
		}
		if rec.Commitment.StableKeyID == "" || rec.Commitment.FinalEpoch == 0 || len(rec.CommitmentDigest) == 0 {
			return nil, fmt.Errorf("%w: incomplete per-key destruction record", ErrInvalidRecord)
		}
		vector, err := record.Vector(rec.Commitment.StableKeyID, rec)
		if err != nil {
			return nil, fmt.Errorf("aggregate decommissioning record: derive per-key vector: %w", err)
		}
		leaf := Leaf{
			TenantID:         tenantID,
			StableKeyID:      rec.Commitment.StableKeyID,
			FinalEpoch:       rec.Commitment.FinalEpoch,
			KeyClass:         strings.TrimSpace(in.KeyClass),
			RecordDigest:     cloneBytes(vector.EncodedRecordDigest),
			CommitmentDigest: cloneBytes(rec.CommitmentDigest),
		}
		if leaf.KeyClass == "" {
			leaf.KeyClass = "unspecified"
		}
		key := leaf.TenantID + "\x00" + leaf.StableKeyID + "\x00" + fmt.Sprint(leaf.FinalEpoch)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: duplicate per-key destruction record %s", ErrInvalidRecord, leaf.StableKeyID)
		}
		seen[key] = struct{}{}
		leaves = append(leaves, leaf)
	}
	return normalizeLeaves(leaves), nil
}

func inventoryFromRequest(tenantID string, pos uint64, keyIDs []string, supplied []byte, leaves []Leaf) (InventoryCompleteness, error) {
	if pos == 0 {
		return InventoryCompleteness{}, fmt.Errorf("%w: inventory ledger position is required", ErrInvalidRecord)
	}
	leafKeys := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		leafKeys = append(leafKeys, leaf.StableKeyID)
	}
	if len(keyIDs) == 0 && len(supplied) == 0 {
		return InventoryCompleteness{}, fmt.Errorf("%w: inventory completeness digest or key set is required", ErrInvalidRecord)
	}
	if len(keyIDs) != 0 {
		if !sameStringSet(keyIDs, leafKeys) {
			return InventoryCompleteness{}, fmt.Errorf("%w: inventory key set is not exhausted by aggregate leaves", ErrInvalidRecord)
		}
		digest, err := InventoryDigest(tenantID, pos, keyIDs)
		if err != nil {
			return InventoryCompleteness{}, err
		}
		if len(supplied) != 0 && !bytes.Equal(supplied, digest) {
			return InventoryCompleteness{}, fmt.Errorf("%w: inventory digest mismatch", ErrInvalidRecord)
		}
		supplied = digest
	}
	return InventoryCompleteness{
		LedgerPosition: pos,
		KeyCount:       len(leaves),
		Digest:         cloneBytes(supplied),
		Exhausted:      true,
	}, nil
}

func InventoryDigest(tenantID string, ledgerPosition uint64, keyIDs []string) ([]byte, error) {
	body := struct {
		Domain         string   `json:"domain"`
		TenantID       string   `json:"tenant_id"`
		LedgerPosition uint64   `json:"ledger_position"`
		KeyIDs         []string `json:"key_ids"`
	}{
		Domain:         "trstctl/vdec/aggregate/inventory-completeness/v1",
		TenantID:       strings.TrimSpace(tenantID),
		LedgerPosition: ledgerPosition,
		KeyIDs:         sortedStrings(keyIDs),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("aggregate decommissioning record: encode inventory digest: %w", err)
	}
	return crypto.SHA256Sum(raw), nil
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
		return nil, fmt.Errorf("aggregate decommissioning record: encode digest domain: %w", err)
	}
	return crypto.SHA256Sum(wrapped), nil
}

func CanonicalCommitmentBytes(c Commitment) ([]byte, error) {
	raw, err := json.Marshal(normalizeCommitment(c))
	if err != nil {
		return nil, fmt.Errorf("aggregate decommissioning record: encode commitment: %w", err)
	}
	return raw, nil
}

func EncodeRecord(rec SignedRecord) ([]byte, error) {
	raw, err := json.Marshal(normalizeRecord(rec))
	if err != nil {
		return nil, fmt.Errorf("aggregate decommissioning record: encode signed record: %w", err)
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
	if rec.Version != SchemaV1 || rec.Type != TypeAggregateRecord {
		return fmt.Errorf("%w: unsupported record type or version", ErrInvalidRecord)
	}
	if trust.Algorithm == "" || len(trust.DER) == 0 {
		return fmt.Errorf("%w: missing verification key", ErrUnverified)
	}
	if rec.AttestationAlgorithm != trust.Algorithm || !bytes.Equal(rec.AttestationPublicKeyDER, trust.DER) {
		return fmt.Errorf("%w: attestation key does not match trust root", ErrUnverified)
	}
	root, err := LeafRoot(rec.Commitment.Leaves)
	if err != nil {
		return err
	}
	if !bytes.Equal(root, rec.Commitment.LeafRoot) {
		return fmt.Errorf("%w: leaf root mismatch", ErrUnverified)
	}
	digest, err := CommitmentDigest(rec.Commitment)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, rec.CommitmentDigest) {
		return fmt.Errorf("%w: commitment digest mismatch", ErrUnverified)
	}
	if err := crypto.VerifyDigest(trust, digest, rec.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("%w: %v", ErrUnverified, err)
	}
	return nil
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
		rec.Type = TypeAggregateRecord
	}
	rec.Commitment = normalizeCommitment(rec.Commitment)
	rec.CommitmentDigest = cloneBytes(rec.CommitmentDigest)
	rec.AttestationPublicKeyDER = cloneBytes(rec.AttestationPublicKeyDER)
	rec.Signature = cloneBytes(rec.Signature)
	return rec
}

func normalizeCommitment(c Commitment) Commitment {
	c.Version = SchemaV1
	c.Domain = commitmentDomain
	c.TenantID = strings.TrimSpace(c.TenantID)
	c.Leaves = normalizeLeaves(c.Leaves)
	c.LeafRoot = cloneBytes(c.LeafRoot)
	c.KeyClassCounts = normalizeCounts(c.KeyClassCounts)
	c.AuditChainHead = strings.TrimSpace(c.AuditChainHead)
	c.Inventory.Digest = cloneBytes(c.Inventory.Digest)
	c.Campaign = cloneCampaign(c.Campaign)
	c.SanitizationClaims = normalizeClaims(c.SanitizationClaims)
	c.GovernanceEvidenceRefs = sortedStrings(c.GovernanceEvidenceRefs)
	return c
}

func normalizeLeaves(in []Leaf) []Leaf {
	out := make([]Leaf, 0, len(in))
	for _, leaf := range in {
		leaf.TenantID = strings.TrimSpace(leaf.TenantID)
		leaf.StableKeyID = strings.TrimSpace(leaf.StableKeyID)
		leaf.KeyClass = strings.TrimSpace(leaf.KeyClass)
		leaf.RecordDigest = cloneBytes(leaf.RecordDigest)
		leaf.CommitmentDigest = cloneBytes(leaf.CommitmentDigest)
		out = append(out, leaf)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		if out[i].StableKeyID != out[j].StableKeyID {
			return out[i].StableKeyID < out[j].StableKeyID
		}
		if out[i].FinalEpoch != out[j].FinalEpoch {
			return out[i].FinalEpoch < out[j].FinalEpoch
		}
		if out[i].KeyClass != out[j].KeyClass {
			return out[i].KeyClass < out[j].KeyClass
		}
		return bytes.Compare(out[i].RecordDigest, out[j].RecordDigest) < 0
	})
	return out
}

func keyClassCounts(leaves []Leaf) []KeyClassCount {
	counts := map[string]int{}
	for _, leaf := range leaves {
		counts[leaf.KeyClass]++
	}
	out := make([]KeyClassCount, 0, len(counts))
	for class, count := range counts {
		out = append(out, KeyClassCount{KeyClass: class, Count: count})
	}
	return normalizeCounts(out)
}

func normalizeCounts(in []KeyClassCount) []KeyClassCount {
	out := append([]KeyClassCount(nil), in...)
	for i := range out {
		out[i].KeyClass = strings.TrimSpace(out[i].KeyClass)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyClass < out[j].KeyClass })
	return out
}

func cloneRecord(in SignedRecord) SignedRecord { return normalizeRecord(in) }

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}

func sortedStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	aa := sortedStrings(a)
	bb := sortedStrings(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func mintKey(tenantID string, ledgerPosition uint64, root []byte) string {
	return strings.TrimSpace(tenantID) + "\x00" + fmt.Sprint(ledgerPosition) + "\x00" + string(root)
}
