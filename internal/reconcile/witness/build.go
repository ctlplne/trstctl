// SPDX-License-Identifier: BUSL-1.1

package witness

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/digest"
)

var ErrInvalidWitness = errors.New("witness: invalid witness")

type planeIndex struct {
	state   PlaneState
	records map[string]canon.CanonicalRecord
	leaves  map[string]digest.Leaf
}

// Build produces the minimal divergence witness: only diverging canonical
// records are disclosed, and the absence proofs redact the bracketing
// non-diverging record bodies (XREC-claim-9).
func Build(req BuildRequest) (Body, error) {
	if err := validateRequest(req); err != nil {
		return Body{}, err
	}
	left, err := indexPlane(req.Left)
	if err != nil {
		return Body{}, err
	}
	right, err := indexPlane(req.Right)
	if err != nil {
		return Body{}, err
	}
	entries, err := diffEntries(left, right)
	if err != nil {
		return Body{}, err
	}
	for _, pv := range req.PolicyViolations {
		entry, err := policyEntry(pv, left, right)
		if err != nil {
			return Body{}, err
		}
		entries = append(entries, entry)
	}
	for _, stale := range req.Staleness {
		entry, err := stalenessEntry(stale)
		if err != nil {
			return Body{}, err
		}
		entries = append(entries, entry)
	}
	sortEntries(entries)
	body := Body{
		RoundID:     strings.TrimSpace(req.RoundID),
		TenantID:    strings.TrimSpace(req.TenantID),
		SpecVersion: strings.TrimSpace(req.SpecVersion),
		DigestRefs:  []DigestRef{digestRef(req.Left), digestRef(req.Right)},
		Entries:     entries,
		GeneratedAt: req.GeneratedAt,
	}
	body.WitnessID = hex.EncodeToString(body.WitnessHash())
	return body, nil
}

func (b Body) ContentBytes() ([]byte, error) {
	content := struct {
		RoundID     string      `json:"round_id"`
		TenantID    string      `json:"tenant_id"`
		SpecVersion string      `json:"spec_version"`
		DigestRefs  []DigestRef `json:"digest_refs"`
		Entries     []Entry     `json:"entries"`
		GeneratedAt int64       `json:"generated_at"`
	}{
		RoundID:     b.RoundID,
		TenantID:    b.TenantID,
		SpecVersion: b.SpecVersion,
		DigestRefs:  b.DigestRefs,
		Entries:     b.Entries,
		GeneratedAt: b.GeneratedAt,
	}
	return json.Marshal(content)
}

func (b Body) WitnessHash() []byte {
	content, err := b.ContentBytes()
	if err != nil {
		return nil
	}
	return crypto.SHA256Sum(content)
}

func (b Body) VerifyWitnessID() bool {
	if b.WitnessID == "" {
		return false
	}
	return b.WitnessID == hex.EncodeToString(b.WitnessHash())
}

func (b Body) CanonicalBytes() ([]byte, error) {
	if !b.VerifyWitnessID() {
		return nil, ErrInvalidWitness
	}
	return json.Marshal(b)
}

func validateRequest(req BuildRequest) error {
	if strings.TrimSpace(req.RoundID) == "" || strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.SpecVersion) == "" || req.GeneratedAt == 0 {
		return ErrInvalidWitness
	}
	if req.Left.AuthorityID == "" || req.Right.AuthorityID == "" || req.Left.AuthorityID == req.Right.AuthorityID {
		return ErrInvalidWitness
	}
	if req.Left.Set.TenantID != req.TenantID || req.Right.Set.TenantID != req.TenantID {
		return ErrInvalidWitness
	}
	if req.Left.Set.SpecVersion != req.SpecVersion || req.Right.Set.SpecVersion != req.SpecVersion {
		return ErrInvalidWitness
	}
	if req.Left.Tree == nil || req.Right.Tree == nil {
		return ErrInvalidWitness
	}
	return nil
}

func indexPlane(state PlaneState) (planeIndex, error) {
	idx := planeIndex{state: state, records: map[string]canon.CanonicalRecord{}, leaves: map[string]digest.Leaf{}}
	for _, rec := range state.Set.Records {
		key, err := digest.RecordKeyBytes(rec.RecordKey)
		if err != nil {
			return planeIndex{}, err
		}
		idx.records[string(key)] = rec
	}
	for _, leaf := range state.Tree.Leaves {
		idx.leaves[string(leaf.RecordKeyBytes)] = leaf
	}
	return idx, nil
}

func diffEntries(left, right planeIndex) ([]Entry, error) {
	keys := unionKeys(left.records, right.records)
	entries := make([]Entry, 0)
	for _, key := range keys {
		lrec, lok := left.records[string(key)]
		rrec, rok := right.records[string(key)]
		switch {
		case lok && !rok:
			entry, err := presenceEntry(left, right, key, lrec)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		case !lok && rok:
			entry, err := presenceEntry(right, left, key, rrec)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		case lok && rok:
			lb, err := materialBytes(lrec)
			if err != nil {
				return nil, err
			}
			rb, err := materialBytes(rrec)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(lb, rb) {
				entry, err := attributeEntry(left, right, key, lrec, rrec)
				if err != nil {
					return nil, err
				}
				entries = append(entries, entry)
			}
		}
	}
	return entries, nil
}

func materialBytes(rec canon.CanonicalRecord) ([]byte, error) {
	rec.Provenance = canon.Provenance{}
	return rec.CanonicalBytes()
}

func presenceEntry(containing, absent planeIndex, key []byte, rec canon.CanonicalRecord) (Entry, error) {
	inc, ok := containing.state.Tree.InclusionProof(key)
	if !ok {
		return Entry{}, fmt.Errorf("%w: missing inclusion proof", ErrInvalidWitness)
	}
	abs, ok := absent.state.Tree.AbsenceProof(key)
	if !ok {
		return Entry{}, fmt.Errorf("%w: missing absence proof", ErrInvalidWitness)
	}
	recBytes, err := rec.CanonicalBytes()
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		RecordKey:        rec.RecordKey,
		Class:            ClassPresence,
		PresentAuthority: containing.state.AuthorityID,
		Inclusions: []InclusionProofRef{{
			AuthorityID: containing.state.AuthorityID,
			Proof:       inclusionFromDigest(inc),
		}},
		Absence: absenceFromDigest(abs),
		DisclosedRecords: []DisclosedRecord{{
			AuthorityID:          containing.state.AuthorityID,
			RecordKey:            rec.RecordKey,
			CanonicalRecordBytes: recBytes,
		}},
	}, nil
}

func attributeEntry(left, right planeIndex, key []byte, lrec, rrec canon.CanonicalRecord) (Entry, error) {
	linc, ok := left.state.Tree.InclusionProof(key)
	if !ok {
		return Entry{}, fmt.Errorf("%w: missing left inclusion", ErrInvalidWitness)
	}
	rinc, ok := right.state.Tree.InclusionProof(key)
	if !ok {
		return Entry{}, fmt.Errorf("%w: missing right inclusion", ErrInvalidWitness)
	}
	lb, err := lrec.CanonicalBytes()
	if err != nil {
		return Entry{}, err
	}
	rb, err := rrec.CanonicalBytes()
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		RecordKey: lrec.RecordKey,
		Class:     ClassAttributeConflict,
		Inclusions: []InclusionProofRef{
			{AuthorityID: left.state.AuthorityID, Proof: inclusionFromDigest(linc)},
			{AuthorityID: right.state.AuthorityID, Proof: inclusionFromDigest(rinc)},
		},
		DisclosedRecords: []DisclosedRecord{
			{AuthorityID: left.state.AuthorityID, RecordKey: lrec.RecordKey, CanonicalRecordBytes: lb},
			{AuthorityID: right.state.AuthorityID, RecordKey: rrec.RecordKey, CanonicalRecordBytes: rb},
		},
	}, nil
}

func policyEntry(pv PolicyViolation, left, right planeIndex) (Entry, error) {
	plane, ok := planeByAuthority(pv.AuthorityID, left, right)
	if !ok {
		return Entry{}, ErrInvalidWitness
	}
	key, err := digest.RecordKeyBytes(pv.RecordKey)
	if err != nil {
		return Entry{}, err
	}
	rec, ok := plane.records[string(key)]
	if !ok {
		return Entry{}, fmt.Errorf("%w: policy record absent", ErrInvalidWitness)
	}
	inc, ok := plane.state.Tree.InclusionProof(key)
	if !ok {
		return Entry{}, fmt.Errorf("%w: policy inclusion absent", ErrInvalidWitness)
	}
	recBytes, err := rec.CanonicalBytes()
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		RecordKey: rec.RecordKey,
		Class:     ClassPolicyViolation,
		Inclusions: []InclusionProofRef{{
			AuthorityID: plane.state.AuthorityID,
			Proof:       inclusionFromDigest(inc),
		}},
		DisclosedRecords: []DisclosedRecord{{
			AuthorityID:          plane.state.AuthorityID,
			RecordKey:            rec.RecordKey,
			CanonicalRecordBytes: recBytes,
		}},
		Policy: &PolicyEvidence{
			AuthorityID:   plane.state.AuthorityID,
			RuleID:        strings.TrimSpace(pv.RuleID),
			PolicySetHash: append([]byte(nil), pv.PolicySetHash...),
			RecordKey:     rec.RecordKey,
		},
	}, nil
}

func stalenessEntry(stale Staleness) (Entry, error) {
	if strings.TrimSpace(stale.AuthorityID) == "" || strings.TrimSpace(stale.Reason) == "" || strings.TrimSpace(stale.Watermark.Position) == "" {
		return Entry{}, ErrInvalidWitness
	}
	return Entry{
		Class: ClassStaleness,
		Staleness: &StalenessEvidence{
			AuthorityID: strings.TrimSpace(stale.AuthorityID),
			Reason:      strings.TrimSpace(stale.Reason),
			Watermark:   stale.Watermark,
			LivenessSec: stale.LivenessSec,
		},
	}, nil
}

func digestRef(state PlaneState) DigestRef {
	return DigestRef{
		AuthorityID:  state.AuthorityID,
		DigestHash:   append([]byte(nil), state.Digest.DigestHash...),
		KeyID:        state.Digest.KeyID,
		Algorithm:    state.Digest.Algorithm,
		PublicKeyDER: append([]byte(nil), state.Digest.PublicKeyDER...),
		Signature:    append([]byte(nil), state.Digest.Signature...),
		Watermark:    state.Digest.Body.Watermark,
	}
}

func unionKeys(left, right map[string]canon.CanonicalRecord) [][]byte {
	seen := map[string]struct{}{}
	for key := range left {
		seen[key] = struct{}{}
	}
	for key := range right {
		seen[key] = struct{}{}
	}
	out := make([][]byte, 0, len(seen))
	for key := range seen {
		out = append(out, []byte(key))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

func planeByAuthority(authorityID string, left, right planeIndex) (planeIndex, bool) {
	switch strings.TrimSpace(authorityID) {
	case left.state.AuthorityID:
		return left, true
	case right.state.AuthorityID:
		return right, true
	default:
		return planeIndex{}, false
	}
}

func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		ki := entrySortKey(entries[i])
		kj := entrySortKey(entries[j])
		return ki < kj
	})
}

func entrySortKey(e Entry) string {
	return e.Class + "\x00" + e.RecordKey.TenantID + "\x00" + e.RecordKey.RecordType + "\x00" + e.RecordKey.StableID
}
