// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"encoding/hex"
	"sort"

	"trstctl.com/trstctl/internal/eventspec"
)

// This file holds the delegation-tree read projections folded from the AN-2
// delegation-lifecycle events (events.go): the "descendant credential set for a
// subject" together with the determining WATERMARK (§7.1, AGID-claim-16 / INV-A8). The
// projection is the source of truth AGID-10 reads to determine the cascade. It is a
// PURE FUNCTION of the event prefix up to the watermark: DescendantSetOf(seq,
// subject, wm) depends only on the events with sequence <= wm, and is deterministic
// under replay AND duplicate delivery (idempotent). It performs no I/O and no key
// operation; the durable RLS serving copy is the store package.
//
// Digest conventions on the events (events.go): DelegationRecordedV1 carries the
// record's own digest (RecordDigest) and its parent-hash edge (ParentDigest), so the
// record forest is reconstructed edge-by-edge. IssuanceRecordedV1 carries the
// credential digest (CredentialDigest, the credential's stable id for projection
// purposes) and ChainDigest — the leaf/chain-head record digest that anchors the
// credential to the record it was issued over. The descendant walk starts at that
// chain-head record and follows ParentDigest to the root, exactly as the store's
// FetchChain walk does, so the projection and the durable read agree.

// EdgeSet is the delegation forest folded from the ledger: a map from a record
// digest to that record's parent-hash edge and parties, plus the credential->chain
// head bindings from issuances, plus the determining watermark. Duplicate
// DelegationRecorded / IssuanceRecorded events for the same digest collapse (upsert
// on identical content), so the fold is idempotent under duplicate delivery.
type EdgeSet struct {
	records     map[string]edge   // record digest (hex) -> folded record edge
	chainHead   map[string]string // credential digest (hex) -> chain-head record digest (hex)
	credSubject map[string]string // credential digest (hex) -> subject it was issued for
	watermark   uint64            // highest event sequence folded into this set
}

// edge is one folded delegation record: its parent digest (empty iff root), whether
// it is a root anchor, and the two parties. Only the fields the descendant fold
// needs are retained. Digests are hex-encoded map keys.
type edge struct {
	parent     string // hex of parent record digest; "" iff rootAnchor
	rootAnchor bool
	delegator  string
	delegate   string
}

// UnboundedWatermark folds the entire supplied prefix regardless of Sequence. Use it
// when the caller has already sliced the event prefix (or when events are
// unsequenced, as with MemSink in tests) and wants every supplied event folded.
const UnboundedWatermark = ^uint64(0)

// FoldEdges folds the event prefix with sequence <= watermark into an EdgeSet. Only
// DelegationRecorded and IssuanceRecorded events contribute; every other type
// (RevocationDirective, Refusal, and any Unknown/forward event) is skipped with no
// effect, so replay is forward-compatible. FoldEdges is a pure function of (seq,
// watermark): the same prefix yields an identical EdgeSet, and re-delivering any
// event does not change the result (map upserts are idempotent on identical
// content). A malformed payload of a known type is a corruption error and fails the
// fold closed rather than being silently dropped.
func FoldEdges(seq []eventspec.Event, watermark uint64) (EdgeSet, error) {
	es := EdgeSet{
		records:     make(map[string]edge),
		chainHead:   make(map[string]string),
		credSubject: make(map[string]string),
	}
	for i := range seq {
		e := seq[i]
		if !withinWatermark(e.Sequence, watermark) {
			continue
		}
		if e.Sequence > es.watermark {
			es.watermark = e.Sequence
		}
		pl, err := Decode(e)
		if err != nil {
			return EdgeSet{}, err
		}
		switch v := pl.(type) {
		case DelegationRecordedV1:
			if len(v.RecordDigest) == 0 {
				continue
			}
			es.records[hexKey(v.RecordDigest)] = edge{
				parent:     hexKey(v.ParentDigest),
				rootAnchor: v.RootAnchor,
				delegator:  v.DelegatorID,
				delegate:   v.DelegateID,
			}
		case IssuanceRecordedV1:
			cred := v.CredentialID
			if cred == "" {
				cred = hexKey(v.CredentialDigest)
			}
			if cred == "" {
				continue
			}
			es.chainHead[cred] = hexKey(v.ChainDigest)
			es.credSubject[cred] = v.SubjectID
		default:
			// RevocationDirectiveV1, RefusalRecordedV1, an issuance/record event
			// missing its digest, and Unknown carry no edge/issuance effect.
		}
	}
	return es, nil
}

// Watermark returns the highest event sequence folded into the set — the
// "determining watermark" a revocation directive records (INV-A8). A fold over an
// unsequenced prefix (all Sequence == 0) returns 0.
func (es EdgeSet) Watermark() uint64 { return es.watermark }

// withinWatermark reports whether an event at seq is within the folded prefix.
// UnboundedWatermark includes everything; otherwise an event is included iff its
// sequence is <= watermark. Unsequenced events (Sequence == 0) are included only
// under UnboundedWatermark, so a bounded fold over sequenced events is exact.
func withinWatermark(seq, watermark uint64) bool {
	if watermark == UnboundedWatermark {
		return true
	}
	if seq == 0 {
		return false
	}
	return seq <= watermark
}

// DescendantSet is the descendant-credential set for a subject as of a watermark
// (AGID-claim-16 / INV-A8): every issued credential whose delegation chain includes the
// subject (as delegator or delegate on any record of the chain), determined over the
// event prefix with sequence <= watermark. Credentials is SORTED and de-duplicated
// so the set is a deterministic value. Watermark is the determining watermark of the
// fold. The result is a pure function of (seq, subjectID, watermark) and is
// identical under replay and duplicate delivery.
type DescendantSet struct {
	Subject     string
	Watermark   uint64
	Credentials []string // sorted, unique credential ids (hex of the credential digest)
}

// DescendantSetFromEdges folds an EdgeSet into the descendant set for subjectID. A
// credential is included iff the subject appears as delegator or delegate on some
// record of the credential's chain, walking parent-hash edges from the chain head to
// the root. A broken chain (missing edge) stops that credential's walk without
// panicking. The walk is the in-memory twin of the store's descendant walk, so the
// projection and the durable read agree.
func DescendantSetFromEdges(es EdgeSet, subjectID string) DescendantSet {
	creds := make([]string, 0)
	for cred, head := range es.chainHead {
		if es.chainContains(head, subjectID) {
			creds = append(creds, cred)
		}
	}
	sort.Strings(creds)
	return DescendantSet{Subject: subjectID, Watermark: es.watermark, Credentials: creds}
}

// DescendantSetOf is the one-call form: fold the event prefix up to watermark, then
// derive the descendant set for subjectID. It is the projection the cascade reads
// (§7.1). Pure and idempotent: identical (seq, subjectID, watermark) always yields an
// identical DescendantSet, and duplicate delivery of any event does not change it.
func DescendantSetOf(seq []eventspec.Event, subjectID string, watermark uint64) (DescendantSet, error) {
	es, err := FoldEdges(seq, watermark)
	if err != nil {
		return DescendantSet{}, err
	}
	return DescendantSetFromEdges(es, subjectID), nil
}

// chainContains reports whether subjectID appears as delegator or delegate on any
// record of the chain rooted at head, walking parent-hash edges through the folded
// records. Cycles are bounded by the visited set; a missing edge stops the walk.
func (es EdgeSet) chainContains(head, subjectID string) bool {
	cur := head
	seen := make(map[string]struct{})
	for cur != "" {
		if _, dup := seen[cur]; dup {
			return false
		}
		seen[cur] = struct{}{}
		rec, ok := es.records[cur]
		if !ok {
			return false
		}
		if rec.delegator == subjectID || rec.delegate == subjectID {
			return true
		}
		if rec.rootAnchor || rec.parent == "" {
			return false
		}
		cur = rec.parent
	}
	return false
}

// hexKey renders a digest as a lower-case hex string for use as a stable, comparable
// map key and set element. An empty digest maps to "" (the "no edge" / "no head"
// sentinel the walk stops on).
func hexKey(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}
