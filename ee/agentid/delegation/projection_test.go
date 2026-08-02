// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"encoding/binary"
	"reflect"
	"sort"
	"testing"
	"trstctl.com/trstctl/ee/proptest"

	"trstctl.com/trstctl/internal/eventspec"
)

// dig makes a deterministic 32-byte digest from a label for the pure projection
// tests (no crypto needed — the projection treats digests as opaque keys).
func dig(label string) []byte {
	b := make([]byte, 32)
	copy(b, label)
	return b
}

func mustEncodeSeq(t *testing.T, p Payload, seq uint64) eventspec.Event {
	t.Helper()
	e, err := Encode(p)
	if err != nil {
		t.Fatalf("encode %T: %v", p, err)
	}
	if e.SchemaVersion == 0 {
		e.SchemaVersion = eventspec.DefaultSchemaVersion
	}
	e.Sequence = seq
	return e
}

// TestProjection_DescendantSetPureFunctionOfPrefix is the property that the
// descendant-set projection is a PURE FUNCTION of the event prefix up to the
// watermark: DescendantSetOf(seq, subject, wm) depends only on the events with
// sequence <= wm. Folding the full sequence bounded at wm equals folding just the
// prefix (events with sequence <= wm) unbounded — so events beyond the watermark can
// never influence the answer (INV-A8 "as of" the watermark).
func TestProjection_DescendantSetPureFunctionOfPrefix(t *testing.T) {
	rootDig, leafDig, credEarly, credLate := dig("root"), dig("leaf"), dig("c-early"), dig("c-late")
	full := []eventspec.Event{
		mustEncodeSeq(t, DelegationRecordedV1{RecordDigest: rootDig, RootAnchor: true, DelegatorID: "alice", DelegateID: "bob"}, 1),
		mustEncodeSeq(t, DelegationRecordedV1{RecordDigest: leafDig, ParentDigest: rootDig, DelegatorID: "bob", DelegateID: "carol"}, 2),
		mustEncodeSeq(t, IssuanceRecordedV1{CredentialDigest: credEarly, SubjectID: "carol", ChainDigest: leafDig}, 3),
		// Beyond the watermark: a second credential at seq 7.
		mustEncodeSeq(t, IssuanceRecordedV1{CredentialDigest: credLate, SubjectID: "carol", ChainDigest: leafDig}, 7),
	}
	const wm = 3

	boundedFull, err := DescendantSetOf(full, "alice", wm)
	if err != nil {
		t.Fatalf("bounded full: %v", err)
	}
	// The prefix with sequence <= wm, folded unbounded.
	var prefix []eventspec.Event
	for _, e := range full {
		if e.Sequence <= wm {
			prefix = append(prefix, e)
		}
	}
	prefixOnly, err := DescendantSetOf(prefix, "alice", UnboundedWatermark)
	if err != nil {
		t.Fatalf("prefix only: %v", err)
	}
	if !reflect.DeepEqual(boundedFull, prefixOnly) {
		t.Fatalf("projection is not a pure function of the prefix up to the watermark:\n bounded %#v\n  prefix %#v", boundedFull, prefixOnly)
	}
	if boundedFull.Watermark != wm {
		t.Fatalf("watermark = %d, want %d", boundedFull.Watermark, wm)
	}
	if !reflect.DeepEqual(boundedFull.Credentials, []string{hexKey(credEarly)}) {
		t.Fatalf("as-of watermark %d credentials = %v, want [%s] (the later credential must be excluded)", wm, boundedFull.Credentials, hexKey(credEarly))
	}
}

// TestProjection_IdempotentUnderDuplicateDelivery is the property that folding is
// idempotent under at-least-once (duplicate) delivery: re-delivering the whole
// sequence, plus extra duplicates of individual events, does not change the
// descendant set or the watermark (INV-A8 replay/duplicate-delivery).
func TestProjection_IdempotentUnderDuplicateDelivery(t *testing.T) {
	rootDig, leafDig, credDig := dig("r"), dig("l"), dig("c")
	clean := []eventspec.Event{
		mustEncodeSeq(t, DelegationRecordedV1{RecordDigest: rootDig, RootAnchor: true, DelegatorID: "alice", DelegateID: "bob"}, 1),
		mustEncodeSeq(t, DelegationRecordedV1{RecordDigest: leafDig, ParentDigest: rootDig, DelegatorID: "bob", DelegateID: "carol"}, 2),
		mustEncodeSeq(t, IssuanceRecordedV1{CredentialDigest: credDig, SubjectID: "carol", ChainDigest: leafDig}, 3),
	}
	dup := append([]eventspec.Event{}, clean...)
	dup = append(dup, clean...)                     // whole sequence again
	dup = append(dup, clean[1], clean[2], clean[2]) // extra copies

	for _, subject := range []string{"alice", "bob", "carol", "nobody"} {
		a, err := DescendantSetOf(clean, subject, UnboundedWatermark)
		if err != nil {
			t.Fatalf("clean %s: %v", subject, err)
		}
		b, err := DescendantSetOf(dup, subject, UnboundedWatermark)
		if err != nil {
			t.Fatalf("dup %s: %v", subject, err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("duplicate delivery changed descendants for %q:\n clean %#v\n   dup %#v", subject, a, b)
		}
	}
}

// TestProjection_DescendantSetEqualsReferenceUnderRandomForests is a property test:
// over many random valid delegation forests, the folded descendant set for a subject
// equals an independent reference reduction (a direct reachability check over the
// generated edges). fold(persist(seq)) == reference(seq).
func TestProjection_DescendantSetEqualsReferenceUnderRandomForests(t *testing.T) {
	subjects := []string{"s0", "s1", "s2", "s3"}
	for seed := int64(0); seed < 80; seed++ {
		rng := proptest.New(seed)
		f := randomForest(rng, subjects)

		var events []eventspec.Event
		for _, r := range f.records {
			events = append(events, mustEncodeSeq(t, r.DelegationRecordedV1, r.seq()))
		}
		for _, iss := range f.issuances {
			events = append(events, mustEncodeSeq(t, iss.ev, iss.seq))
		}

		for _, subj := range subjects {
			got, err := DescendantSetOf(events, subj, UnboundedWatermark)
			if err != nil {
				t.Fatalf("seed %d subj %s: %v", seed, subj, err)
			}
			want := f.referenceDescendants(subj)
			if !reflect.DeepEqual(got.Credentials, want) {
				t.Fatalf("seed %d subj %s: fold %v != reference %v", seed, subj, got.Credentials, want)
			}
		}
	}
}

// --- reference model (independent of the projection under test) ---

type recWithSeq struct {
	DelegationRecordedV1
	s uint64
}

func (r recWithSeq) seq() uint64 { return r.s }

type issWithSeq struct {
	ev  IssuanceRecordedV1
	seq uint64
}

type forest struct {
	records   []recWithSeq
	issuances []issWithSeq
	byDigest  map[string]DelegationRecordedV1
}

// randomForest builds a random valid delegation forest: a set of roots, each
// extended by random parent-linked records, and random credentials issued over
// random chain-head records.
func randomForest(rng *proptest.Rand, subjects []string) forest {
	f := forest{byDigest: map[string]DelegationRecordedV1{}}
	var digests [][]byte
	n := 3 + rng.Intn(8)
	for i := 0; i < n; i++ {
		d := seqDigest(i)
		var rec DelegationRecordedV1
		if i == 0 || rng.Intn(3) == 0 {
			rec = DelegationRecordedV1{RecordDigest: d, RootAnchor: true,
				DelegatorID: subjects[rng.Intn(len(subjects))], DelegateID: subjects[rng.Intn(len(subjects))]}
		} else {
			parent := digests[rng.Intn(len(digests))]
			rec = DelegationRecordedV1{RecordDigest: d, ParentDigest: parent,
				DelegatorID: subjects[rng.Intn(len(subjects))], DelegateID: subjects[rng.Intn(len(subjects))]}
		}
		f.records = append(f.records, recWithSeq{rec, uint64(i + 1)})
		f.byDigest[hexKey(d)] = rec
		digests = append(digests, d)
	}
	m := 1 + rng.Intn(6)
	for j := 0; j < m; j++ {
		head := digests[rng.Intn(len(digests))]
		cred := seqDigest(1000 + j)
		f.issuances = append(f.issuances, issWithSeq{
			ev:  IssuanceRecordedV1{CredentialDigest: cred, SubjectID: subjects[rng.Intn(len(subjects))], ChainDigest: head},
			seq: uint64(100 + j),
		})
	}
	return f
}

// referenceDescendants computes, independently of the projection, the sorted set of
// credential ids whose chain (walked head->root over the forest edges) contains subj.
func (f forest) referenceDescendants(subj string) []string {
	var out []string
	for _, iss := range f.issuances {
		if f.chainHasSubject(hexKey(iss.ev.ChainDigest), subj) {
			out = append(out, hexKey(iss.ev.CredentialDigest))
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func (f forest) chainHasSubject(head, subj string) bool {
	cur := head
	seen := map[string]bool{}
	for cur != "" {
		if seen[cur] {
			return false
		}
		seen[cur] = true
		rec, ok := f.byDigest[cur]
		if !ok {
			return false
		}
		if rec.DelegatorID == subj || rec.DelegateID == subj {
			return true
		}
		if rec.RootAnchor || len(rec.ParentDigest) == 0 {
			return false
		}
		cur = hexKey(rec.ParentDigest)
	}
	return false
}

// seqDigest makes a distinct 32-byte digest for an integer so forest nodes have
// unique, comparable ids.
func seqDigest(i int) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b, uint64(i)+1)
	return b
}
