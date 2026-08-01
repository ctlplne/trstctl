// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package reach is the CRYPTO-ONLY half of the AGID pre-issuance reachability bound (patent
// AGID-claims-5/6/25, INV-A5): the SIGNED REACHABILITY VERDICT, the policy CEILINGS a reachable
// set is bounded by, the reachable-set VALUE the verdict binds a digest of, and the pure,
// datastore-free IN-SIGNER VERIFICATION the isolated signer runs as a key-op precondition.
// BEFORE the isolated signer performs a private-key operation, it must verify a signed
// verdict as a precondition; the verdict is produced OUTSIDE the signer by the reachability
// engine (package ee/agentid/reach/engine), which resolves the requested authority of the
// FINAL delegation record against the read-only core credential graph, computes the
// bounded-depth reachable set, and classifies it. The signer trusts the verdict's SIGNATURE
// + WATERMARK, never a live graph query, so graph computation stays out of the custody
// boundary (AGID-claim-6). A reachable set exceeding a policy ceiling yields a refusal, so the
// signer refuses the key op (AGID-claim-5).
//
// AN-4 boundary (the reason for the engine split): this package imports ONLY internal/crypto
// (+ stdlib). The graph-walking engine — which pulls internal/graph + internal/store, and
// transitively database/sql, pgx, NATS, and net/http — lives in the SUBPACKAGE
// ee/agentid/reach/engine, which NOTHING on the signer path imports. The signer-linked
// delegation gate imports THIS package (reach.DecodeVerdict / reach.VerifyVerdict /
// reach.VerifyInput / reach.CeilingExceededError), so the signer's dependency closure stays
// datastore-free (AN-4). The engine references the shared verdict/ceiling/reachable-set
// types defined here qualified (reach.Verdict, reach.Ceiling, reach.ReachableSet, ...), so
// both halves agree on the wire types without the signer linking a datastore.
//
// Boundaries this package holds to:
//   - AN-1: the reachable set / verdict carry the single tenant they were computed for; a
//     verdict for one tenant is refused for another (verify.go). The tenant-scoped graph
//     BUILD (store.WithTenant) lives in the engine subpackage; this package never touches a
//     store.
//   - AN-3: all hashing and signature verification route through internal/crypto; no
//     crypto/* is imported here.
//   - EE fence (§1.6): proprietary Enterprise/Provider material behind ee/; core never
//     imports it, and this package imports nothing that would drag a datastore into the
//     isolated signer's verify path (this package depends only on internal/crypto).
package reach

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// reachPrefix domain-separates every canonical encoding this package hashes (a reachable
// set, a verdict) from every other hashed structure in the repo. It is part of the v1
// canonical semantics.
const reachPrefix = "agid/reach/v1"

// Sensitivity is an ordered asset-sensitivity class derived from graph node labels. The
// order is total (Public < Internal < Confidential < Restricted) so a ceiling can bound
// the MAXIMUM sensitivity a reachable set may contain. Higher is more sensitive. The
// engine (ee/agentid/reach/engine) derives it from graph node labels; it lives here so the
// verdict, the ceiling determination, and the reachable-set digest all share one ordered
// type without the crypto-only signer path importing the graph.
type Sensitivity int

// Sensitivity classes, least to most sensitive. SensitivityUnknown sorts as the least
// sensitive so an unlabeled asset never spuriously trips a sensitivity ceiling; a caller
// that wants to treat unlabeled assets as sensitive sets a low ceiling and labels its
// assets.
const (
	SensitivityUnknown      Sensitivity = iota // no recognized sensitivity label
	SensitivityPublic                          // "public"
	SensitivityInternal                        // "internal"
	SensitivityConfidential                    // "confidential"
	SensitivityRestricted                      // "restricted" / "secret" (most sensitive)
)

// String renders a sensitivity for refusal detail (non-secret, human-meaningful).
func (s Sensitivity) String() string {
	switch s {
	case SensitivityPublic:
		return "public"
	case SensitivityInternal:
		return "internal"
	case SensitivityConfidential:
		return "confidential"
	case SensitivityRestricted:
		return "restricted"
	default:
		return "unknown"
	}
}

// ReachedNode is one node in a reachable set: its stable graph id, kind, a stable label
// set (the asset labels that classify it), and its derived sensitivity. Only NON-SECRET,
// stable fields are retained so the reachable-set digest is reproducible and no secret is
// carried into a verdict.
type ReachedNode struct {
	ID          string      `json:"id"`
	Kind        string      `json:"kind"`
	Labels      []string    `json:"labels,omitempty"` // sorted "key=value" asset labels
	Sensitivity Sensitivity `json:"sensitivity"`
}

// ReachableSet is the resolved consequence of a delegation record's authority: the set of
// graph nodes forward-reachable (within the bounded depth) from the services that accept
// the requested authority, with cardinality, the maximum sensitivity encountered, the
// prohibited labels present, and the tenant span. It is the object the verdict binds a
// DIGEST of (AGID-claim-6); the verdict never carries the set itself into the signer. The engine
// (ee/agentid/reach/engine) populates it from the tenant graph; the crypto-only digest
// lives here so the verdict path never needs the graph.
type ReachableSet struct {
	// TenantID is the single tenant this set was computed for (AN-1: a set never spans
	// tenants; the engine builds one tenant graph under WithTenant).
	TenantID string `json:"tenant_id"`
	// Nodes is the reachable node set in canonical (id-sorted) order.
	Nodes []ReachedNode `json:"nodes"`
	// Cardinality is len(Nodes), materialized so a ceiling can bound it without walking
	// the slice and so it survives in a decoded verdict for diagnostics.
	Cardinality int `json:"cardinality"`
	// MaxSensitivity is the greatest Sensitivity across Nodes (SensitivityUnknown for an
	// empty set).
	MaxSensitivity Sensitivity `json:"max_sensitivity"`
	// TenantSpan is the number of distinct tenants the set touches. Under the AN-1 build
	// discipline this is 1 for a non-empty set and 0 for an empty set; it is modeled
	// explicitly so a tenant-span ceiling is a first-class dimension the verdict binds.
	TenantSpan int `json:"tenant_span"`
	// PresentLabels is the sorted set of DISTINCT asset labels ("key=value") present on
	// reachable nodes, so a prohibited-label ceiling can be evaluated against the verdict
	// alone (the signer never sees the graph).
	PresentLabels []string `json:"present_labels,omitempty"`
}

// Digest returns the canonical, byte-stable SHA-256 of the reachable set, routed through
// internal/crypto (AN-3). It is the value the verdict binds (AGID-claim-6) and is deterministic
// for a fixed graph watermark (acceptance criterion 3): the encoding is length-prefixed,
// fixed-endian, and iterates canonically-ordered node/label sets, so the same set yields
// identical bytes across runs, machines, and architectures. It carries NO secret (only
// stable ids, kinds, labels, and the derived sensitivity).
func (rs ReachableSet) Digest() []byte {
	return crypto.SHA256Sum(rs.canonicalBytes())
}

// canonicalBytes is the deterministic serialization of the reachable set the digest is
// taken over. It mirrors the length-prefixed, sorted-set discipline of
// taskenv/envelope.go and delegation/record.go so the digest is reproducible.
func (rs ReachableSet) canonicalBytes() []byte {
	var b []byte
	b = appendStr(b, reachPrefix)
	b = appendStr(b, "reachable-set")
	b = appendStr(b, rs.TenantID)
	b = appendU64(b, uint64(rs.Cardinality))
	b = appendU64(b, uint64(rs.MaxSensitivity))
	b = appendU64(b, uint64(rs.TenantSpan))
	// nodes, sorted by id so the digest is a pure function of the set's CONTENT, not the
	// slice order it happens to be built in (defensive: Resolve already id-sorts, but a
	// caller assembling a set by hand still gets an order-independent digest).
	nodes := append([]ReachedNode(nil), rs.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	b = appendU64(b, uint64(len(nodes)))
	for _, n := range nodes {
		b = appendStr(b, n.ID)
		b = appendStr(b, n.Kind)
		b = appendU64(b, uint64(n.Sensitivity))
		labels := append([]string(nil), n.Labels...)
		sort.Strings(labels)
		b = appendU64(b, uint64(len(labels)))
		for _, l := range labels {
			b = appendStr(b, l)
		}
	}
	// present labels (sorted union), bound so a decoded verdict's prohibited-label
	// determination is over the same committed bytes.
	pl := append([]string(nil), rs.PresentLabels...)
	sort.Strings(pl)
	b = appendU64(b, uint64(len(pl)))
	for _, l := range pl {
		b = appendStr(b, l)
	}
	return b
}

// DistinctLabels returns the sorted union of the label sets across nodes. It is exported so
// the engine subpackage can compute a reachable set's PresentLabels through the same
// canonical helper the digest relies on, keeping the label discipline in one place.
func DistinctLabels(nodes []ReachedNode) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range nodes {
		for _, l := range n.Labels {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---- canonical writer helpers (length-prefixed, fixed big-endian; mirrors taskenv /
// delegation so the encodings share their discipline). ----

func appendStr(b []byte, s string) []byte {
	b = appendU64(b, uint64(len(s)))
	return append(b, s...)
}

func appendU64(b []byte, v uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return append(b, x[:]...)
}

// normLabel normalizes a label/sensitivity value: trim surrounding whitespace and
// lowercase, matching the scope/tool normalization discipline elsewhere so labels compare
// by meaning, not spelling.
func normLabel(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// sha256Of routes a byte slice through the internal/crypto SHA-256 boundary (AN-3). It is
// the single hashing helper the non-verdict files in this package use so no file here
// imports crypto/sha256 directly; ceiling.go's offending-subset digests and any other
// intra-package hashing go through it.
func sha256Of(b []byte) []byte { return crypto.SHA256Sum(b) }

// verdict.go defines the SIGNED REACHABILITY VERDICT (AGID-claim-6 / INV-A5): the artifact the
// reachability engine emits OUTSIDE the signer and the signer verifies as a key-op
// precondition. The verdict binds three things and nothing that requires a graph to check:
//
//  1. ReachableDigest — the canonical digest of the reachable set the engine computed
//     (AGID-claim-6). The signer never sees the set, only this digest.
//  2. Determination   — the ceiling determination (Exceeded + named violations with
//     offending-subset digests, AGID-claim-5). The signer HONORS this determination: an
//     Exceeded determination means no key op.
//  3. Watermark        — the graph freshness watermark the reachable set was computed at
//     (AGID-claim-6). The signer checks the watermark is acceptable (present and not stale);
//     verification is invariant to graph changes AFTER the watermark, because the signer
//     trusts the SIGNED digest, not a live query (acceptance criterion 3).
//
// The verdict is signed with the ENGINE's verdict-signing key (an out-of-signer key the
// signer trusts via a held verifier public key), through internal/crypto (AN-3). The
// verdict holds NO issuance key and mints nothing (INV-A1 preserved by construction): Sign
// attests only the verdict's own contents.
//
// Canonical bytes for signing are length-prefixed and fixed-endian (mirroring
// taskenv/delegation), so a signed verdict verifies deterministically across runs and
// machines, and ANY tamper to a bound field invalidates the signature.

// verdictPrefix domain-separates the verdict's canonical signing bytes from every other
// hashed/signed structure (a reachable set, an envelope, a record). Part of v1 semantics.
const verdictPrefix = "agid/reach/verdict/v1"

// VerdictKeyRef references the engine's verdict-signing key without carrying private (or
// public) key material (AN-8). ID is the opaque key id the signer resolves to a trusted
// public key via its held verifier; Algorithm names the signature algorithm.
type VerdictKeyRef struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
}

// Verdict is the signed reachability verdict (AGID-claim-6). It is produced outside the signer
// and verified inside it. Fields are ordered so the canonical bytes are stable.
type Verdict struct {
	// TenantID is the tenant the reachable set was computed for (AN-1). Bound so a verdict
	// for one tenant cannot be replayed for another.
	TenantID string `json:"tenant_id"`
	// SubjectDigest binds the verdict to the specific issuance request it authorizes: the
	// digest of the final delegation record / authority the reachable set was computed
	// FROM. The signer requires the verdict's SubjectDigest to equal the digest of the
	// request's final-record authority (verify.go), so a verdict computed for one
	// authority cannot be presented for a different, broader one.
	SubjectDigest []byte `json:"subject_digest"`
	// ReachableDigest is the canonical digest of the reachable set (AGID-claim-6).
	ReachableDigest []byte `json:"reachable_digest"`
	// Cardinality, MaxSensitivity, TenantSpan mirror the reachable set's summary so a
	// human reading a decoded verdict (or an audit) sees the shape without the set; they
	// are bound into the canonical bytes so they cannot be altered independently of the
	// digest.
	Cardinality    int         `json:"cardinality"`
	MaxSensitivity Sensitivity `json:"max_sensitivity"`
	TenantSpan     int         `json:"tenant_span"`
	// Determination is the ceiling determination (AGID-claim-5). Bound so the signer honors the
	// SIGNED determination.
	Determination Determination `json:"determination"`
	// Watermark is the graph freshness watermark (AGID-claim-6).
	Watermark string `json:"watermark"`
	// IssuedAt is the Unix second the verdict was produced (non-secret), bound for audit
	// and available for a freshness-by-age policy in the signer.
	IssuedAt int64 `json:"issued_at"`
	// Key references the verdict-signing key. Bound so a verdict cannot be re-attributed to
	// a different key id.
	Key VerdictKeyRef `json:"key"`
	// Signature is the engine's signature over CanonicalBytes (all fields above). Excluded
	// from the canonical bytes (the signature is OVER them). A missing signature fails
	// closed in the signer.
	Signature []byte `json:"signature,omitempty"`
}

// Verdict errors.
var (
	// ErrVerdictSignature is returned when a verdict's signature is missing or does not
	// verify against the supplied verdict-signer public key.
	ErrVerdictSignature = errors.New("reach: verdict signature missing or invalid")
	// ErrVerdictDecode is returned when an opaque verdict body cannot be decoded.
	ErrVerdictDecode = errors.New("reach: cannot decode reachability verdict body")
)

// CanonicalBytes returns the deterministic serialization of every verdict field EXCEPT
// the signature (the signature is over these bytes). It is length-prefixed and fixed
// big-endian, iterating the determination's violations in their (already deterministic)
// order, so the encoding is reproducible across runs, machines, and architectures and any
// tamper flips it.
func (v Verdict) CanonicalBytes() []byte {
	var b []byte
	b = appendStr(b, verdictPrefix)
	b = appendStr(b, v.TenantID)
	b = appendBytes(b, v.SubjectDigest)
	b = appendBytes(b, v.ReachableDigest)
	b = appendU64(b, uint64(v.Cardinality))
	b = appendU64(b, uint64(v.MaxSensitivity))
	b = appendU64(b, uint64(v.TenantSpan))
	// determination
	b = appendStr(b, "determination")
	b = appendStr(b, v.Determination.RequesterClass)
	b = appendBool(b, v.Determination.Exceeded)
	b = appendU64(b, uint64(len(v.Determination.Violations)))
	for _, vi := range v.Determination.Violations {
		b = appendStr(b, string(vi.Ceiling))
		b = appendStr(b, vi.Reason)
		b = appendBytes(b, vi.OffendingDigest)
	}
	b = appendStr(b, v.Watermark)
	b = appendU64(b, uint64(v.IssuedAt))
	b = appendStr(b, v.Key.ID)
	b = appendStr(b, v.Key.Algorithm)
	return b
}

// Digest is the SHA-256 of the verdict's canonical bytes (signature excluded), through the
// internal/crypto boundary (AN-3). Useful for audit references to a specific verdict.
func (v Verdict) Digest() []byte { return crypto.SHA256Sum(v.CanonicalBytes()) }

// Sign returns a copy of v signed over its canonical bytes with the engine's
// verdict-signing key, through internal/crypto (AN-3). It performs no issuance key
// operation and mints nothing — it attests only the verdict's own contents (INV-A1
// preserved). The signer later verifies this signature as a key-op precondition.
func (v Verdict) Sign(signer crypto.Signer) (Verdict, error) {
	sig, err := signer.Sign(v.CanonicalBytes(), crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return Verdict{}, err
	}
	v.Signature = sig
	return v, nil
}

// VerifySignature checks the verdict's signature over its canonical bytes against pub (the
// verdict-signer public key held by the signer), through the internal/crypto verify
// boundary (AN-3). Any tamper to a bound field invalidates it; a missing signature fails
// closed. It performs no key operation of its own beyond signature checking.
func (v Verdict) VerifySignature(pub crypto.PublicKey) error {
	if len(v.Signature) == 0 {
		return ErrVerdictSignature
	}
	if err := crypto.VerifyMessage(pub.DER, v.CanonicalBytes(), v.Signature); err != nil {
		return ErrVerdictSignature
	}
	return nil
}

// EncodeVerdict serializes a verdict for carriage over the delegation seam (opaque bytes
// the gate decodes fail-closed), as JSON, matching the rest of the seam carriage.
func EncodeVerdict(v Verdict) ([]byte, error) { return json.Marshal(v) }

// DecodeVerdict deserializes a verdict from opaque bytes, fail-closed.
func DecodeVerdict(b []byte) (Verdict, error) {
	if len(b) == 0 {
		return Verdict{}, ErrVerdictDecode
	}
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		return Verdict{}, ErrVerdictDecode
	}
	return v, nil
}

// NewVerdict assembles an UNSIGNED verdict from a resolved reachable set, its ceiling
// determination, the graph watermark, the subject digest (the final-record authority
// digest the verdict is bound to), the issued-at time, and the signing key reference. The
// caller then Sign()s it. It binds the reachable-set digest (AGID-claim-6) and the summary
// fields so the verdict is self-describing and tamper-evident.
func NewVerdict(set ReachableSet, det Determination, watermark string, subjectDigest []byte, issuedAt int64, key VerdictKeyRef) Verdict {
	return Verdict{
		TenantID:        set.TenantID,
		SubjectDigest:   append([]byte(nil), subjectDigest...),
		ReachableDigest: set.Digest(),
		Cardinality:     set.Cardinality,
		MaxSensitivity:  set.MaxSensitivity,
		TenantSpan:      set.TenantSpan,
		Determination:   det,
		Watermark:       watermark,
		IssuedAt:        issuedAt,
		Key:             key,
	}
}

// DetermineOrFailClosed evaluates a resolved reachable set against the requester class's
// ceiling, or — when the class has NO configured ceiling — returns a fail-closed Exceeded
// determination (AGID-claim-5). It is the ceiling half of the OUTSIDE-signer path, exported so
// the reachability engine (ee/agentid/reach/engine) produces its verdict's determination
// through the exact same crypto-only logic the signer's verify path re-checks, WITHOUT the
// engine's graph/store dependencies leaking into this package. It performs NO key op and no
// I/O. See determineOrFailClosed for the semantics.
func DetermineOrFailClosed(set ReachableSet, class string, policy *CeilingPolicy) Determination {
	return determineOrFailClosed(set, class, policy)
}

// determineOrFailClosed evaluates the reachable set against the class's ceiling, or — when
// the class has NO configured ceiling — returns a fail-closed Exceeded determination. This
// is the OUTSIDE-signer half of the fail-closed policy: an un-enumerated requester class
// does not get an unbounded reach; its verdict carries an Exceeded determination the signer
// refuses on. (The signer independently fails closed on an absent/unsigned/stale verdict —
// verify.go — so the bound is fail-closed on both sides.)
func determineOrFailClosed(set ReachableSet, class string, policy *CeilingPolicy) Determination {
	c, ok := policy.Ceiling(class)
	if !ok {
		return Determination{
			RequesterClass: class,
			Exceeded:       true,
			Violations: []Violation{{
				Ceiling:         CeilingCardinality,
				Reason:          "no reachability ceiling configured for requester class " + safeClass(class) + " (fail-closed)",
				OffendingDigest: set.Digest(),
			}},
		}
	}
	return Evaluate(set, class, c)
}

// safeClass renders a class name for a reason string, substituting a placeholder for an
// empty class so the message is meaningful.
func safeClass(class string) string {
	if class == "" {
		return "(unspecified)"
	}
	return class
}

// appendBytes writes a length-prefixed byte slice.
func appendBytes(b []byte, p []byte) []byte {
	b = appendU64(b, uint64(len(p)))
	return append(b, p...)
}

// appendBool writes a single byte (0/1).
func appendBool(b []byte, v bool) []byte {
	if v {
		return append(b, 1)
	}
	return append(b, 0)
}
