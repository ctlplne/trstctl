// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reach

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// verdict.go defines the SIGNED REACHABILITY VERDICT (claim 6 / INV-A5): the artifact the
// reachability engine emits OUTSIDE the signer and the signer verifies as a key-op
// precondition. The verdict binds three things and nothing that requires a graph to check:
//
//  1. ReachableDigest — the canonical digest of the reachable set the engine computed
//     (claim 6). The signer never sees the set, only this digest.
//  2. Determination   — the ceiling determination (Exceeded + named violations with
//     offending-subset digests, claim 5). The signer HONORS this determination: an
//     Exceeded determination means no key op.
//  3. Watermark        — the graph freshness watermark the reachable set was computed at
//     (claim 6). The signer checks the watermark is acceptable (present and not stale);
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

// Verdict is the signed reachability verdict (claim 6). It is produced outside the signer
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
	// ReachableDigest is the canonical digest of the reachable set (claim 6).
	ReachableDigest []byte `json:"reachable_digest"`
	// Cardinality, MaxSensitivity, TenantSpan mirror the reachable set's summary so a
	// human reading a decoded verdict (or an audit) sees the shape without the set; they
	// are bound into the canonical bytes so they cannot be altered independently of the
	// digest.
	Cardinality    int         `json:"cardinality"`
	MaxSensitivity Sensitivity `json:"max_sensitivity"`
	TenantSpan     int         `json:"tenant_span"`
	// Determination is the ceiling determination (claim 5). Bound so the signer honors the
	// SIGNED determination.
	Determination Determination `json:"determination"`
	// Watermark is the graph freshness watermark (claim 6).
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
// caller then Sign()s it. It binds the reachable-set digest (claim 6) and the summary
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

// ProduceVerdict is the engine's end-to-end OUTSIDE-the-signer path (claims 5/6): resolve
// the reachable set for a request, evaluate it against the requester class's ceiling, and
// return a SIGNED verdict binding the reachable-set digest, the ceiling determination, and
// the graph watermark. class selects the ceiling; a class with no configured ceiling is a
// fail-closed refusal determination (Exceeded with a named cardinality violation carrying
// the whole-set digest), so a verdict is ALWAYS produced (the signer then refuses on the
// Exceeded determination) rather than silently allowing an unbounded reach.
//
// subjectDigest binds the verdict to the exact authority it was computed for (the
// final-record authority digest); the signer requires it to match. issuedAt/key/signer
// come from the engine's signing context. It performs NO key operation and mints nothing.
func (e *Engine) ProduceVerdict(ctx context.Context, req AuthorityRequest, class string, policy *CeilingPolicy, subjectDigest []byte, issuedAt int64, key VerdictKeyRef, signer crypto.Signer) (Verdict, error) {
	set, wm, err := e.Resolve(ctx, req)
	if err != nil {
		return Verdict{}, err
	}
	det := determineOrFailClosed(set, class, policy)
	v := NewVerdict(set, det, wm, subjectDigest, issuedAt, key)
	return v.Sign(signer)
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
