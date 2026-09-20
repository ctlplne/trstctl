// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"encoding/json"
	"fmt"
	"sort"

	"trstctl.com/trstctl/internal/crypto"
)

// aggregate.go mints and verifies the SIGNED aggregate evidence artifact for a terminal
// revocation (AGID-claims-18 and the independent AGID-claim-33). When a directive reaches the
// terminal revoked-with-evidence state — every enqueued and follow-on job carries signed
// per-job completion evidence (§7.3 / INV-A9) — the terminal transition mints ONE signed
// artifact that binds a DIGEST of the per-job completion evidence recorded under the
// directive, so a single portable proof answers "did the kill finish?" without replaying
// the whole ledger. Per the independent AGID-claim-33, the same artifact ALSO binds the
// subject id, the reason class, the directive watermark, and the ledger head as of the
// terminal revoked state.
//
// The artifact is THIRD-PARTY VERIFIABLE OFFLINE: an auditor or counterparty verifies it
// against ONLY the published per-job evidence digests (the same digests the per-job
// CompletionEvidence documents hash to) plus the artifact's embedded verifying key — no
// control-plane access, no database, no signer. VerifyAggregateOffline is that check.

// aggregateDomain is the domain-separation tag prefixed to the canonical aggregate bytes
// before signing, so an aggregate-artifact signature can never be confused with a
// per-job completion-evidence signature, a refusal, or any other artifact. Versioned so
// the artifact shape can evolve without ambiguity.
const aggregateDomain = "agid/agentid/revocation-aggregate-evidence/v1"

// completionDigestDomain is the domain tag under which the per-job completion-evidence
// digest set is folded into the single CompletionEvidenceDigest the artifact binds. It
// keeps the aggregation function distinct from any other digest-over-digests use.
const completionDigestDomain = "agid/agentid/revocation-aggregate/completion-set/v1"

// AggregateEvidence is the signed terminal-revocation aggregate artifact (AGID-claims-18/33).
// It is a pure value: a relying party stores it and verifies it offline. The bound set
// is exactly the AGID-claim-33 binding set plus the completion-evidence digest of AGID-claim-18:
//   - CompletionEvidenceDigest: a digest over the SORTED per-job completion-evidence
//     digests recorded under the directive (AGID-claim-18). Deterministic and reproducible
//     from the published per-job evidence digests alone.
//   - SubjectID, ReasonClass, Watermark, LedgerHead: the AGID-claim-33 binding set — the
//     subject the directive named, the reason class, the directive's determining
//     watermark, and the ledger head AS OF the terminal revoked state.
//
// Signature is over the canonical body (aggregateBodyBytes) via internal/crypto (AN-3);
// PublicKey is the PKIX/DER verifying key so verification needs no control-plane access.
type AggregateEvidence struct {
	TenantID    string      `json:"tenant_id"`
	DirectiveID string      `json:"directive_id"`
	SubjectID   string      `json:"subject_id"`
	ReasonClass ReasonClass `json:"reason_class"`
	Watermark   uint64      `json:"watermark"`
	LedgerHead  uint64      `json:"ledger_head"`
	// JobCount is the number of per-job completion-evidence digests folded into
	// CompletionEvidenceDigest (the obligation-set size at terminal). It is bound so a
	// verifier presented FEWER published digests than were aggregated cannot silently
	// verify a truncated set: the recomputed digest would differ AND the count would not
	// match.
	JobCount int `json:"job_count"`
	// CompletionEvidenceDigest is the digest over the sorted per-job completion-evidence
	// digests recorded under the directive (AGID-claim-18).
	CompletionEvidenceDigest []byte `json:"completion_evidence_digest"`
	// Signature is the terminal-signer's signature over aggregateBodyBytes; omitted from
	// the body that is signed (a signature cannot cover itself) and attached after.
	Signature []byte `json:"signature,omitempty"`
	// PublicKey is the PKIX/DER SubjectPublicKeyInfo of the verifying key.
	PublicKey []byte `json:"public_key,omitempty"`
}

// CompletionEvidenceDigestOf folds a set of per-job completion-evidence digests into the
// single digest the aggregate artifact binds (AGID-claim-18). It SORTS the digests (so the
// result is independent of job discovery order) and hashes the domain tag, the count, and
// each length-prefixed digest through internal/crypto (AN-3). It is the SAME function the
// artifact minting and the offline verifier both run, so an auditor recomputes the exact
// bound digest from the published per-job evidence digests. A caller passes the digest of
// each job's canonical CompletionEvidence body (crypto.SHA256Sum(evidenceBody), i.e. the
// completion reference the store records on the job row).
func CompletionEvidenceDigestOf(perJobEvidenceDigests [][]byte) []byte {
	sorted := make([][]byte, len(perJobEvidenceDigests))
	copy(sorted, perJobEvidenceDigests)
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })

	var b []byte
	b = append(b, completionDigestDomain...)
	b = append(b, ':')
	b = appendU64(b, uint64(len(sorted)))
	for _, d := range sorted {
		b = appendU64(b, uint64(len(d)))
		b = append(b, d...)
	}
	return crypto.SHA256Sum(b)
}

// aggregateBodyBytes returns the canonical, deterministic bytes that are signed: the
// domain tag followed by the JSON of the artifact with Signature and PublicKey cleared
// (they cannot cover themselves). Fixed field order makes it reproducible on replay and
// on independent verification.
func (a AggregateEvidence) aggregateBodyBytes() ([]byte, error) {
	body := a
	body.Signature = nil
	body.PublicKey = nil
	j, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("revoke: marshal aggregate body: %w", err)
	}
	var out []byte
	out = append(out, aggregateDomain...)
	out = append(out, ':')
	out = append(out, j...)
	return out, nil
}

// signAggregate signs the aggregate body with signer and returns the artifact with
// Signature + PublicKey attached. Signing goes through internal/crypto (AN-3); a nil
// signer is a programming error (the terminal transition always supplies one).
func signAggregate(signer crypto.Signer, a AggregateEvidence) (AggregateEvidence, error) {
	if signer == nil {
		return AggregateEvidence{}, fmt.Errorf("revoke: aggregate evidence requires a signer (AN-3)")
	}
	body, err := a.aggregateBodyBytes()
	if err != nil {
		return AggregateEvidence{}, err
	}
	sig, err := signer.Sign(body, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return AggregateEvidence{}, fmt.Errorf("revoke: sign aggregate evidence: %w", err)
	}
	pub := signer.Public()
	a.Signature = sig
	a.PublicKey = pub.DER
	return a, nil
}

// EncodeAggregate marshals a signed aggregate artifact to portable JSON bytes (the form
// an auditor receives out-of-band). DecodeAggregate is the inverse.
func EncodeAggregate(a AggregateEvidence) ([]byte, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("revoke: encode aggregate artifact: %w", err)
	}
	return b, nil
}

// DecodeAggregate parses portable aggregate-artifact bytes back into an AggregateEvidence.
func DecodeAggregate(b []byte) (AggregateEvidence, error) {
	var a AggregateEvidence
	if err := json.Unmarshal(b, &a); err != nil {
		return AggregateEvidence{}, fmt.Errorf("revoke: decode aggregate artifact: %w", err)
	}
	return a, nil
}

// VerifyAggregateSignature checks the artifact's signature against its embedded public
// key, over the canonical body. It is the signature half of offline verification; a
// missing signature/key or a signature that does not verify is an error (fail-closed —
// an unverifiable artifact is not proof).
func VerifyAggregateSignature(a AggregateEvidence) error {
	if len(a.Signature) == 0 {
		return fmt.Errorf("revoke: aggregate artifact has no signature")
	}
	if len(a.PublicKey) == 0 {
		return fmt.Errorf("revoke: aggregate artifact has no public key")
	}
	body, err := a.aggregateBodyBytes()
	if err != nil {
		return err
	}
	if err := crypto.Verify(crypto.PublicKey{DER: a.PublicKey}, body, a.Signature, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		return fmt.Errorf("revoke: aggregate artifact signature invalid: %w", err)
	}
	return nil
}

// VerifyAggregateOffline is the THIRD-PARTY, control-plane-free verification (AGID-claim-18):
// given the signed aggregate artifact and ONLY the published per-job completion-evidence
// digests, it (1) verifies the artifact signature against its embedded key and (2)
// recomputes the completion-evidence digest over the published digests and requires it to
// equal the digest the artifact binds, AND the published count to equal the bound
// JobCount. An auditor runs this with no database and no signer: the artifact plus the
// published digests are a portable proof that every job completed. Any mismatch —
// truncated set, substituted digest, tampered binding, wrong count — fails closed.
//
// The published digests are the per-job completion-evidence digests (each
// crypto.SHA256Sum of a job's canonical CompletionEvidence body); a publisher lists them
// alongside the artifact. VerifyAggregateOffline does NOT need the evidence bodies, only
// their digests — the auditor can be given digests without the (potentially sensitive)
// evidence contents and still verify completeness.
func VerifyAggregateOffline(a AggregateEvidence, publishedEvidenceDigests [][]byte) error {
	if err := VerifyAggregateSignature(a); err != nil {
		return err
	}
	if len(publishedEvidenceDigests) != a.JobCount {
		return fmt.Errorf("revoke: aggregate offline verify: published %d evidence digests, artifact binds %d jobs", len(publishedEvidenceDigests), a.JobCount)
	}
	recomputed := CompletionEvidenceDigestOf(publishedEvidenceDigests)
	if !bytesEqual(recomputed, a.CompletionEvidenceDigest) {
		return fmt.Errorf("revoke: aggregate offline verify: recomputed completion-evidence digest does not match the artifact (truncated or substituted evidence set)")
	}
	return nil
}

// appendU64 appends v as 8 big-endian bytes. Local helper so the aggregation stays
// std-hash-free (the digest itself is taken inside internal/crypto, AN-3). Each byte is
// MASKED out of v (& 0xFF) rather than narrowed, so every octet is by construction in
// range and the encoding is exactly the same big-endian byte string as before.
func appendU64(b []byte, v uint64) []byte {
	return append(b,
		byte((v>>56)&0xFF), byte((v>>48)&0xFF), byte((v>>40)&0xFF), byte((v>>32)&0xFF),
		byte((v>>24)&0xFF), byte((v>>16)&0xFF), byte((v>>8)&0xFF), byte(v&0xFF))
}

// bytesEqual is a length-then-content comparison (these are public digests, not secrets).
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
