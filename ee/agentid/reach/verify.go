// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reach

import (
	"errors"

	"trstctl.com/trstctl/internal/crypto"
)

// verify.go is the pure, testable IN-SIGNER verification of a signed reachability verdict
// (AGID-claims 5/6 / INV-A5): the check the isolated signer runs as a PRECONDITION of the key
// operation. It performs NO key operation, holds no issuance key, builds no graph, and
// touches no datastore — it depends ONLY on internal/crypto (so the isolated signer stays
// datastore-free, AN-4, and graph computation stays OUT of the signer, AGID-claim-6). It:
//
//   - resolves the verdict-signer's public key through a caller-supplied trust lookup (the
//     signer holds this mapping; a caller cannot inject their own verdict key);
//   - checks the verdict's signature over its canonical bytes (via internal/crypto, AN-3);
//   - checks the graph WATERMARK is present and ACCEPTABLE (not stale) against the signer's
//     watermark policy — so verification is bounded by, and invariant to graph changes
//     after, the watermark (AGID-claim-6 / acceptance criterion 3);
//   - checks the verdict's SubjectDigest equals the request's final-record authority digest
//     (so a verdict for one authority cannot authorize a different, broader one);
//   - checks the ceiling DETERMINATION is not Exceeded (AGID-claim-5).
//
// FAIL-CLOSED is the spine: an absent, unsigned, tampered, stale-watermark, wrong-subject,
// or Exceeded verdict is a CEILING VIOLATION — the delegation gate turns any returned
// error into a signed refusal naming the reachability check, with ZERO key ops (INV-A1
// preserved). An unverifiable verdict is NEVER treated as "allowed".

// VerdictTrustLookup resolves a verdict-signer key id to the PKIX/DER
// SubjectPublicKeyInfo of the trusted verdict-signer public key, and whether it is
// trusted. The signer holds this mapping (the reachability engine's verdict-signing
// identity/identities); an unresolved id returns (nil,false) and the verdict is refused
// fail-closed (ErrUntrustedVerdictSigner). It mirrors taskenv.TrustLookup so the signer's
// registries are uniform.
type VerdictTrustLookup func(verdictKeyID string) (publicDER []byte, trusted bool)

// WatermarkPolicy decides whether a verdict's graph watermark is ACCEPTABLE at issuance
// time. It is how the signer bounds freshness WITHOUT a live graph query: the verdict
// binds the watermark it was computed at, and this policy (held by the signer) accepts or
// rejects it (e.g. "must equal the current tenant watermark", "must be within N of it",
// or in tests "must be non-empty"). Returning false means STALE ⇒ fail-closed refusal.
// tenantID and the verdict's watermark are passed; a nil policy is treated by
// VerifyVerdict as "any non-empty watermark is acceptable" (a permissive default suitable
// for tests; production supplies a real policy).
type WatermarkPolicy func(tenantID, watermark string) bool

// VerifyInput bundles what the signer needs to verify a verdict as a precondition, kept
// small and datastore-free.
type VerifyInput struct {
	// Verdict is the signed reachability verdict presented over the seam.
	Verdict Verdict
	// TenantID is the issuance request's tenant. The verdict's TenantID must equal it
	// (AN-1: a verdict for another tenant is refused).
	TenantID string
	// SubjectDigest is the digest of the request's FINAL delegation-record authority (the
	// leaf the credential is for). The verdict's SubjectDigest must equal it, binding the
	// verdict to this exact authority.
	SubjectDigest []byte
	// Trust resolves the verdict-signer key id to a trusted public key. REQUIRED:
	// verification with no trust lookup fails closed (a verdict whose signer cannot be
	// resolved cannot be trusted).
	Trust VerdictTrustLookup
	// Watermark is the freshness policy. Optional: nil accepts any non-empty watermark
	// (test default); production supplies a real staleness policy.
	Watermark WatermarkPolicy
}

// Verification errors. Each is fail-closed: the delegation gate maps any of them to a
// signed refusal naming the reachability check, with no key op.
var (
	// ErrNoVerdict is returned when no verdict is presented (or it is empty). Fail-closed:
	// an absent verdict is a ceiling violation, never "allowed".
	ErrNoVerdict = errors.New("reach: no reachability verdict presented (fail-closed)")
	// ErrUntrustedVerdictSigner is returned when the verdict-signer key id does not resolve
	// through the trust lookup. Fail-closed.
	ErrUntrustedVerdictSigner = errors.New("reach: verdict signer key id does not resolve to a trusted key")
	// ErrVerdictTenantMismatch is returned when the verdict's tenant does not match the
	// request's tenant (AN-1). Fail-closed.
	ErrVerdictTenantMismatch = errors.New("reach: verdict tenant does not match the request tenant")
	// ErrVerdictSubjectMismatch is returned when the verdict's SubjectDigest does not match
	// the request's final-record authority digest. Fail-closed: a verdict for a different
	// authority cannot authorize this issuance.
	ErrVerdictSubjectMismatch = errors.New("reach: verdict subject digest does not match the requested authority")
	// ErrVerdictStale is returned when the verdict's watermark is empty or rejected by the
	// freshness policy. Fail-closed.
	ErrVerdictStale = errors.New("reach: verdict graph watermark is stale or absent")
	// ErrCeilingExceeded is returned when the verdict's ceiling determination is Exceeded
	// (AGID-claim-5). The error names the first violated ceiling; the gate's refusal carries it.
	ErrCeilingExceeded = errors.New("reach: reachable set exceeds a policy ceiling")
)

// CeilingExceededError carries the exceeded-ceiling detail so the delegation gate can name
// the violated ceiling and reference the offending-subset digest in its signed refusal,
// WITHOUT re-computing the graph (AGID-claim-5). It wraps ErrCeilingExceeded.
type CeilingExceededError struct {
	// Violations are the verdict's determination violations (each names a ceiling and
	// carries an offending-subset digest).
	Violations []Violation
	// RequesterClass is the class the ceiling was selected by.
	RequesterClass string
}

func (e *CeilingExceededError) Error() string {
	if len(e.Violations) == 0 {
		return ErrCeilingExceeded.Error()
	}
	return ErrCeilingExceeded.Error() + ": " + string(e.Violations[0].Ceiling) + " (" + e.Violations[0].Reason + ")"
}

// Unwrap lets errors.Is(err, ErrCeilingExceeded) match a CeilingExceededError.
func (e *CeilingExceededError) Unwrap() error { return ErrCeilingExceeded }

// FirstCeiling returns the first violated ceiling kind (or "" when none), for a refusal's
// failed-check detail.
func (e *CeilingExceededError) FirstCeiling() CeilingKind {
	if len(e.Violations) == 0 {
		return ""
	}
	return e.Violations[0].Ceiling
}

// OffendingDigest returns the first violation's offending-subset digest (or nil), for a
// refusal to reference the cause.
func (e *CeilingExceededError) OffendingDigest() []byte {
	if len(e.Violations) == 0 {
		return nil
	}
	return e.Violations[0].OffendingDigest
}

// VerifyVerdict verifies a signed reachability verdict as a key-op precondition (claims
// 5/6 / INV-A5). It is pure and fail-closed and performs NO key operation. On success it
// returns nil (the reachable set is within ceilings, the verdict is authentic, fresh, and
// bound to this authority) and the caller may proceed to the key op. On ANY failure it
// returns a non-nil error the gate turns into a signed refusal with zero key ops; a
// ceiling breach returns a *CeilingExceededError so the refusal can name the ceiling.
//
// Order is deliberate: cheap structural/fail-closed checks first (present, tenant,
// subject), then the cryptographic signature (authenticity), then freshness (watermark),
// then the ceiling determination. Every check that can refuse runs before any approval is
// signaled; the signer reaches its keyOp only after VerifyVerdict returns nil.
func VerifyVerdict(in VerifyInput) error {
	v := in.Verdict

	// (0) Presence / trust lookup availability — fail closed on an absent verdict or a
	// gate with no way to resolve the verdict signer.
	if len(v.Signature) == 0 && v.TenantID == "" && len(v.ReachableDigest) == 0 {
		return ErrNoVerdict
	}
	if in.Trust == nil {
		return ErrUntrustedVerdictSigner
	}

	// (1) Tenant binding (AN-1): the verdict must be for the request's tenant.
	if v.TenantID != in.TenantID {
		return ErrVerdictTenantMismatch
	}

	// (2) Subject binding: the verdict must be for the exact authority being issued.
	if !constantTimeEqualDigest(v.SubjectDigest, in.SubjectDigest) {
		return ErrVerdictSubjectMismatch
	}

	// (3) Signature (authenticity): resolve the verdict-signer public key and verify the
	// signature over the verdict's canonical bytes (AN-3). A tampered verdict (any bound
	// field altered, including the determination or watermark) fails here.
	pubDER, trusted := in.Trust(v.Key.ID)
	if !trusted || len(pubDER) == 0 {
		return ErrUntrustedVerdictSigner
	}
	if err := v.VerifySignature(crypto.PublicKey{DER: pubDER}); err != nil {
		return ErrVerdictSignature
	}

	// (4) Freshness (watermark): bound by the watermark; a stale/absent watermark fails
	// closed. Verification is invariant to graph changes AFTER the watermark because we
	// trust the SIGNED digest, not a live query.
	if v.Watermark == "" {
		return ErrVerdictStale
	}
	if in.Watermark != nil && !in.Watermark(in.TenantID, v.Watermark) {
		return ErrVerdictStale
	}

	// (5) Ceiling determination (AGID-claim-5): the SIGNED determination governs. An Exceeded
	// determination is a refusal naming the ceiling.
	if v.Determination.Exceeded {
		return &CeilingExceededError{
			Violations:     v.Determination.Violations,
			RequesterClass: v.Determination.RequesterClass,
		}
	}
	return nil
}

// constantTimeEqualDigest compares two digests for equality. These are public digests
// (not secrets), so timing is not load-bearing; a length-then-content compare via
// internal/crypto's subtle helper keeps a single comparison discipline. A nil/empty
// expected digest never matches a set one (fail-closed): a request that carries no subject
// digest cannot be satisfied by any verdict.
func constantTimeEqualDigest(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return crypto.ConstantTimeEqual(a, b)
}
