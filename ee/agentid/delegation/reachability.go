// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/ee/agentid/reach"
)

// reachability.go is the AGID-06 extension of the in-signer gate: the pre-issuance
// reachability bound (AGID-claims 5/6 / INV-A5). When the reachability precondition is engaged,
// the gate verifies a SIGNED REACHABILITY VERDICT — produced OUTSIDE the signer by the
// ee/agentid/reach engine — as a PRECONDITION of the key operation, BOUND to the FINAL
// delegation record's authority. The verdict binds a reachable-set digest, a ceiling
// determination, and a graph watermark; the signer trusts the verdict's SIGNATURE +
// WATERMARK, never a live graph query, so graph computation stays out of the custody
// boundary (AGID-claim-6). A reachable set that exceeds a policy ceiling yields an Exceeded
// determination the gate refuses on, naming the violated ceiling and referencing a digest
// of the offending reachable subset (AGID-claim-5). An absent/unsigned/tampered/stale verdict
// is treated fail-closed as a ceiling violation (no key op).
//
// This file adds NO new core signing option: it extends the existing AGID-04a
// WithIssuanceGate seam the gate is already attached through. The verdict travels opaquely
// in PreconditionsBody.ReachabilityVerdict (wire.go), exactly as the chain, subject repr,
// attestation, and task envelope do; the gate treats it as untrusted input and
// re-verifies it inside the boundary. The reachability model + pure verification live in
// ee/agentid/reach, which imports only internal/crypto (so the isolated signer stays
// datastore-free and graph-free on the verify path, AN-4); the graph-walking engine that
// PRODUCES a verdict lives in the ee/agentid/reach/engine subpackage (which pulls
// internal/graph + internal/store) and is NOT on the signer path.
//
// Engagement (fail-closed, no regression):
//   - A verdict IS carried ⇒ verify it (regardless of config): a caller who ships a verdict
//     has asked for it to be checked, and an invalid one must not slip through.
//   - No verdict carried, reachability ENABLED (ReachabilityTrust set or
//     RequireReachability), and a chain is present ⇒ fail-closed refusal (an authority to
//     bound with no verdict is a ceiling violation).
//   - No verdict carried and reachability NOT enabled ⇒ inert (exactly AGID-05 behavior;
//     gates that never configure reachability are unaffected).

// Reachability-precondition errors (surfaced as refusal detail; never leak secrets).
var (
	// ErrReachabilityVerdictMissing is returned when the reachability precondition is
	// engaged (enabled + a chain present) but no verdict was carried over the seam.
	// Fail-closed: an authority to bound with no reachability verdict cannot be issued.
	ErrReachabilityVerdictMissing = errors.New("delegation: reachability required but no verdict was supplied")
	// ErrReachabilityNoTrust is returned when a reachability verdict is presented (or
	// required) but the gate holds no reachability trust lookup to resolve the verdict
	// signer. Fail-closed: an unverifiable verdict must be refused, never trusted.
	ErrReachabilityNoTrust = errors.New("delegation: no reachability trust lookup configured to verify a verdict")
	// ErrReachabilityDecode is returned when the opaque reachability-verdict body cannot be
	// decoded. Fail-closed.
	ErrReachabilityDecode = errors.New("delegation: cannot decode reachability verdict body")
	// ErrReachabilitySubject is returned when the head authority digest cannot be computed
	// to bind the verdict to. Fail-closed.
	ErrReachabilitySubject = errors.New("delegation: cannot compute head authority digest for reachability")
)

// verifyReachability is the AGID-06 in-signer precondition (AGID-claims 5/6 / INV-A5). It runs
// INSIDE verify(), AFTER the chain has verified (so the head record is a verified value)
// and BEFORE the binding is assembled / any key op is reached. It performs NO key op. Any
// refusal names CheckReachability. Semantics per the engagement rules above.
func (g *Gate) verifyReachability(tenantID string, body PreconditionsBody, now time.Time) verifyResult {
	engaged, err := g.reachabilityEngaged(body)
	if err != nil {
		return refusal(CheckReachability, -1, err.Error())
	}
	if !engaged {
		// Not engaged: inert (no verdict and reachability not enabled). AGID-05 behavior
		// is exactly preserved.
		return verifyResult{}
	}

	// The verdict must be present. When engaged-because-required but absent, fail closed.
	if len(body.ReachabilityVerdict) == 0 {
		return refusal(CheckReachability, -1, ErrReachabilityVerdictMissing.Error())
	}

	// A gate that must verify a verdict but holds no trust lookup cannot trust it: fail
	// closed (mirrors the task-envelope no-trust refusal).
	if g.cfg.ReachabilityTrust == nil {
		return refusal(CheckReachability, -1, ErrReachabilityNoTrust.Error())
	}

	// The verdict is bound to the FINAL record's authority. Re-derive the head authority
	// digest inside the boundary; the verdict's SubjectDigest must equal it, so a verdict
	// computed for a different (e.g. narrower) authority cannot authorize this issuance.
	subjectDigest, err := g.headAuthorityDigest(body.Chain)
	if err != nil {
		return refusal(CheckReachability, -1, err.Error())
	}

	// Decode the opaque verdict fail-closed, then verify it as a precondition (signature +
	// tenant + subject + watermark + ceiling determination) via the pure, graph-free
	// ee/agentid/reach verifier. A stale/absent watermark, a wrong tenant/subject, a bad
	// signature, or an Exceeded determination all refuse here — the signer trusts the
	// SIGNED result, computing nothing from a graph.
	verdict, err := reach.DecodeVerdict(body.ReachabilityVerdict)
	if err != nil {
		return refusal(CheckReachability, -1, ErrReachabilityDecode.Error())
	}
	verr := reach.VerifyVerdict(reach.VerifyInput{
		Verdict:       verdict,
		TenantID:      tenantID,
		SubjectDigest: subjectDigest,
		Trust:         g.cfg.ReachabilityTrust,
		Watermark:     g.cfg.ReachabilityWatermark,
	})
	if verr != nil {
		return refusal(CheckReachability, -1, reachabilityDetail(verr))
	}
	// Verdict verified and within ceilings: the reachability precondition passes. Nothing
	// is bound into the credential from reachability (the graph is an input to a refusal
	// gate only, §6.3); the credential binding is unchanged.
	return verifyResult{}
}

// reachabilityEngaged reports whether the reachability precondition applies to this
// request. It is engaged when a verdict is carried (verify whatever is presented), or when
// reachability is ENABLED (a trust lookup is configured, or RequireReachability is set) AND
// there is a chain (an authority to bound). A decode failure of the precondition body is
// surfaced as an error the caller turns into a fail-closed refusal.
func (g *Gate) reachabilityEngaged(body PreconditionsBody) (bool, error) {
	if len(body.ReachabilityVerdict) > 0 {
		return true, nil
	}
	enabled := g.cfg.ReachabilityTrust != nil || g.cfg.RequireReachability
	if enabled && len(body.Chain) > 0 {
		return true, nil
	}
	return false, nil
}

// headAuthorityDigest returns the canonical digest of the FINAL (leaf) record's authority
// — the subject the reachability verdict is bound to. The head is the last hop (the record
// the credential is being issued for); its authority is what the reachable set is computed
// from. The digest uses the same comparator canonicalization the narrowing check uses, so
// the value the gate binds to matches the value an out-of-signer engine computes from the
// same record.
func (g *Gate) headAuthorityDigest(chain []RecordEnvelope) ([]byte, error) {
	if len(chain) == 0 {
		return nil, ErrReachabilitySubject
	}
	head := chain[len(chain)-1].Record
	d, err := CanonicalDigest(head.Authority, g.cfg.Tools)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReachabilitySubject, err)
	}
	return d, nil
}

// reachabilityDetail renders a verification error as refusal detail, NAMING the violated
// ceiling for a ceiling breach (AGID-claim-5) so the signed refusal is diagnostic without the
// graph. A CeilingExceededError names its first ceiling and reason; every other error is
// rendered by its message (all fail-closed, all no-key-op).
func reachabilityDetail(err error) string {
	var ce *reach.CeilingExceededError
	if errors.As(err, &ce) {
		if k := ce.FirstCeiling(); k != "" {
			return fmt.Sprintf("reachable set exceeds ceiling %s: %s", k, ce.Error())
		}
	}
	return err.Error()
}
