// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/digest"
	"trstctl.com/trstctl/internal/reconcile/witness"
)

var (
	ErrInvalidRequest = errors.New("xrec verifier: invalid request")
	ErrUnverified     = errors.New("xrec verifier: unverified witness")
	ErrStaleWatermark = errors.New("xrec verifier: stale watermark")
)

type Request struct {
	Evidence           witness.Evidence
	Digests            []digest.SignedDigest
	TrustedDigestKeys  map[string]crypto.PublicKey
	TrustedWitnessKeys map[string]crypto.PublicKey
	Policy             Policy
}

type Policy struct {
	VerifierAuthority      string
	RequireCountersignFrom string
	Now                    time.Time
	FreshnessBound         time.Duration
}

type Result struct {
	WitnessID          string
	TenantID           string
	SpecVersion        string
	Determinations     []Determination
	DigestWatermarks   []DigestWatermark
	StaleDigests       []StaleDigest
	AuthorityContacted bool
}

type Determination struct {
	RecordKey        canon.RecordKey
	Class            string
	PresentAuthority string
	Authorities      []string
	DisclosedRecords []witness.DisclosedRecord
	Staleness        *witness.StalenessEvidence
	Policy           *witness.PolicyEvidence
}

type DigestWatermark struct {
	AuthorityID string
	Watermark   digest.Watermark
}

type StaleDigest struct {
	AuthorityID  string
	ObservedAt   time.Time
	AgeSeconds   int64
	BoundSeconds int64
}

// Verify checks a signed witness and its signed state digests using only
// caller-supplied verification keys. It communicates with neither authority and
// touches no ledger, which is the substance of the independent-verifier claim
// (XREC-claim-20).
func Verify(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: nil context", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	policy := normalizePolicy(req.Policy)
	if policy.RequireCountersignFrom != "" && !hasCountersignFrom(req.Evidence, policy.RequireCountersignFrom) {
		return Result{}, fmt.Errorf("%w: missing countersignature from %s", ErrUnverified, policy.RequireCountersignFrom)
	}
	if err := witness.VerifyOffline(witness.OfflineVerifyRequest{
		Evidence:               req.Evidence,
		Digests:                req.Digests,
		TrustedDigestKeys:      req.TrustedDigestKeys,
		TrustedWitnessKeys:     req.TrustedWitnessKeys,
		VerifierAuthority:      policy.VerifierAuthority,
		RequireCountersignFrom: policy.RequireCountersignFrom,
	}); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrUnverified, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	result := buildResult(req.Evidence, req.Digests)
	stale := staleDigests(req.Digests, policy)
	if len(stale) > 0 {
		result.StaleDigests = stale
		return result, fmt.Errorf("%w: %d stale digest watermarks", ErrStaleWatermark, len(stale))
	}
	return result, nil
}

func normalizePolicy(policy Policy) Policy {
	policy.VerifierAuthority = strings.TrimSpace(policy.VerifierAuthority)
	policy.RequireCountersignFrom = strings.TrimSpace(policy.RequireCountersignFrom)
	if policy.Now.IsZero() {
		policy.Now = time.Now().UTC()
	} else {
		policy.Now = policy.Now.UTC()
	}
	return policy
}

func hasCountersignFrom(evidence witness.Evidence, authorityID string) bool {
	for _, sig := range evidence.CounterSignatures {
		if sig.AuthorityID == authorityID {
			return true
		}
	}
	return false
}

func buildResult(evidence witness.Evidence, signed []digest.SignedDigest) Result {
	out := Result{
		WitnessID:          evidence.Body.WitnessID,
		TenantID:           evidence.Body.TenantID,
		SpecVersion:        evidence.Body.SpecVersion,
		Determinations:     make([]Determination, 0, len(evidence.Body.Entries)),
		DigestWatermarks:   make([]DigestWatermark, 0, len(signed)),
		AuthorityContacted: false,
	}
	for _, sd := range signed {
		out.DigestWatermarks = append(out.DigestWatermarks, DigestWatermark{
			AuthorityID: sd.Body.AuthorityID,
			Watermark:   sd.Body.Watermark,
		})
	}
	for _, entry := range evidence.Body.Entries {
		out.Determinations = append(out.Determinations, Determination{
			RecordKey:        entry.RecordKey,
			Class:            entry.Class,
			PresentAuthority: entry.PresentAuthority,
			Authorities:      authoritiesFor(entry),
			DisclosedRecords: cloneDisclosed(entry.DisclosedRecords),
			Staleness:        cloneStaleness(entry.Staleness),
			Policy:           clonePolicy(entry.Policy),
		})
	}
	return out
}

func authoritiesFor(entry witness.Entry) []string {
	seen := map[string]bool{}
	var out []string
	for _, inc := range entry.Inclusions {
		if inc.AuthorityID == "" || seen[inc.AuthorityID] {
			continue
		}
		seen[inc.AuthorityID] = true
		out = append(out, inc.AuthorityID)
	}
	if entry.PresentAuthority != "" && !seen[entry.PresentAuthority] {
		out = append(out, entry.PresentAuthority)
	}
	if entry.Staleness != nil && entry.Staleness.AuthorityID != "" && !seen[entry.Staleness.AuthorityID] {
		out = append(out, entry.Staleness.AuthorityID)
	}
	if entry.Policy != nil && entry.Policy.AuthorityID != "" && !seen[entry.Policy.AuthorityID] {
		out = append(out, entry.Policy.AuthorityID)
	}
	return out
}

func cloneDisclosed(in []witness.DisclosedRecord) []witness.DisclosedRecord {
	if len(in) == 0 {
		return nil
	}
	out := make([]witness.DisclosedRecord, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].CanonicalRecordBytes = append([]byte(nil), in[i].CanonicalRecordBytes...)
	}
	return out
}

func cloneStaleness(in *witness.StalenessEvidence) *witness.StalenessEvidence {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func clonePolicy(in *witness.PolicyEvidence) *witness.PolicyEvidence {
	if in == nil {
		return nil
	}
	out := *in
	out.PolicySetHash = append([]byte(nil), in.PolicySetHash...)
	return &out
}

func staleDigests(signed []digest.SignedDigest, policy Policy) []StaleDigest {
	if policy.FreshnessBound <= 0 {
		return nil
	}
	boundSeconds := int64(policy.FreshnessBound / time.Second)
	stale := make([]StaleDigest, 0)
	for _, sd := range signed {
		observedAt := time.Unix(sd.Body.Watermark.ObservedAt, 0).UTC()
		age := policy.Now.Sub(observedAt)
		if age <= policy.FreshnessBound {
			continue
		}
		stale = append(stale, StaleDigest{
			AuthorityID:  sd.Body.AuthorityID,
			ObservedAt:   observedAt,
			AgeSeconds:   int64(age / time.Second),
			BoundSeconds: boundSeconds,
		})
	}
	return stale
}
