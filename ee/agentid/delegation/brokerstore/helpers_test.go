// SPDX-License-Identifier: LicenseRef-trstctl-EE

package brokerstore

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/internal/broker"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/policy"
)

// helpers_test.go builds the AGID-07b precondition test fixtures using ONLY the PUBLIC
// delegation API (the precondition lives here, in the control-plane brokerstore package,
// which cannot reach delegation's white-box test helpers). It assembles a real AGID-04
// gate over software crypto, a signed narrowing chain, a fake attestation verifier, and
// in-memory policy / resolver / recorder fakes.

// ---- crypto + chain builders (public delegation API) ----

// signerDER generates an ephemeral ECDSA signer and returns it with its public DER.
func signerDER(t *testing.T) (crypto.Signer, []byte) {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	s, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return s, s.Public().DER
}

// testHop describes one delegation hop for the builder.
type testHop struct {
	delegatorID    string
	delegatorKeyID string
	delegateID     string
	authority      delegation.Authority
	depthRemaining uint32
	validity       delegation.Window
}

// buildChain signs a root-first chain from hops and returns the envelopes + the matching
// root-anchor map (so the anchor key matches the signed root hop). hops[0] is
// root-anchored; each subsequent hop links to its parent by digest.
func buildChain(t *testing.T, tenantID string, hops []testHop) ([]delegation.RecordEnvelope, map[string]delegation.RootAnchor) {
	t.Helper()
	var envs []delegation.RecordEnvelope
	var parentDigest []byte
	var rootDER []byte
	// Every hop's key is generated UP FRONT, because a record must now commit to
	// the key its delegate will sign with — which means hop i needs hop i+1's key
	// before it can be signed.
	signers := make([]crypto.Signer, len(hops))
	delegatorDERs := make([][]byte, len(hops))
	for i := range hops {
		signers[i], delegatorDERs[i] = signerDER(t)
	}
	for i, h := range hops {
		s, der := signers[i], delegatorDERs[i]
		if i == 0 {
			rootDER = der
		}
		rec := delegation.Record{
			TenantID:     tenantID,
			DelegatorID:  h.delegatorID,
			DelegatorKey: delegation.KeyRef{ID: h.delegatorKeyID, Algorithm: "ECDSA-P256"},
			DelegateID:   h.delegateID,
			// Commit to the key the NEXT hop signs with; the last hop delegates to
			// nobody and so commits to nothing.
			DelegateKeyThumbprint: nextHopKeyThumbprint(delegatorDERs, i),
			Authority:             h.authority,
			DepthRemaining:        h.depthRemaining,
			Validity:              h.validity,
		}
		if i == 0 {
			rec.RootAnchor = true
		} else {
			rec.ParentDigest = parentDigest
		}
		signed, err := rec.Sign(s, nil)
		if err != nil {
			t.Fatalf("sign hop %d: %v", i, err)
		}
		envs = append(envs, delegation.RecordEnvelope{Record: signed, DelegatorPublicDER: der})
		d, err := signed.Digest(nil)
		if err != nil {
			t.Fatalf("digest hop %d: %v", i, err)
		}
		parentDigest = d
	}
	anchors := map[string]delegation.RootAnchor{
		hops[0].delegatorKeyID: {PublicDER: rootDER, AuthRef: "fido2:" + hops[0].delegatorKeyID},
	}
	return envs, anchors
}

// openWindow is a validity window with no bounds (always valid).
func openWindow() delegation.Window { return delegation.Window{} }

// wideAuthority is a broad root authority.
func wideAuthority() delegation.Authority {
	return delegation.Authority{
		Scopes: []string{"read", "write"},
		Tools:  []string{"search", "email"},
		Spend:  delegation.Budget{Amount: 1000, Currency: "usd"},
		Rate:   delegation.Rate{Limit: 100, Per: "minute"},
		Depth:  3,
	}
}

// narrowerAuthority is strictly within wideAuthority.
func narrowerAuthority() delegation.Authority {
	return delegation.Authority{
		Scopes: []string{"read"},
		Tools:  []string{"search"},
		Spend:  delegation.Budget{Amount: 500, Currency: "usd"},
		Rate:   delegation.Rate{Limit: 50, Per: "minute"},
		Depth:  2,
	}
}

// twoHopChain builds a valid root→narrower two-hop chain with the given per-hop validity
// windows, returning envelopes + anchors.
func twoHopChain(t *testing.T, tenantID string, rootWin, childWin delegation.Window) ([]delegation.RecordEnvelope, map[string]delegation.RootAnchor) {
	t.Helper()
	return buildChain(t, tenantID, []testHop{
		{delegatorID: "root", delegatorKeyID: "root-key", delegateID: "mid", authority: wideAuthority(), depthRemaining: 3, validity: rootWin},
		{delegatorID: "mid", delegatorKeyID: "mid-key", delegateID: "leaf", authority: narrowerAuthority(), depthRemaining: 2, validity: childWin},
	})
}

// ---- gate (public delegation API) ----

// gateWith builds a real AGID-04 gate over software crypto with the supplied anchors,
// min-class policy, revocation reader, attestor, and clock, and returns the gate plus the
// attestor (so tests can seed and observe attestation verifications).
func gateWith(t *testing.T, anchors map[string]delegation.RootAnchor, minClass delegation.MinClassPolicy, clock func() time.Time) (*delegation.Gate, *fakeAttestor) {
	t.Helper()
	refusal, _ := signerDER(t)
	att := newFakeAttestor()
	gate, err := delegation.NewGate(delegation.Config{
		SignerID:      "brokerstore-test-signer",
		Roots:         delegation.NewTrustStore(anchors),
		RefusalSigner: refusal,
		Revocations:   delegation.NeverRevoked{},
		Attestor:      att,
		MinClass:      minClass,
		Clock:         clock,
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return gate, att
}

// ---- attestation fake (implements delegation.AttestationVerifier) ----

// fakeAttestor accepts ONLY the exact (method,payload) it was seeded with (a forged or
// replayed payload fails), and records "verified" per successful verify so a test can
// count in-signer verifications.
type fakeAttestor struct {
	mu       sync.Mutex
	good     map[string][]byte
	att      map[string]delegation.VerifiedAttestation
	verified int
}

func newFakeAttestor() *fakeAttestor {
	return &fakeAttestor{good: map[string][]byte{}, att: map[string]delegation.VerifiedAttestation{}}
}

// seed registers a method with its one accepted payload and the verified attestation it
// yields.
func (f *fakeAttestor) seed(method string, payload []byte, va delegation.VerifiedAttestation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.good[method] = append([]byte(nil), payload...)
	va.Method = method
	f.att[method] = va
}

// VerifyEvidence implements delegation.AttestationVerifier.
func (f *fakeAttestor) VerifyEvidence(method string, payload []byte) (delegation.VerifiedAttestation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	want, ok := f.good[method]
	if !ok || !bytesEqual(want, payload) {
		return delegation.VerifiedAttestation{}, delegation.ErrAttestationInvalid
	}
	f.verified++
	return f.att[method], nil
}

func (f *fakeAttestor) verifyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verified
}

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

// attBody builds the opaque attestation body bytes for (method,payload) (public
// delegation.AttestationBody).
func attBody(t *testing.T, method string, payload []byte) []byte {
	t.Helper()
	b, err := json.Marshal(delegation.AttestationBody{Method: method, Payload: payload})
	if err != nil {
		t.Fatalf("encode attestation body: %v", err)
	}
	return b
}

// ---- policy / resolver / recorder fakes ----

// fakePolicy is a PolicyEvaluator that allows or denies with a fixed reason and counts
// evaluations.
type fakePolicy struct {
	allow  bool
	reason string
	calls  int
}

func (p *fakePolicy) Evaluate(_ context.Context, _ policy.Input) (policy.Decision, error) {
	p.calls++
	return policy.Decision{Allow: p.allow, Reason: p.reason}, nil
}

// staticResolver returns a fixed ChainBoundRequest for every view (found=true), or
// found=false to exercise the fail-closed no-context path.
type staticResolver struct {
	req   ChainBoundRequest
	found bool
}

// Resolve implements RequestResolver.
func (r staticResolver) Resolve(_ context.Context, _ broker.IssuanceView) (ChainBoundRequest, bool, error) {
	return r.req, r.found, nil
}

// countingRecorder is an in-memory IssuanceBindingRecorder that records bindings and,
// optionally, refuses a repeated evidence digest so a replay path can be exercised
// without a datastore.
type countingRecorder struct {
	mu           sync.Mutex
	bindings     []delegation.IssuanceBinding
	seenEvidence map[string]bool
	refuseReplay bool
}

func newCountingRecorder() *countingRecorder {
	return &countingRecorder{seenEvidence: map[string]bool{}}
}

func (r *countingRecorder) RecordIssuanceBinding(_ context.Context, b delegation.IssuanceBinding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refuseReplay && len(b.EvidenceDigest) > 0 {
		key := string(b.EvidenceDigest)
		if r.seenEvidence[key] {
			return delegation.ErrAttestationReplay
		}
		r.seenEvidence[key] = true
	}
	r.bindings = append(r.bindings, b)
	return nil
}

func (r *countingRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bindings)
}

func (r *countingRecorder) last() delegation.IssuanceBinding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bindings[len(r.bindings)-1]
}

// ---- audit recorder (implements auditsink.Auditor) ----

type auditEvent struct {
	eventType string
	tenantID  string
	data      []byte
}

type auditRecorder struct {
	mu     sync.Mutex
	events []auditEvent
}

func newAuditRecorder() *auditRecorder { return &auditRecorder{} }

func (r *auditRecorder) Audit(_ context.Context, eventType, tenantID string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, auditEvent{eventType: eventType, tenantID: tenantID, data: append([]byte(nil), data...)})
	return nil
}

func (r *auditRecorder) find(eventType string) (auditEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e.eventType == eventType {
			return e, true
		}
	}
	return auditEvent{}, false
}

func nextHopKeyThumbprint(delegatorDERs [][]byte, i int) []byte {
	if i+1 >= len(delegatorDERs) {
		return nil
	}
	return delegation.DelegateKeyThumbprintOf(delegatorDERs[i+1])
}
