// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/agentstack"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// ---- ordering instrumentation (mirrors the 04a seam's orderLog/instrumented key
// factory, reproduced here so the gate's verify-before-keygen ordering is asserted in
// this package with an INSTRUMENTED FAKE KEYSTORE, per the card). ----

// orderLog records the observed ordering of gate consults, in-gate check completions,
// and keystore key ops, so a test can assert no key op is observed until every check has
// passed and the gate has approved (INV-A1).
type orderLog struct {
	mu     sync.Mutex
	events []string
}

func (l *orderLog) record(ev string) {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
}

func (l *orderLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.events))
	copy(out, l.events)
	return out
}

func (l *orderLog) count(ev string) int {
	n := 0
	for _, e := range l.snapshot() {
		if e == ev {
			n++
		}
	}
	return n
}

// index returns the position of the first occurrence of ev, or -1.
func (l *orderLog) index(ev string) int {
	for i, e := range l.snapshot() {
		if e == ev {
			return i
		}
	}
	return -1
}

// instrumentedKeystore is an INSTRUMENTED FAKE KEYSTORE: every key op (agent key
// generation) records a "keyop" event in the shared order log BEFORE producing a locked
// key inside the boundary. A test fails on any "keyop" preceding a completed check
// (INV-A1). It generates real locked keys so the minted credential is real and
// offline-verifiable.
type instrumentedKeystore struct {
	log *orderLog
	mu  sync.Mutex
	n   int
}

// GenerateAgentKey is the observable key op the gated keyOp closure invokes AFTER the
// gate approves. It records "keyop" then returns a real locked signer (its private key
// stays locked; only the DigestSigner view is returned, AN-8).
func (k *instrumentedKeystore) GenerateAgentKey(alg crypto.Algorithm) (crypto.DigestSigner, func(), error) {
	k.log.record("keyop")
	k.mu.Lock()
	k.n++
	k.mu.Unlock()
	locked, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return nil, func() {}, err
	}
	return locked, locked.Destroy, nil
}

func (k *instrumentedKeystore) keyOps() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.n
}

// gatedResult bundles the decision plus whether the keyOp ran and the credential it
// produced, for assertions.
type gatedResult struct {
	decision   signing.IssuanceDecision
	keyOpRan   bool
	credential []byte
}

// runGatedIssue faithfully MIRRORS the core seam internal/signing.(*Server).gatedIssue
// (which 04a proves at the seam with its own instrumented key factory): it consults the
// gate FIRST, and runs keyOp ONLY when the gate returns an Approved decision. It is
// reproduced here so this package's tests can drive the exact ordering with an
// instrumented fake keystore. A refusing gate ⇒ keyOp never runs ⇒ zero key ops. It
// records "gate" at consult time so the log shows the gate strictly before any keyop.
func runGatedIssue(t *testing.T, log *orderLog, gate *Gate, req signing.IssuancePreconditions, keyOp func(signing.IssuanceDecision) ([]byte, error)) gatedResult {
	t.Helper()
	log.record("gate")
	decision, err := gate.VerifyIssuancePreconditions(backgroundCtx(), req)
	if err != nil {
		t.Fatalf("gate returned a hard error (the gate must fail closed with a refusal, not error): %v", err)
	}
	if !decision.Approved {
		return gatedResult{decision: decision, keyOpRan: false}
	}
	cred, err := keyOp(decision)
	if err != nil {
		t.Fatalf("keyOp failed after approval: %v", err)
	}
	return gatedResult{decision: decision, keyOpRan: true, credential: cred}
}

// ---- crypto/chain builders ----

// signerWithDER generates an ephemeral ECDSA signer and returns it with its public DER.
func signerWithDER(t *testing.T) (crypto.Signer, []byte) {
	t.Helper()
	be := crypto.NewSoftwareBackend()
	s, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return s, s.Public().DER
}

// hop describes one delegation hop to build: the delegator/delegate ids, the authority,
// and the depth remaining. The builder signs it with the supplied delegator signer and
// links it to its parent.
type hop struct {
	delegatorID    string
	delegatorKeyID string
	delegateID     string
	authority      Authority
	depthRemaining uint32
	validity       Window
}

// builtChain is the output of buildChain: the signed root-first envelopes and the root
// anchor (delegator key id -> RootAnchor) to seed the trust store, plus the chain-head
// digest for assertions.
type builtChain struct {
	envelopes  []RecordEnvelope
	rootKeyID  string
	rootDER    []byte
	headDigest []byte
}

// buildChain builds a signed, correctly-linked root-first chain from hops. hops[0] is
// the root-anchored hop; each subsequent hop links to the previous by parent digest and
// is signed by its delegator key. delegatorSigners[i] signs hops[i]. The reg is used for
// canonical bytes. It returns the envelopes and the root anchor material.
func buildChain(t *testing.T, reg *ToolRegistry, tenantID string, hops []hop, delegatorSigners []crypto.Signer, delegatorDERs [][]byte) builtChain {
	t.Helper()
	if len(hops) != len(delegatorSigners) || len(hops) != len(delegatorDERs) {
		t.Fatalf("buildChain: mismatched lengths")
	}
	var envs []RecordEnvelope
	var parentDigest []byte
	for i, h := range hops {
		rec := Record{
			TenantID:       tenantID,
			DelegatorID:    h.delegatorID,
			DelegatorKey:   KeyRef{ID: h.delegatorKeyID, Algorithm: "ECDSA-P256"},
			DelegateID:     h.delegateID,
			Authority:      h.authority,
			DepthRemaining: h.depthRemaining,
			Validity:       h.validity,
		}
		if i == 0 {
			rec.RootAnchor = true
		} else {
			rec.ParentDigest = parentDigest
		}
		signed, err := rec.Sign(delegatorSigners[i], reg)
		if err != nil {
			t.Fatalf("sign hop %d: %v", i, err)
		}
		envs = append(envs, RecordEnvelope{Record: signed, DelegatorPublicDER: delegatorDERs[i]})
		d, err := signed.Digest(reg)
		if err != nil {
			t.Fatalf("digest hop %d: %v", i, err)
		}
		parentDigest = d
	}
	return builtChain{
		envelopes:  envs,
		rootKeyID:  hops[0].delegatorKeyID,
		rootDER:    delegatorDERs[0],
		headDigest: parentDigest,
	}
}

// openWindow is a validity window that always contains now (no bounds).
func openWindow() Window { return Window{} }

// wideAuthority is a broad root authority: two scopes, high budget, depth 3.
func wideAuthority() Authority {
	return Authority{
		Scopes: []string{"read", "write"},
		Tools:  []string{"search", "email"},
		Spend:  Budget{Amount: 1000, Currency: "usd"},
		Rate:   Rate{Limit: 100, Per: "minute"},
		Depth:  3,
	}
}

// narrowerAuthority is strictly within wideAuthority (subset scopes/tools, lower budget,
// lower depth).
func narrowerAuthority() Authority {
	return Authority{
		Scopes: []string{"read"},
		Tools:  []string{"search"},
		Spend:  Budget{Amount: 500, Currency: "usd"},
		Rate:   Rate{Limit: 50, Per: "minute"},
		Depth:  2,
	}
}

// widerAuthority widens wideAuthority in the scopes dimension (adds "admin").
func widerAuthority() Authority {
	return Authority{
		Scopes: []string{"read", "write", "admin"},
		Tools:  []string{"search", "email"},
		Spend:  Budget{Amount: 1000, Currency: "usd"},
		Rate:   Rate{Limit: 100, Per: "minute"},
		Depth:  2,
	}
}

// ---- attestation fake ----

// fakeAttestor is an in-memory AttestationVerifier: it returns a canned Attestation for
// a recognized (method,payload) pair, or an error (forged/replayed evidence). It records
// "attest-verified" in the order log on a successful verify so tests can assert
// attestation is verified BEFORE keygen. It is deliberately strict: it accepts ONLY the
// exact payload it was seeded with (a replayed/forged payload fails), modeling the core
// internal/attest fail-closed contract.
type fakeAttestor struct {
	log       *orderLog
	good      map[string][]byte // method -> the one accepted payload
	attByMeth map[string]VerifiedAttestation
}

func newFakeAttestor(log *orderLog) *fakeAttestor {
	return &fakeAttestor{log: log, good: map[string][]byte{}, attByMeth: map[string]VerifiedAttestation{}}
}

// seed registers a method with its one accepted payload and the verified attestation it
// yields (the gate's package-local VerifiedAttestation, so the fake -- like the gate --
// does not depend on internal/attest and the signer stays datastore-free, AN-4).
func (f *fakeAttestor) seed(method string, payload []byte, att VerifiedAttestation) {
	f.good[method] = append([]byte(nil), payload...)
	att.Method = method
	f.attByMeth[method] = att
}

func (f *fakeAttestor) VerifyEvidence(method string, payload []byte) (VerifiedAttestation, error) {
	want, ok := f.good[method]
	if !ok || !bytesEqual(want, payload) {
		return VerifiedAttestation{}, ErrAttestationInvalid
	}
	if f.log != nil {
		f.log.record("attest-verified")
	}
	return f.attByMeth[method], nil
}

// ---- misc ----

// mustRepr builds a valid agent-stack representation for binding tests.
func mustRepr(t *testing.T, prompt string, tools ...string) agentstack.Representation {
	t.Helper()
	rep, err := agentstack.New([]byte(prompt), agentstack.NewToolManifest(tools...), agentstack.Model{
		Form:            agentstack.ModelFormProviderID,
		ProviderModelID: "anthropic/claude-x",
		ModelVersion:    "2026-01-01",
	})
	if err != nil {
		t.Fatalf("agentstack.New: %v", err)
	}
	return rep
}

// fixedClock returns a clock pinned to ts (Unix seconds).
func fixedClock(ts int64) func() time.Time {
	return func() time.Time { return time.Unix(ts, 0) }
}

// jsonMarshal is a thin test helper marshaling a value to JSON (the seam carriage
// format), so tests read as encode/decode round-trips.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// hexOf renders a digest as lower-case hex (matching the revocation reader's keying).
func hexOf(b []byte) string { return hex.EncodeToString(b) }

// jsonUnmarshalImpl unmarshals JSON for the decode-side test helper.
func jsonUnmarshalImpl(b []byte, v any) error { return json.Unmarshal(b, v) }
