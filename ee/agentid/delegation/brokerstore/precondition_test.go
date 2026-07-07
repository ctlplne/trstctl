// SPDX-License-Identifier: LicenseRef-trstctl-EE

package brokerstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/delegation"
	"trstctl.com/trstctl/internal/broker"
	"trstctl.com/trstctl/internal/signing"
)

// precondition_test.go covers the AGID-07b chain-bound precondition paths that need NO
// datastore: short-TTL/no-status-query (claim 7 / INV-A7), sub-hour-on-verified-
// attestation (claim 26 / INV-A6), renewal-repeats-verification-in-signer (claim 8), and
// policy-deny-no-key-op-audit-reason (claim 14). The datastore-backed replay + idempotency
// paths (claims 9/15) live in brokerpg_test.go against real embedded PostgreSQL.
//
// The precondition drives a REAL AGID-04 gate (built via the public delegation API), an
// in-memory fake recorder standing in for the durable store, and fake policy/resolver.

// attestedRequest builds a valid narrowing chain plus a seeded verified attestation and
// returns the gate, its attestor, and the ChainBoundRequest a resolver would stage. The
// designated class + min-class make attestation REQUIRED (claim 10), which is the
// "mints only on verified attestation" property (claim 26).
func attestedRequest(t *testing.T, tenantID, method string, minClass delegation.MinClassPolicy, designatedClass string, clock func() time.Time) (*delegation.Gate, *fakeAttestor, ChainBoundRequest) {
	t.Helper()
	envs, anchors := twoHopChain(t, tenantID, openWindow(), openWindow())
	gate, att := gateWith(t, anchors, minClass, clock)
	payload := []byte("verified-evidence-" + method)
	att.seed(method, payload, delegation.VerifiedAttestation{Subject: "instance-1", Method: method})
	req := ChainBoundRequest{
		Chain:             envs,
		DesignatedClass:   designatedClass,
		Attestation:       attBody(t, method, payload),
		AttestationMethod: method,
		TrustAnchorRef:    "leaf",
	}
	return gate, att, req
}

// newPre builds a BrokerPrecondition over the gate with the supplied policy, resolver,
// recorder, audit, and clock.
func newPre(gate *delegation.Gate, pol PolicyEvaluator, res RequestResolver, rec delegation.IssuanceBindingRecorder, audit *auditRecorder, clock func() time.Time) *BrokerPrecondition {
	return NewBrokerPrecondition(Config{
		Gate: gate, Policy: pol, Resolver: res, Recorder: rec, Audit: audit, Clock: clock,
	})
}

// ---- TestCredential_ShortTTLNoStatusQuery (claim 7 / INV-A7) ----

// TestCredential_ShortTTLNoStatusQuery proves the chain-bound ephemeral credential's
// validity is <= the minimum ceiling along the chain AND < 1h, and that the lifetime is
// determinable from the credential/chain alone with NO revocation-status query (the
// SubHourCeiling derivation is a pure fold over the chain's validity windows).
func TestCredential_ShortTTLNoStatusQuery(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	clock := func() time.Time { return now }
	rootWin := delegation.Window{NotBefore: now.Unix(), NotAfter: now.Add(20 * time.Minute).Unix()}
	childWin := delegation.Window{NotBefore: now.Unix(), NotAfter: now.Add(40 * time.Minute).Unix()}
	envs, anchors := twoHopChain(t, "t1", rootWin, childWin)

	// Ceiling with NO requested TTL: the 20-minute chain minimum, and always < 1h.
	ttl, err := delegation.SubHourCeiling(envs, now, 0)
	if err != nil {
		t.Fatalf("SubHourCeiling: %v", err)
	}
	if ttl != 20*time.Minute {
		t.Fatalf("derived TTL = %s, want the 20-minute chain minimum", ttl)
	}
	if ttl >= delegation.SubHour {
		t.Fatalf("derived TTL %s is not sub-hour (claim 7 / INV-A7)", ttl)
	}
	// A request over the ceiling is refused (over-long is fail-closed).
	if _, err := delegation.SubHourCeiling(envs, now, 45*time.Minute); !errors.Is(err, delegation.ErrTTLCeilingExceeded) {
		t.Fatalf("requesting 45m over a 20m ceiling = %v, want ErrTTLCeilingExceeded", err)
	}
	// An hour+ request is refused even for an open-ended chain (hard sub-hour clamp).
	openEnvs, _ := twoHopChain(t, "t1", openWindow(), openWindow())
	if _, err := delegation.SubHourCeiling(openEnvs, now, time.Hour); !errors.Is(err, delegation.ErrTTLCeilingExceeded) {
		t.Fatalf("requesting 1h = %v, want ErrTTLCeilingExceeded (sub-hour clamp)", err)
	}
	// Open-ended chain with no request still yields a sub-hour lifetime (never unbounded).
	openTTL, err := delegation.SubHourCeiling(openEnvs, now, 0)
	if err != nil {
		t.Fatalf("open-chain ceiling: %v", err)
	}
	if openTTL <= 0 || openTTL >= delegation.SubHour {
		t.Fatalf("open-chain ceiling %s is not sub-hour", openTTL)
	}

	// End-to-end: the recorded credential's validity equals the chain minimum and is
	// sub-hour. The gate consults NeverRevoked (built into gateWith); the ceiling itself
	// queries no revocation status — validity is from the credential/chain alone.
	gate, att := gateWith(t, anchors, delegation.MinClassPolicy{"privileged": delegation.ClassHardwareTPM}, clock)
	att.seed("tpm", []byte("tpm-quote"), delegation.VerifiedAttestation{Subject: "instance-1", Method: "tpm"})
	rec := newCountingRecorder()
	pre := newPre(gate, &fakePolicy{allow: true}, staticResolver{req: ChainBoundRequest{
		Chain: envs, DesignatedClass: "privileged",
		Attestation: attBody(t, "tpm", []byte("tpm-quote")), AttestationMethod: "tpm", TrustAnchorRef: "leaf",
	}, found: true}, rec, newAuditRecorder(), clock)

	if err := pre.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-1", IdempotencyKey: "k-ttl", AttestationMethod: "tpm",
	}); err != nil {
		t.Fatalf("chain-bound issuance refused: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("recorded %d bindings, want 1", rec.count())
	}
	life := time.Duration(rec.last().NotAfter-rec.last().NotBefore) * time.Second
	if life != 20*time.Minute {
		t.Fatalf("recorded credential life = %s, want the 20-minute chain-minimum ceiling", life)
	}
	if life >= delegation.SubHour {
		t.Fatalf("recorded credential life %s is not sub-hour (INV-A7)", life)
	}
}

// ---- TestEphemeral_SubHourOnVerifiedAttestation (claim 26 / INV-A6) ----

// TestEphemeral_SubHourOnVerifiedAttestation proves the chain-bound path mints ONLY on a
// verified attestation and is refused absent it.
func TestEphemeral_SubHourOnVerifiedAttestation(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	clock := func() time.Time { return now }
	gate, _, req := attestedRequest(t, "t1", "aws_iid", delegation.MinClassPolicy{"agent": delegation.ClassVirtualTPM}, "agent", clock)

	// (a) With verified attestation: approved, one sub-hour binding with an evidence digest.
	recOK := newCountingRecorder()
	preOK := newPre(gate, &fakePolicy{allow: true}, staticResolver{req: req, found: true}, recOK, newAuditRecorder(), clock)
	if err := preOK.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-1", IdempotencyKey: "k-att-ok", AttestationMethod: "aws_iid",
	}); err != nil {
		t.Fatalf("verified-attestation issuance refused: %v", err)
	}
	if recOK.count() != 1 {
		t.Fatalf("verified attestation recorded %d bindings, want 1", recOK.count())
	}
	life := time.Duration(recOK.last().NotAfter-recOK.last().NotBefore) * time.Second
	if life <= 0 || life >= delegation.SubHour {
		t.Fatalf("minted credential life %s is not sub-hour (INV-A7)", life)
	}
	if len(recOK.last().EvidenceDigest) == 0 {
		t.Fatal("verified-attestation binding recorded no evidence digest (nothing to replay-guard)")
	}

	// (b) Attestation REMOVED: the min-class gate refuses in-signer; NO binding recorded.
	reqNo := req
	reqNo.Attestation = nil
	reqNo.AttestationMethod = ""
	recNo := newCountingRecorder()
	preNo := newPre(gate, &fakePolicy{allow: true}, staticResolver{req: reqNo, found: true}, recNo, newAuditRecorder(), clock)
	err := preNo.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-1", IdempotencyKey: "k-att-no",
	})
	if err == nil {
		t.Fatal("issuance minted WITHOUT a verified attestation (claim 26 violated)")
	}
	if !errors.Is(err, ErrSignerRefused) {
		t.Fatalf("attestation-absent refusal = %v, want ErrSignerRefused", err)
	}
	if recNo.count() != 0 {
		t.Fatalf("attestation-absent request recorded %d bindings, want 0 (no key op)", recNo.count())
	}

	// (c) FORGED evidence (payload the attestor rejects): refused, no binding.
	reqForged := req
	reqForged.Attestation = attBody(t, "aws_iid", []byte("forged-not-seeded"))
	recForged := newCountingRecorder()
	preForged := newPre(gate, &fakePolicy{allow: true}, staticResolver{req: reqForged, found: true}, recForged, newAuditRecorder(), clock)
	if err := preForged.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-1", IdempotencyKey: "k-att-forged", AttestationMethod: "aws_iid",
	}); !errors.Is(err, ErrSignerRefused) {
		t.Fatalf("forged-attestation refusal = %v, want ErrSignerRefused", err)
	}
	if recForged.count() != 0 {
		t.Fatalf("forged-attestation request recorded %d bindings, want 0", recForged.count())
	}
}

// ---- TestRenewal_RepeatsVerificationInSigner (claim 8) ----

// TestRenewal_RepeatsVerificationInSigner proves a renewal re-invokes the FULL in-signer
// verification (chain + attestation) via the AGID-04 gate before any key op: the attestor
// records a verification on every successful in-signer verify, so a first issuance + a
// renewal yields TWO verifications. It also proves the renewal re-runs the policy gate.
func TestRenewal_RepeatsVerificationInSigner(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	clock := func() time.Time { return now }
	gate, att, req := attestedRequest(t, "t1", "tpm", delegation.MinClassPolicy{"privileged": delegation.ClassHardwareTPM}, "privileged", clock)

	rec := newCountingRecorder()
	pol := &fakePolicy{allow: true}
	pre := newPre(gate, pol, staticResolver{req: req, found: true}, rec, newAuditRecorder(), clock)

	// First issuance: one in-signer verification.
	if err := pre.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-1", IdempotencyKey: "k-first", AttestationMethod: "tpm",
	}); err != nil {
		t.Fatalf("first issuance refused: %v", err)
	}
	if att.verifyCount() != 1 {
		t.Fatalf("first issuance ran %d in-signer attestation verifications, want 1", att.verifyCount())
	}

	// Renewal: re-invokes the SAME full in-signer verification (another verify), under a
	// DISTINCT idempotency key (a fresh credential).
	if err := pre.CheckRenewalPrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-1", IdempotencyKey: "k-renew", AttestationMethod: "tpm",
	}); err != nil {
		t.Fatalf("renewal refused: %v", err)
	}
	if att.verifyCount() != 2 {
		t.Fatalf("renewal ran the in-signer verification %d times total, want 2 (renewal repeats verification, claim 8)", att.verifyCount())
	}
	if rec.count() != 2 {
		t.Fatalf("renewal recorded %d bindings, want 2 (a fresh credential)", rec.count())
	}
	if !strings.HasPrefix(rec.bindings[1].CredentialID, "renew:") {
		t.Fatalf("renewal credential id = %q, want a renew: prefix (distinct fresh credential)", rec.bindings[1].CredentialID)
	}

	// A renewal under a now-DENYING policy is refused before any in-signer verify.
	pol.allow = false
	pol.reason = "renewal-blocked-by-policy"
	before := att.verifyCount()
	if err := pre.CheckRenewalPrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-1", IdempotencyKey: "k-renew-denied", AttestationMethod: "tpm",
	}); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("policy-denied renewal = %v, want ErrPolicyDenied", err)
	}
	if att.verifyCount() != before {
		t.Fatal("policy-denied renewal still ran an in-signer verification (policy must gate first)")
	}
	if rec.count() != 2 {
		t.Fatalf("policy-denied renewal recorded a binding (count now %d, want 2)", rec.count())
	}
}

// ---- TestPolicyGate_DenyNoKeyOpAuditReason (claim 14) ----

// TestPolicyGate_DenyNoKeyOpAuditReason proves a policy-denied chain-bound issuance
// performs NO key op (no in-signer verify, no binding) and emits an audit event carrying
// the denial reason.
func TestPolicyGate_DenyNoKeyOpAuditReason(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	clock := func() time.Time { return now }
	gate, att, req := attestedRequest(t, "t1", "tpm", delegation.MinClassPolicy{"privileged": delegation.ClassHardwareTPM}, "privileged", clock)

	const reason = "scope read:secrets not permitted for this agent"
	audit := newAuditRecorder()
	rec := newCountingRecorder()
	pre := newPre(gate, &fakePolicy{allow: false, reason: reason}, staticResolver{req: req, found: true}, rec, audit, clock)

	err := pre.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-deny", IdempotencyKey: "k-deny", AttestationMethod: "tpm",
	})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("policy-denied issuance = %v, want ErrPolicyDenied", err)
	}
	// No key op: no in-signer verification and no binding.
	if att.verifyCount() != 0 {
		t.Fatalf("policy-denied issuance ran %d in-signer verifications, want 0 (no key op before deny)", att.verifyCount())
	}
	if rec.count() != 0 {
		t.Fatalf("policy-denied issuance recorded %d bindings, want 0 (no key op)", rec.count())
	}
	// An audit event carrying the denial reason was emitted.
	ev, ok := audit.find("agent.identity.refused")
	if !ok {
		t.Fatal("policy-denied issuance emitted no agent.identity.refused audit event (claim 14)")
	}
	if !strings.Contains(string(ev.data), reason) {
		t.Fatalf("audit event data %q does not carry the denial reason %q (claim 14)", ev.data, reason)
	}
	if ev.tenantID != "t1" {
		t.Fatalf("audit event tenant = %q, want t1 (AN-1/AN-2)", ev.tenantID)
	}
}

type signerResultGate struct {
	req signing.IssuancePreconditions
}

func (g *signerResultGate) VerifyIssuancePreconditions(_ context.Context, req signing.IssuancePreconditions) (signing.IssuanceDecision, error) {
	g.req = req
	bm, err := delegation.NewBindingMaterial([]byte("chain-head"), req.SubjectRepr, "agent", []byte("attestation"), "auth-ref", nil)
	if err != nil {
		return signing.IssuanceDecision{}, err
	}
	encoded, err := bm.Encode()
	if err != nil {
		return signing.IssuanceDecision{}, err
	}
	return signing.IssuanceDecision{
		Approved:        true,
		BindingMaterial: encoded,
		EncodedRecord:   []byte("signer-cert-der"),
	}, nil
}

// TestSignerResultCarriesSubHourValidityAndCredential proves the production signer
// transport shape: the precondition derives the exact sub-hour validity before calling the
// signer, passes that window into the gate/key-op request, records the binding, and returns
// the signer's public credential result to the core broker.
func TestSignerResultCarriesSubHourValidityAndCredential(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	clock := func() time.Time { return now }
	gate := &signerResultGate{}
	rec := newCountingRecorder()
	pre := NewBrokerPrecondition(Config{
		Gate:     gate,
		Policy:   &fakePolicy{allow: true},
		Resolver: staticResolver{req: ChainBoundRequest{SubjectRepr: []byte("agent-stack"), RequestedTTL: 20 * time.Minute, TrustAnchorRef: "root-key"}, found: true},
		Recorder: rec,
		Clock:    clock,
	})

	result, err := pre.CheckIssuancePreconditionResult(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-1", IdempotencyKey: "k-signer-result", AttestationMethod: "tpm",
	})
	if err != nil {
		t.Fatalf("CheckIssuancePreconditionResult: %v", err)
	}
	if string(result.CertDER) != "signer-cert-der" {
		t.Fatalf("signer result cert = %q", result.CertDER)
	}
	if !result.NotAfter.Equal(now.Add(20 * time.Minute)) {
		t.Fatalf("result NotAfter = %s, want %s", result.NotAfter, now.Add(20*time.Minute))
	}
	if gate.req.NotBefore != now.Unix() || gate.req.NotAfter != now.Add(20*time.Minute).Unix() {
		t.Fatalf("signer validity window = %d..%d, want %d..%d", gate.req.NotBefore, gate.req.NotAfter, now.Unix(), now.Add(20*time.Minute).Unix())
	}
	if rec.count() != 1 {
		t.Fatalf("recorded %d bindings, want 1", rec.count())
	}
	if rec.last().CredentialID != result.CredentialID {
		t.Fatalf("recorded credential id %q != result %q", rec.last().CredentialID, result.CredentialID)
	}
}

// ---- fail-closed default (the AGID-07a stub replacement) ----

// TestBrokerPrecondition_FailClosedByDefault proves the fail-closed default form (what the
// AGID activation block attaches before AGID-INT-WIRE provisions the substrate) refuses
// every chain-bound request — replacing the AGID-07a placeholder's refuse-all stance with
// the real type in its unprovisioned state (INV-A1).
func TestBrokerPrecondition_FailClosedByDefault(t *testing.T) {
	pre := NewFailClosedBrokerPrecondition()
	err := pre.CheckIssuancePrecondition(context.Background(), broker.IssuanceView{
		TenantID: "t1", AgentID: "agent-x", IdempotencyKey: "k-fc",
	})
	if err == nil {
		t.Fatal("fail-closed default APPROVED a chain-bound request (must refuse)")
	}
	if !errors.Is(err, ErrNoRequestContext) {
		t.Fatalf("fail-closed default refusal = %v, want ErrNoRequestContext", err)
	}
}
