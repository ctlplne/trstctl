// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package conformance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	eereconcile "trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/canon"
	xrecplan "trstctl.com/trstctl/internal/reconcile/plan"
	"trstctl.com/trstctl/internal/reconcile/plan/remediation"
	"trstctl.com/trstctl/internal/reconcile/quarantine"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

// TestE2E_StoreBackedAuthoritiesRoundToWitness is the C4 acceptance run
// end-to-end on the PRODUCTION assembly: two store-backed authorities seeded
// with divergent durable state, the shipped runtime's rounds worker observing
// both through the real reducers, digests signed in the real isolated signer,
// the disagreement witnessed into the event ledger naming EXACTLY the
// differing subset, the witness verified offline from the durable event alone,
// quarantine admission updated, and remediation of the conflict authorized
// only after in-signer plan verification (XREC-claims-1, 16).
//
// The other e2e test in this package hand-builds its planes and hand-calls the
// witness pipeline; that proves the pieces. This test proves the BINARY's own
// path exercises them: nothing here below the seed data and the schedule is
// test code.
func TestE2E_StoreBackedAuthoritiesRoundToWitness(t *testing.T) {
	h := newE2EHarness(t)

	// Two independent record sets from state the platform already keeps:
	//   inventory (trstctl-self): A active, B active, C active, E (foreign CA)
	//   CA ledger (trstctl-ca):   A active, B REVOKED, D active
	// Differing subset: {B attribute conflict, C inventory-only, D ledger-only}.
	// A agrees; E is outside the internal-CA jurisdiction and must not appear.
	caKey, caCert := e2eStoreCA(t, "trstctl e2e internal CA")
	foreignKey, foreignCert := e2eStoreCA(t, "e2e foreign root")

	serialA, serialB, serialC := big.NewInt(0x0a01), big.NewInt(0x0b02), big.NewInt(0x0c03)
	serialD, serialE := big.NewInt(0x0dd4), big.NewInt(0x0e05)
	leafA := e2eStoreLeaf(t, caCert, caKey, serialA, "a.internal.example")
	leafB := e2eStoreLeaf(t, caCert, caKey, serialB, "b.internal.example")
	leafC := e2eStoreLeaf(t, caCert, caKey, serialC, "c.internal.example")
	leafE := e2eStoreLeaf(t, foreignCert, foreignKey, serialE, "e.foreign.example")

	ca, err := h.store.InsertCAAuthority(h.ctx, corestore.CAAuthority{
		TenantID:   h.tenant,
		CommonName: "trstctl e2e internal CA",
		Kind:       "root",
		Status:     "active",
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: caCert.Raw,
		})),
		Serial:     "1",
		MaxPathLen: -1,
	})
	if err != nil {
		t.Fatalf("InsertCAAuthority: %v", err)
	}
	for _, leaf := range []struct {
		der []byte
		cn  string
	}{
		{leafA, "a.internal.example"}, {leafB, "b.internal.example"},
		{leafC, "c.internal.example"}, {leafE, "e.foreign.example"},
	} {
		if _, err := h.store.UpsertCertificate(h.ctx, corestore.Certificate{
			TenantID:       h.tenant,
			Subject:        "CN=" + leaf.cn,
			Fingerprint:    crypto.SHA256Hex(leaf.der),
			CertificateDER: leaf.der,
			Source:         "e2e-seed",
		}); err != nil {
			t.Fatalf("UpsertCertificate(%s): %v", leaf.cn, err)
		}
	}
	now := time.Now().UTC()
	for _, serial := range []*big.Int{serialA, serialB, serialD} {
		if err := h.store.RecordIssuedCert(h.ctx, h.tenant, ca.ID, serial.Text(16), now); err != nil {
			t.Fatalf("RecordIssuedCert(%s): %v", serial.Text(16), err)
		}
	}
	if err := h.store.RevokeIssuedCert(h.ctx, h.tenant, ca.ID, serialB.Text(16), 1, now); err != nil {
		t.Fatalf("RevokeIssuedCert(B): %v", err)
	}

	// The production assembly: NewRuntime with the same wiring the attach seam
	// uses, plus a schedule comparing the two store-backed authorities.
	rt, err := eereconcile.NewRuntime(eereconcile.RuntimeConfig{
		Store:       h.store,
		Log:         h.log,
		Idempotency: orchestrator.NewIdempotency(h.store),
		Signer:      e2eSignerProvider{client: h.client},
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Schedules: []rounds.Config{{
			TenantID: h.tenant,
			Cadence:  200 * time.Millisecond,
			Liveness: time.Hour,
			Planes: []rounds.PlaneConfig{
				{AuthorityID: "trstctl-self", Liveness: time.Hour},
				{AuthorityID: "trstctl-ca", Liveness: time.Hour},
			},
		}},
		RoundInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if len(rt.BackgroundWorkers) != 1 {
		t.Fatalf("background workers = %d, want the rounds worker", len(rt.BackgroundWorkers))
	}
	workerCtx, cancel := context.WithCancel(h.ctx)
	done := make(chan error, 1)
	go func() { done <- rt.BackgroundWorkers[0].Run(workerCtx) }()
	deadline := time.Now().Add(60 * time.Second)
	for countEventsOfType(t, h.log, witness.EventTypeWitnessRecorded) == 0 {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("no witness recorded within 60s: the scheduled round never turned the seeded " +
				"divergence into ledger evidence")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	recorded := firstWitnessRecorded(t, h.log)

	// Claim 1's heart: the witness identifies EXACTLY the differing subset.
	stableB := e2eStableID(t, caCert, serialB)
	stableC := e2eStableID(t, caCert, serialC)
	stableD := e2eStableID(t, caCert, serialD)
	stableE := e2eStableID(t, foreignCert, serialE)
	entries := recorded.Evidence.Body.Entries
	if len(entries) != 3 {
		t.Fatalf("witness entries = %d (%+v), want exactly 3: the conflict, the inventory-only "+
			"cert and the ledger-only serial. More means agreeing or out-of-jurisdiction records "+
			"were reported as drift; fewer means real drift went unnamed.", len(entries), entries)
	}
	byStableID := map[string]witness.Entry{}
	for _, entry := range entries {
		byStableID[entry.RecordKey.StableID] = entry
	}
	if entry, ok := byStableID[stableB]; !ok || entry.Class != witness.ClassAttributeConflict {
		t.Fatalf("B (ledger-revoked, inventory-active) = %+v, want attribute_conflict", entry)
	}
	if entry, ok := byStableID[stableC]; !ok || entry.Class != witness.ClassPresence || entry.PresentAuthority != "trstctl-self" {
		t.Fatalf("C (inventory-only) = %+v, want presence held by trstctl-self", entry)
	}
	if entry, ok := byStableID[stableD]; !ok || entry.Class != witness.ClassPresence || entry.PresentAuthority != "trstctl-ca" {
		t.Fatalf("D (ledger-only) = %+v, want presence held by trstctl-ca", entry)
	}
	if _, ok := byStableID[stableE]; ok {
		t.Fatal("foreign-CA certificate appeared in the witness; the ledger never claimed that " +
			"jurisdiction, so reporting it is a false alarm")
	}

	// Offline verification from the durable event ALONE: evidence plus the
	// signed digests it references, verified with no callback to either
	// authority (XREC-claim-15).
	if len(recorded.Digests) != 2 {
		t.Fatalf("recorded digests = %d, want both planes' signed digests on the event", len(recorded.Digests))
	}
	digestTrust := map[string]crypto.PublicKey{}
	for _, sd := range recorded.Digests {
		digestTrust[sd.KeyID] = crypto.PublicKey{Algorithm: sd.Algorithm, DER: append([]byte(nil), sd.PublicKeyDER...)}
	}
	witnessTrust := map[string]crypto.PublicKey{}
	for _, sig := range recorded.Evidence.Signatures {
		witnessTrust[sig.KeyID] = crypto.PublicKey{Algorithm: sig.Algorithm, DER: append([]byte(nil), sig.PublicKeyDER...)}
	}
	if err := witness.VerifyOffline(witness.OfflineVerifyRequest{
		Evidence:           recorded.Evidence,
		Digests:            recorded.Digests,
		TrustedDigestKeys:  digestTrust,
		TrustedWitnessKeys: witnessTrust,
	}); err != nil {
		t.Fatalf("VerifyOffline from the recorded event: %v", err)
	}

	// The attribute conflict on an x509 record entered quarantine through the
	// runtime's own admission path (ReferencePolicy).
	if n := countEventsOfType(t, h.log, quarantine.EventTypeEntered); n == 0 {
		t.Fatal("no quarantine entry recorded; the runtime observed the witness but admission never moved")
	}

	// Remediation of the conflict is gated on IN-SIGNER plan verification: the
	// signed plan binds the witness hash, the real signer verifies it against
	// the recorded evidence, and only that decision authorizes the connector.
	action := xrecplan.Action{
		AuthorityID: "trstctl-self",
		RecordKey:   canon.RecordKey{TenantID: h.tenant, RecordType: canon.RecordTypeX509Certificate, StableID: stableB},
		Operation:   e2eOperation,
	}
	plan := xrecplan.Plan{
		PlanID:      "storebacked-plan-" + recorded.WitnessID,
		TenantID:    h.tenant,
		WitnessID:   recorded.Evidence.Body.WitnessID,
		WitnessHash: recorded.Evidence.ContentHash(),
		Actions:     []xrecplan.Action{action},
		GeneratedAt: time.Now().UTC().Unix(),
	}
	signedPlan, err := xrecplan.Sign(h.ctx, h.planKey, plan, e2ePlanAuthority, e2ePlanKeyID, plan.GeneratedAt)
	if err != nil {
		t.Fatalf("plan.Sign: %v", err)
	}
	preconditions, err := xrecplan.EncodeSignedPlan(signedPlan)
	if err != nil {
		t.Fatalf("EncodeSignedPlan: %v", err)
	}
	envelope, err := xrecplan.EncodeVerificationEnvelope(xrecplan.VerificationEnvelope{Recorded: recorded})
	if err != nil {
		t.Fatalf("EncodeVerificationEnvelope: %v", err)
	}
	decision, err := h.client.VerifyOperation(h.ctx, signing.OperationRequest{
		TenantID:       h.tenant,
		Operation:      e2eOperation,
		SubjectRef:     xrecplan.RecordKeyRef(action.RecordKey),
		IdempotencyKey: "storebacked-plan:" + recorded.WitnessID,
		Preconditions:  preconditions,
		Evidence:       envelope,
	})
	if err != nil {
		t.Fatalf("VerifyOperation(real signer): %v", err)
	}
	if !decision.Approved {
		t.Fatalf("plan refused by real signer: %s", string(decision.RefusalRecord))
	}
	if _, err := h.remediationMgr.Authorize(h.ctx, remediation.AuthorizationRequest{
		TenantID:   h.tenant,
		SignedPlan: signedPlan,
		Action:     action,
		Decision:   decision,
	}); err != nil {
		t.Fatalf("remediation.Authorize: %v", err)
	}
	connector := newE2EConnector("trstctl-self")
	registry := remediation.NewRegistry(remediation.NewStoreReceiptRecorder(h.store))
	registry.Register(connector)
	handler := remediation.NewHandler(registry)
	for i := 0; i < 10 && connector.Count() == 0; i++ {
		if _, err := h.outbox.Dispatch(h.ctx, handler); err != nil {
			t.Fatalf("outbox Dispatch: %v", err)
		}
	}
	if connector.Count() != 1 {
		t.Fatalf("remediation executions = %d, want exactly 1 signer-authorized execution", connector.Count())
	}

	// The drift projection — the served agreement surface's data — rebuilds
	// from the ledger events the round produced.
	if err := replayInto(t, h.log, rt.DriftProjection); err != nil {
		t.Fatalf("drift replay: %v", err)
	}
	snap := rt.DriftProjection.Snapshot()
	if snap.OpenWitnesses == 0 {
		t.Fatal("drift snapshot shows zero open witnesses after a witnessed round")
	}
	var presence, conflicts int64
	for _, count := range snap.WitnessClassCounts {
		switch count.Class {
		case witness.ClassPresence:
			presence += count.Count
		case witness.ClassAttributeConflict:
			conflicts += count.Count
		}
	}
	if presence == 0 || conflicts == 0 {
		t.Fatalf("drift counts presence=%d conflicts=%d; the served surface must show both classes", presence, conflicts)
	}
}

type e2eSignerProvider struct {
	client *signing.Client
}

func (p e2eSignerProvider) Client() *signing.Client { return p.client }

func firstWitnessRecorded(t *testing.T, log interface {
	Replay(context.Context, uint64, func(eventspec.Event) error) error
}) witness.WitnessRecorded {
	t.Helper()
	var out witness.WitnessRecorded
	found := false
	if err := log.Replay(context.Background(), 1, func(ev eventspec.Event) error {
		if !found && ev.Type == witness.EventTypeWitnessRecorded {
			decodeConformanceEvent(t, ev, &out)
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !found {
		t.Fatal("no witness recorded event in the ledger")
	}
	return out
}

func replayInto(t *testing.T, log interface {
	Replay(context.Context, uint64, func(eventspec.Event) error) error
}, drift *rounds.DriftProjection) error {
	t.Helper()
	return log.Replay(context.Background(), 1, func(ev eventspec.Event) error {
		return drift.Apply(ev)
	})
}

func e2eStableID(t *testing.T, issuer *x509.Certificate, serial *big.Int) string {
	t.Helper()
	id, err := canon.X509StableID(issuer.RawSubject, serial.Text(16))
	if err != nil {
		t.Fatalf("X509StableID: %v", err)
	}
	return id
}

func e2eStoreKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func e2eStoreCA(t *testing.T, commonName string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := e2eStoreKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA %s: %v", commonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA %s: %v", commonName, err)
	}
	return key, cert
}

func e2eStoreLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial *big.Int, cn string) []byte {
	t.Helper()
	leafKey := e2eStoreKey(t)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issue leaf %s: %v", cn, err)
	}
	return der
}
