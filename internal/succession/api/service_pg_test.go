// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
	"trstctl.com/trstctl/internal/succession/retirement"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

func openStorePCAS(t *testing.T) *corestore.Store {
	t.Helper()
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	t.Cleanup(cs.Close)
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return cs
}

func TestService_RegisterIssuerRefusesUnavailableCustodyBeforePersist(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	caDER, err := crypto.SelfSignedCACert(signer, "qa issuer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc := succapi.NewService(cs, nil, nil)
	const issuerID = "qa-unbound-issuer"
	if _, err := cs.InsertCAAuthority(ctx, corestore.CAAuthority{
		TenantID: tenantA, CommonName: "qa issuer", Kind: "root", Serial: "qa-issuer-serial",
		CertificatePEM: string(crypto.EncodeCertificatePEM(caDER)), SignerHandle: "missing-signer-handle",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterIssuerAuthority(ctx, tenantA, succapi.IssuerAuthorityRequest{
		IssuerID: issuerID, IdentityID: "spiffe://qa.local/unbound-ca", CurrentEpoch: 1,
		CAKeyHandle: "missing-signer-handle", CACertDER: caDER,
	}); err == nil {
		t.Fatal("issuer registration accepted a key handle with no isolated signer custody")
	}
	if _, found, err := pcasstore.New(cs).GetIssuerAuthority(ctx, tenantA, issuerID); err != nil || found {
		t.Fatalf("refused issuer persisted: found=%t err=%v", found, err)
	}
}

func TestService_IssuerLeafRefusesSupersededManagedCA(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	caDER, err := crypto.SelfSignedCACert(signer, "retired QA CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const handle = "qa-superseded-ca-handle"
	if _, err := cs.InsertCAAuthority(ctx, corestore.CAAuthority{
		TenantID: tenantA, CommonName: "retired QA CA", Kind: "root", Status: "superseded",
		Serial: "qa-superseded-serial", CertificatePEM: string(crypto.EncodeCertificatePEM(caDER)),
		SignerHandle: handle,
	}); err != nil {
		t.Fatal(err)
	}
	const issuerID = "qa-superseded-pcas-issuer"
	if err := pcasstore.New(cs).UpsertIssuerAuthority(ctx, tenantA, pcasstore.IssuerAuthority{
		IssuerID: issuerID, IdentityID: "spiffe://qa.local/superseded-ca", CurrentEpoch: 0,
		CAKeyHandle: handle, CACertDER: caDER,
	}); err != nil {
		t.Fatal(err)
	}
	svc := succapi.NewService(cs, nil, nil)
	if _, err := svc.IssueIssuerLeaf(ctx, tenantA, succapi.IssueLeafRequest{IssuerID: issuerID}); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("superseded CA issuer request = %v, want authority refusal before signer", err)
	}
}

// A retirement policy must target the key the tenant's signer actually minted.
// A blank operator handle cannot silently select the old unscoped test handle,
// and an explicit handle cannot name another tenant's signer key.
func TestConfigureRetirementPolicyBindsTenantPredecessorHandle(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	svc := succapi.NewService(cs, nil, nil)
	rpKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := json.Marshal([]map[string]any{{"relying_party": "rp1", "public_der": rpKey.Public().DER}})
	if err != nil {
		t.Fatal(err)
	}
	id := "spiffe://d/retirement-bound"
	req := succapi.RetirementPolicyRequest{IdentityID: id, PredecessorEpoch: 0,
		Threshold: 1, Roster: roster, ValidityWindowSeconds: 3600}
	want := succession.TenantKeyHandle(tenantA, id, 0)
	got, err := svc.ConfigureRetirementPolicy(ctx, tenantA, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.PredecessorHandle != want {
		t.Fatalf("policy targeted %q; tenant-bound predecessor is %q", got.PredecessorHandle, want)
	}
	stored, found, err := svc.RetirementStatus(ctx, tenantA, id, 0)
	if err != nil || !found || stored.PredecessorHandle != want {
		t.Fatalf("stored policy handle = %q, found=%t, err=%v; want %q", stored.PredecessorHandle, found, err, want)
	}
	req.PredecessorHandle = succession.TenantKeyHandle("22222222-2222-4222-8222-222222222222", id, 0)
	if _, err := svc.ConfigureRetirementPolicy(ctx, tenantA, req); err == nil {
		t.Fatal("another tenant's predecessor handle was accepted")
	}
}

// TestService_FetchChain_Verifiable: the concrete service reads the RLS store and
// returns a chain that verifies offline (PCAS-07) — acceptance 2.
func TestService_FetchChain_Verifiable(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	repo := pcasstore.New(cs)
	id := "spiffe://d/fetch"

	sc, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "spiffe://d", id, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range sc.Records {
		enc, _ := json.Marshal(rec)
		if err := repo.AppendRecord(ctx, tenantA, pcasstore.Record{
			IdentityID: id, Epoch: rec.Fields.Epoch, PredecessorEpoch: rec.Fields.PredecessorEpoch,
			PredecessorAlg: string(rec.Fields.PredecessorAlg), SuccessorAlg: string(rec.Fields.SuccessorAlg),
			SuccessorPub: rec.Fields.SuccessorPub, Encoded: enc,
		}); err != nil {
			t.Fatalf("seed record: %v", err)
		}
	}

	svc := succapi.NewService(cs, nil, nil)
	resp, err := svc.FetchChain(ctx, tenantA, id)
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if resp.Count != len(sc.Records) {
		t.Fatalf("count = %d, want %d", resp.Count, len(sc.Records))
	}
	var records []succession.SuccessionRecord
	for _, b := range resp.Records {
		var rec succession.SuccessionRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatal(err)
		}
		records = append(records, rec)
	}
	if err := succession.VerifyChain(sc.Genesis, records, 0); err != nil {
		t.Fatalf("chain from store does not verify: %v", err)
	}
}

// A new identity cannot receive a misleading queued response until the
// operator has registered and verified its signer-held genesis.
func TestService_RequestSuccession_RefusesMissingGenesis(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	outbox := orchestrator.NewOutbox(cs)
	svc := succapi.NewService(cs, nil, outbox)

	_, err := svc.RequestSuccession(ctx, tenantA, succapi.RequestSuccessionRequest{
		IdentityID: "spiffe://d/enq", CredentialType: "x509", TargetAlgorithm: "ML-DSA-65",
	})
	if err == nil || !strings.Contains(err.Error(), "registered genesis") {
		t.Fatalf("missing genesis: %v", err)
	}
	var n int
	if err := cs.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE destination = $1`,
		succapi.SuccessionRequestDestination).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("outbox rows for unregistered identity = %d, want 0", n)
	}
}

func TestService_RequestRecoveryRefusesMissingOrMismatchedPolicyBeforeOutbox(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	outbox := orchestrator.NewOutbox(cs)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	svc := succapi.NewService(cs, log, outbox)
	root, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	approver, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	const id = "spiffe://d/recovery-policy-bound"
	request := succapi.RecoveryRequest{IdentityID: id, TargetAlgorithm: "ECDSA-P256",
		SuccessorHandle: "qa-recovery-successor", Epoch: 2,
		TrustRootDER: root.Public().DER, Authorization: json.RawMessage(`{}`)}
	if _, err := svc.RequestRecovery(ctx, tenantA, request); err == nil || !strings.Contains(err.Error(), "recovery policy") {
		t.Fatalf("missing recovery policy request = %v, want refusal before outbox", err)
	}
	roster, err := json.Marshal([]map[string]any{{"ID": "custodian-1", "PubDER": approver.Public().DER}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfigureRecoveryPolicy(ctx, tenantA, succapi.RecoveryPolicyRequest{
		IdentityID: id, Threshold: 1, Roster: roster, TrustRootDER: root.Public().DER,
	}); err != nil {
		t.Fatal(err)
	}
	request.TrustRootDER = otherRoot.Public().DER
	if _, err := svc.RequestRecovery(ctx, tenantA, request); err == nil || !strings.Contains(err.Error(), "trust root") {
		t.Fatalf("mismatched recovery trust root request = %v, want refusal before outbox", err)
	}
	request.TrustRootDER = root.Public().DER
	if _, err := svc.RequestRecovery(ctx, "22222222-2222-4222-8222-222222222222", request); err == nil || !strings.Contains(err.Error(), "recovery policy") {
		t.Fatalf("another tenant's recovery policy request = %v, want refusal before outbox", err)
	}
	request.Authorization, err = json.Marshal(map[string]any{
		"Threshold": 1, "Roster": []map[string]any{{"ID": "wrong-custodian", "PubDER": approver.Public().DER}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestRecovery(ctx, tenantA, request); err == nil || !strings.Contains(err.Error(), "roster") {
		t.Fatalf("mismatched recovery roster request = %v, want refusal before outbox", err)
	}
	request.Authorization, err = json.Marshal(map[string]any{
		"Threshold": 1, "Roster": []map[string]any{{"ID": "custodian-1", "PubDER": approver.Public().DER}},
		"Statement": map[string]any{"DeploymentScope": "", "IdentityID": id, "TenantID": tenantA,
			"Epoch": 2, "SuccessorAlg": "ECDSA-P256", "SuccessorPub": approver.Public().DER},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequestRecovery(ctx, tenantA, request); err == nil || !strings.Contains(err.Error(), "signatures") {
		t.Fatalf("unsigned recovery request = %v, want refusal before outbox", err)
	}
	var n int
	if err := cs.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE destination = $1`,
		succapi.RecoveryRequestDestination).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("recovery outbox rows after refused requests = %d, want 0", n)
	}
}

func TestService_RecoveryPolicyAppendsPublicEventBeforeServing(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	cs := openStorePCAS(t)
	svc := succapi.NewService(cs, log, nil)
	root, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	member, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := json.Marshal([]map[string]any{{"ID": "custodian-1", "PubDER": member.Public().DER}})
	if err != nil {
		t.Fatal(err)
	}
	const id = "spiffe://d/recovery-event-source"
	command := succapi.RecoveryPolicyRequest{
		IdentityID: id, Threshold: 1, Roster: roster, TrustRootDER: root.Public().DER,
		OperationID: "qa-recovery-policy-lost-response",
	}
	if _, err := svc.ConfigureRecoveryPolicy(ctx, tenantA, command); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfigureRecoveryPolicy(ctx, tenantA, command); err != nil {
		t.Fatalf("retry of same operation after event append: %v", err)
	}
	differentRoot, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	conflict := command
	conflict.TrustRootDER = differentRoot.Public().DER
	if _, err := svc.ConfigureRecoveryPolicy(ctx, tenantA, conflict); err == nil {
		t.Fatal("changed payload reused the recovery-policy idempotency key")
	}
	if _, err := svc.ConfigureRecoveryPolicy(ctx, tenantA, command); err != nil {
		t.Fatal(err)
	}
	var found bool
	var first events.Event
	var eventCount int
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type == "nhi.recovery.policy.configured" && ev.TenantID == tenantA {
			eventCount++
			first = ev
			var payload struct {
				IdentityID string `json:"identity_id"`
				Threshold  int    `json:"threshold"`
			}
			if err := json.Unmarshal(ev.Data, &payload); err != nil {
				return err
			}
			found = payload.IdentityID == id && payload.Threshold == 1
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("recovery policy was served without an immutable tenant-bound event")
	}
	if eventCount != 1 {
		t.Fatalf("same operation emitted %d policy events, want one", eventCount)
	}
	proj := pcasstore.NewRecoveryPolicyProjection(cs)
	if err := proj.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, err := pcasstore.New(cs).GetRecoveryPolicy(ctx, tenantA, id); err != nil || found {
		t.Fatalf("policy after projection reset: found=%t err=%v", found, err)
	}
	if err := log.Replay(ctx, 0, func(ev events.Event) error { return proj.Apply(ctx, ev) }); err != nil {
		t.Fatal(err)
	}
	got, found, err := pcasstore.New(cs).GetRecoveryPolicy(ctx, tenantA, id)
	if err != nil || !found || got.Threshold != 1 || string(got.TrustRootDER) != string(root.Public().DER) {
		t.Fatalf("policy after event replay: found=%t threshold=%d err=%v", found, got.Threshold, err)
	}
	newRoot, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfigureRecoveryPolicy(ctx, tenantA, succapi.RecoveryPolicyRequest{
		IdentityID: id, Threshold: 1, Roster: roster, TrustRootDER: newRoot.Public().DER,
	}); err != nil {
		t.Fatal(err)
	}
	if err := proj.Apply(ctx, first); err != nil {
		t.Fatal(err)
	}
	got, found, err = pcasstore.New(cs).GetRecoveryPolicy(ctx, tenantA, id)
	if err != nil || !found || string(got.TrustRootDER) != string(newRoot.Public().DER) {
		t.Fatalf("delayed predecessor replaced newer policy: found=%t err=%v", found, err)
	}
}

// TestService_RecordAck_LedgerCountable: the concrete service appends a signed ack to
// the AN-2 ledger and the PCAS-10 quorum counts the ledger-sourced ack (acceptance 3).
// Skipped if an embedded event log cannot start in this environment.
func TestService_RecordAck_LedgerCountable(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Skipf("embedded event log unavailable: %v", err)
	}
	defer func() { _ = log.Close() }()

	cs := openStorePCAS(t)
	svc := succapi.NewService(cs, log, nil)
	rpKey, _ := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	id := "spiffe://d/ackledger"

	// The service stores whatever signature it is given; a real RP signs the
	// canonical ack message so the recorded event is countable.
	sig, err := retirement.SignAck(rpKey, tenantA, id, 1, "rp1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecordAck(ctx, tenantA, succapi.AckRequest{IdentityID: id, Epoch: 1, RelyingParty: "rp1", Signature: sig}); err != nil {
		t.Fatalf("RecordAck: %v", err)
	}

	// Replay the ledger and confirm the ack decodes as a valid RPAckV1.
	var found bool
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type != succession.TypeRPAck {
			return nil
		}
		p, derr := succession.Decode(e)
		if derr != nil {
			return derr
		}
		if ack, ok := p.(succession.RPAckV1); ok && ack.IdentityID == id && ack.Epoch == 1 && ack.RelyingParty == "rp1" && len(ack.AckSignature) > 0 {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !found {
		t.Fatal("recorded ack not found on the ledger as a well-formed RPAckV1")
	}
}
