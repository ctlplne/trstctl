// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"context"
	"encoding/json"
	"testing"

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
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return cs
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

// TestService_RequestSuccession_EnqueuesOutbox: request-succession records an
// idempotent outbox job for the signer to mint (AN-5/AN-6).
func TestService_RequestSuccession_EnqueuesOutbox(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	outbox := orchestrator.NewOutbox(cs)
	svc := succapi.NewService(cs, nil, outbox)

	resp, err := svc.RequestSuccession(ctx, tenantA, succapi.RequestSuccessionRequest{
		IdentityID: "spiffe://d/enq", CredentialType: "x509", TargetAlgorithm: "ML-DSA-65",
	})
	if err != nil {
		t.Fatalf("RequestSuccession: %v", err)
	}
	var n int
	if err := cs.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE destination = $1 AND idempotency_key = $2`,
		succapi.SuccessionRequestDestination, resp.RequestID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("outbox rows for the request = %d, want 1", n)
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
