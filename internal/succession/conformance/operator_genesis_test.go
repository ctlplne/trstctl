// SPDX-License-Identifier: BUSL-1.1

package conformance

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
	"trstctl.com/trstctl/internal/succession/minter"
	pcasorch "trstctl.com/trstctl/internal/succession/orchestrator"
)

// A fresh operator identity must become a usable PCAS chain without a test
// reaching around the product to call signer.GenerateKeyHandle directly.
func TestOperatorGenesisThenSuccessionThroughOutbox(t *testing.T) {
	st := startINT20Stack(t)
	const id = "spiffe://operator.example/workload/shared"
	actorCtx := events.ContextWithActor(st.ctx, events.Actor{Subject: "operator-genesis", Roles: []string{"key-custodian"}})
	registered, err := st.svc.RegisterGenesis(actorCtx, st.tenantID, succapi.GenesisRegistrationRequest{
		IdentityID: id, Algorithm: string(crypto.ECDSAP256), DeploymentScope: "spiffe://operator.example",
	})
	if err != nil || registered.Status != "queued" || registered.RequestID == "" {
		t.Fatalf("register genesis: %+v, %v", registered, err)
	}
	st.dispatchAll(t)
	var attributed int
	if err := st.log.Replay(st.ctx, 0, func(ev events.Event) error {
		if ev.Type == succession.TypeGenesis && ev.TenantID == st.tenantID {
			if ev.Actor == nil || ev.Actor.Subject != "operator-genesis" {
				t.Fatalf("genesis event lost the authenticated actor: %+v", ev.Actor)
			}
			attributed++
		}
		return nil
	}); err != nil || attributed != 1 {
		t.Fatalf("genesis audit event count=%d error=%v, want one", attributed, err)
	}
	first, err := st.svc.FetchChain(st.ctx, st.tenantID, id)
	if err != nil || first.Genesis == nil || len(first.TrustRootPublicDER) == 0 {
		t.Fatalf("genesis readback: %+v, %v", first, err)
	}
	if err := succession.VerifyGenesis(first.TrustRootPublicDER, *first.Genesis); err != nil {
		t.Fatalf("operator genesis is not independently verifiable: %v", err)
	}
	if _, err := st.svc.RequestSuccession(st.ctx, st.tenantID, succapi.RequestSuccessionRequest{
		IdentityID: id, CredentialType: "workload-svid", TargetAlgorithm: string(crypto.ECDSAP384),
		PolicyRef: "policy:operator", DeploymentScope: "spiffe://operator.example",
	}); err != nil {
		t.Fatalf("request succession: %v", err)
	}
	st.dispatchAll(t)
	chain, err := st.svc.FetchChain(st.ctx, st.tenantID, id)
	if err != nil || chain.Count != 1 || chain.Genesis == nil {
		t.Fatalf("succession readback: %+v, %v", chain, err)
	}
	decoded, err := minter.DecodeRecord(chain.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := succession.VerifyChain(*chain.Genesis, []succession.SuccessionRecord{decoded}, 0); err != nil {
		t.Fatalf("served chain does not anchor to operator genesis: %v", err)
	}
}

// Simulate a crash after the event append and before the read-model insert.
// A retry outside JetStream's finite duplicate window must retain exactly one
// logical genesis meaning, with the original queued timestamp and signature.
func TestOperatorGenesisRepairsProjectionAfterAppendCrash(t *testing.T) {
	st := startINT20Stack(t, events.WithDuplicateWindowForTesting(100*time.Millisecond))
	const id = "spiffe://operator.example/workload/crash"
	accepted, err := st.svc.RegisterGenesis(st.ctx, st.tenantID, succapi.GenesisRegistrationRequest{
		IdentityID: id, Algorithm: string(crypto.ECDSAP256), DeploymentScope: "spiffe://operator.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := st.store.SystemPool().QueryRow(st.ctx,
		`SELECT payload FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 AND destination=$3`,
		st.tenantID, accepted.RequestID, pcasorch.GenesisDestination).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	worker := pcasorch.NewGenesisWorker(st.store, st.log, st.signer)
	msg := coreorch.Message{TenantID: st.tenantID, Destination: pcasorch.GenesisDestination, Payload: payload}
	if err := worker.Deliver(st.ctx, msg); err != nil {
		t.Fatalf("first genesis delivery: %v", err)
	}
	if _, err := st.store.SystemPool().Exec(st.ctx,
		`DELETE FROM pcas_genesis WHERE tenant_id=$1 AND identity_id=$2`, st.tenantID, id); err != nil {
		t.Fatalf("simulate missing read projection after append: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := worker.Deliver(st.ctx, msg); err != nil {
		t.Fatalf("redelivery after append crash: %v", err)
	}
	chain, err := st.svc.FetchChain(st.ctx, st.tenantID, id)
	if err != nil || chain.Genesis == nil || succession.VerifyGenesis(chain.TrustRootPublicDER, *chain.Genesis) != nil {
		t.Fatalf("repaired projection is not independently valid: %+v, %v", chain, err)
	}
	var first *events.Event
	var logicalCount int
	if err := st.log.Replay(st.ctx, 0, func(ev events.Event) error {
		if ev.Type != succession.TypeGenesis || ev.TenantID != st.tenantID {
			return nil
		}
		logicalCount++
		if first == nil {
			copy := ev
			first = &copy
		} else if ev.ID != first.ID || !ev.Time.Equal(first.Time) || !bytes.Equal(ev.Data, first.Data) {
			t.Fatalf("retry changed the immutable genesis meaning: first=%s second=%s", first.ID, ev.ID)
		}
		return nil
	}); err != nil || logicalCount < 1 || logicalCount > 2 {
		t.Fatalf("retained genesis events=%d error=%v", logicalCount, err)
	}
}
