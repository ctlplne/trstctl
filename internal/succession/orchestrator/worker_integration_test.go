// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	pcasstore "trstctl.com/trstctl/internal/succession/store"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/orchestrator"
	"trstctl.com/trstctl/internal/succession/signerwiring"
)

// TestINT03_RequestWorker_EndToEnd is the INT-03 integration test: a queued
// "succeed identity X" request is turned into a real minted, recorded, published
// succession, over REAL Postgres and a REAL cross-process signer. It proves the
// full loop the audit found missing — request -> worker -> mint over the transport
// -> record + rp-publish + high-water in one transaction — plus multi-epoch chaining
// (the persisted successor becomes the next predecessor) and idempotency.
func TestINT03_RequestWorker_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// Real core store + PCAS migrations (succession_records, identity_algorithm_epoch,
	// outbox).
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Real isolated signer with the production minter attached, over UDS. Its custody
	// resolves predecessors and PERSISTS successors under their per-epoch handles.
	client := serveProductionSigner(t)

	const id = "spiffe://d/int03"

	// Onboard the genesis key INSIDE the signer under KeyHandle(id, 0). This is the
	// identity's epoch-0 key; the worker resolves it as the first predecessor.
	if _, err := client.GenerateKeyHandle(ctx, crypto.ECDSAP256, succession.KeyHandle(id, 0)); err != nil {
		t.Fatalf("onboard genesis key: %v", err)
	}

	orch := orchestrator.New(cs, client) // *signing.Client is the remote minter (INT-01)
	worker := orchestrator.NewSuccessionRequestWorker(orch)

	// First succession (genesis -> epoch 1: P-256 -> P-384) driven by a queued request.
	if err := worker.Handle(ctx, tenantA, reqPayload("req-1", id, crypto.ECDSAP384)); err != nil {
		t.Fatalf("worker handle (epoch 1): %v", err)
	}
	assertRecord(t, cs, id, 1, 0)   // epoch 1, predecessor_epoch 0
	assertHighWater(t, cs, id, 1)   // serving high-water advanced
	assertPublished(t, cs, "req-1") // rp-publish outbox row written in the same txn

	// Second succession (epoch 1 -> epoch 2: P-384 -> P-521). The predecessor is
	// KeyHandle(id, 1), which the signer PERSISTED when it minted epoch 1 — proving
	// the successor survives and chains.
	if err := worker.Handle(ctx, tenantA, reqPayload("req-2", id, crypto.ECDSAP521)); err != nil {
		t.Fatalf("worker handle (epoch 2): %v", err)
	}
	assertRecord(t, cs, id, 2, 1)
	assertHighWater(t, cs, id, 2)
	assertChainLen(t, cs, id, 2)

	// Idempotency: re-delivering req-1 mints nothing new (RunSuccession replays the
	// already-recorded record on the same key). The chain stays length 2.
	if err := worker.Handle(ctx, tenantA, reqPayload("req-1", id, crypto.ECDSAP384)); err != nil {
		t.Fatalf("worker handle (idempotent re-delivery): %v", err)
	}
	assertChainLen(t, cs, id, 2)
}

func reqPayload(requestID, identityID string, alg crypto.Algorithm) []byte {
	b, _ := json.Marshal(struct {
		RequestID       string `json:"request_id"`
		IdentityID      string `json:"identity_id"`
		TargetAlgorithm string `json:"target_algorithm"`
		PolicyRef       string `json:"policy_ref"`
		DeploymentScope string `json:"deployment_scope"`
	}{RequestID: requestID, IdentityID: identityID, TargetAlgorithm: string(alg), PolicyRef: "policy:1", DeploymentScope: "spiffe://d"})
	return b
}

func assertRecord(t *testing.T, cs *corestore.Store, id string, epoch, predEpoch uint64) {
	t.Helper()
	var e, pe uint64
	if err := cs.SystemPool().QueryRow(context.Background(),
		`SELECT epoch, predecessor_epoch FROM succession_records WHERE identity_id=$1 AND epoch=$2`,
		id, epoch).Scan(&e, &pe); err != nil {
		t.Fatalf("record epoch %d missing: %v", epoch, err)
	}
	if e != epoch || pe != predEpoch {
		t.Fatalf("record epochs = %d<-%d, want %d<-%d", e, pe, epoch, predEpoch)
	}
}

func assertHighWater(t *testing.T, cs *corestore.Store, id string, want uint64) {
	t.Helper()
	var hw uint64
	if err := cs.SystemPool().QueryRow(context.Background(),
		`SELECT epoch FROM identity_algorithm_epoch WHERE identity_id=$1`, id).Scan(&hw); err != nil {
		t.Fatalf("high-water missing: %v", err)
	}
	if hw != want {
		t.Fatalf("high-water = %d, want %d", hw, want)
	}
}

func assertPublished(t *testing.T, cs *corestore.Store, idempotencyKey string) {
	t.Helper()
	var dest string
	if err := cs.SystemPool().QueryRow(context.Background(),
		`SELECT destination FROM outbox WHERE idempotency_key=$1`, idempotencyKey).Scan(&dest); err != nil {
		t.Fatalf("rp-publish outbox row missing for %q: %v", idempotencyKey, err)
	}
	if dest != orchestrator.PublishDestination {
		t.Fatalf("outbox destination = %q, want %q", dest, orchestrator.PublishDestination)
	}
}

func assertChainLen(t *testing.T, cs *corestore.Store, id string, want int) {
	t.Helper()
	var n int
	if err := cs.SystemPool().QueryRow(context.Background(),
		`SELECT count(*) FROM succession_records WHERE identity_id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("chain length = %d, want %d", n, want)
	}
}

// serveProductionSigner runs an isolated signer with the production minter attached
// over UDS and returns a connected control-plane client.
func serveProductionSigner(t *testing.T) *signing.Client {
	t.Helper()
	m, err := signerwiring.NewProductionMinter(signerwiring.Config{SignerID: "trstctl-signer-test"})
	if err != nil {
		t.Fatal(err)
	}
	svc := signing.NewServer(signing.WithSuccessionMinter(m))

	dir, err := os.MkdirTemp("", "pcas-sgn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = signing.ServeServerWithOptions(ctx, sock, svc, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()

	client, err := signing.Dial(sock)
	if err != nil {
		t.Fatalf("dial signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	deadline := time.Now().Add(8 * time.Second)
	for !client.Healthy(context.Background()) {
		if time.Now().After(deadline) {
			t.Fatal("signer did not become healthy in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return client
}
