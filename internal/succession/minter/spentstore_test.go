// SPDX-License-Identifier: BUSL-1.1

package minter_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession/minter"
)

// TestINT06_DurableDualControlSingleUseSurvivesRestart proves single-use survives a
// signer restart (PCAS-claim-5): a durable dual-control authorizer consumes a token; a
// FRESH authorizer over the same custody dir refuses the replay. With the in-memory
// store the fresh authorizer would accept it — a single-use bypass.
func TestINT06_DurableDualControlSingleUseSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	be := crypto.NewSoftwareBackend()
	authority, err := be.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pub := authority.Public().DER

	req := signing.MintRequest{
		IdentityID: "spiffe://d/int06", TenantID: "t", DeploymentScope: "d",
		PredecessorHandle: "pred", AssertedPredecessorEpoch: 0, TargetAlgorithm: crypto.ECDSAP384,
		PolicyRef: "p",
	}
	pd := minter.RequestParamsDigest(req)
	payload, _ := json.Marshal(minter.AuthorizationToken{
		IdentityID: req.IdentityID, TenantID: req.TenantID,
		AssertedPredecessorEpoch: req.AssertedPredecessorEpoch, TargetAlgorithm: req.TargetAlgorithm,
		ParamsDigest: pd, Nonce: "nonce-1",
	})
	token, err := minter.SignEnvelope(authority, payload)
	if err != nil {
		t.Fatal(err)
	}

	a1, err := minter.NewDurableSignedTokenAuthorizer(pub, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := a1.VerifyAndConsume(token, req, pd); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}

	// "Restart": a fresh authorizer over the SAME custody dir loads the consumed nonce
	// and refuses the replay.
	a2, err := minter.NewDurableSignedTokenAuthorizer(pub, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.VerifyAndConsume(token, req, pd); err == nil {
		t.Fatal("post-restart token replay accepted; single-use did not survive restart")
	}
}

// TestDurableSpentStore_ReloadsConsumedNonces: consumed nonces reload across a fresh
// store on the same dir.
func TestDurableSpentStore_ReloadsConsumedNonces(t *testing.T) {
	dir := t.TempDir()
	s1, err := minter.NewDurableSpentStore(dir, "spent")
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := s1.Consume("n1"); used {
		t.Fatal("n1 unexpectedly already spent")
	}
	s2, err := minter.NewDurableSpentStore(dir, "spent")
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := s2.Consume("n1"); !used {
		t.Fatal("n1 not seen as spent after reload (durability failed)")
	}
	if used, _ := s2.Consume("n2"); used {
		t.Fatal("n2 unexpectedly already spent")
	}
}

func TestDurableSpentStoreRejectsReplayAcrossConcurrentInstances(t *testing.T) {
	dir := t.TempDir()
	first, err := minter.NewDurableSpentStore(dir, "spent")
	if err != nil {
		t.Fatal(err)
	}
	second, err := minter.NewDurableSpentStore(dir, "spent")
	if err != nil {
		t.Fatal(err)
	}
	if used, err := first.Consume("same-token-nonce"); err != nil || used {
		t.Fatalf("first consume: used=%t err=%v", used, err)
	}
	if used, err := second.Consume("same-token-nonce"); err != nil || !used {
		t.Fatalf("second live instance accepted one-time nonce: used=%t err=%v", used, err)
	}
	for i := 0; i < 16; i++ {
		nonce := "simultaneous-token-" + string(rune('a'+i))
		start := make(chan struct{})
		results := make(chan bool, 2)
		errors := make(chan error, 2)
		var wg sync.WaitGroup
		for _, instance := range []*minter.DurableSpentStore{first, second} {
			wg.Add(1)
			go func(instance *minter.DurableSpentStore) {
				defer wg.Done()
				<-start
				used, err := instance.Consume(nonce)
				results <- used
				errors <- err
			}(instance)
		}
		close(start)
		wg.Wait()
		close(results)
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatalf("concurrent consume: %v", err)
			}
		}
		newUses := 0
		for alreadySpent := range results {
			if !alreadySpent {
				newUses++
			}
		}
		if newUses != 1 {
			t.Fatalf("nonce %q was accepted %d times, want exactly one", nonce, newUses)
		}
	}
}

func TestDurableSpentStoreBackupRestoreKeepsLegacyAndAtomicClaims(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "spent"), []byte("legacy-nonce\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	instance, err := minter.NewDurableSpentStore(source, "spent")
	if err != nil {
		t.Fatal(err)
	}
	if used, err := instance.Consume("new-nonce"); err != nil || used {
		t.Fatalf("new nonce: used=%t err=%v", used, err)
	}
	destination := filepath.Join(t.TempDir(), "restored-custody")
	if err := backup.CopyTree(source, destination); err != nil {
		t.Fatal(err)
	}
	restored, err := minter.NewDurableSpentStore(destination, "spent")
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []string{"legacy-nonce", "new-nonce"} {
		if used, err := restored.Consume(nonce); err != nil || !used {
			t.Fatalf("restored nonce %q replayed: used=%t err=%v", nonce, used, err)
		}
	}
}
