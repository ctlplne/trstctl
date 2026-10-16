// SPDX-License-Identifier: BUSL-1.1

package minter_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/minter"
)

type mintTestCustody struct {
	keys      map[string]crypto.Signer
	generated int
}

func (c *mintTestCustody) Resolve(handle string) (crypto.Signer, error) {
	key := c.keys[handle]
	if key == nil {
		return nil, errors.New("missing signer handle")
	}
	return key, nil
}

func (c *mintTestCustody) GenerateSuccessorKey(handle string, alg crypto.Algorithm) (crypto.Signer, error) {
	if c.keys[handle] != nil {
		return nil, errors.New("successor handle already exists")
	}
	key, err := crypto.NewSoftwareBackend().GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	c.keys[handle] = key
	c.generated++
	return key, nil
}

type failCompleteOnce struct {
	minter.MintJournal
	failed bool
}

func (j *failCompleteOnce) Complete(key string, entry minter.MintJournalEntry) error {
	if !j.failed {
		j.failed = true
		return errors.New("injected crash before result persistence")
	}
	return j.MintJournal.Complete(key, entry)
}

type oneUseMintApproval struct{ used int }

func (a *oneUseMintApproval) VerifyAndConsume(_ []byte, _ signing.MintRequest, _ []byte) error {
	if a.used != 0 {
		return errors.New("approval already spent")
	}
	a.used++
	return nil
}

func TestMintJournalRecoversPersistedKeyAfterInterruptedResult(t *testing.T) {
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	dir := t.TempDir()
	journal, err := minter.NewDurableMintJournal(dir, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "11111111-1111-1111-1111-111111111111"
	const identity = "spiffe://qa.local/pcas-interrupted-mint"
	pred, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	handle := succession.TenantKeyHandle(tenant, identity, 0)
	custody := &mintTestCustody{keys: map[string]crypto.Signer{handle: pred}}
	approval := &oneUseMintApproval{}
	boot := func(j minter.MintJournal) *minter.Minter {
		t.Helper()
		floors, err := minter.NewDurableFloorStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		mint, err := minter.New(custody, crypto.NewSoftwareBackend(), floors,
			minter.WithCommitmentV2(), minter.WithDualControl(approval), minter.WithMintJournal(j))
		if err != nil {
			t.Fatal(err)
		}
		mint.SetSuccessorKeyStore(custody)
		return mint
	}
	request := signing.MintRequest{
		TenantID: tenant, IdentityID: identity, DeploymentScope: "qa-pcas-interrupted-mint",
		PredecessorHandle: handle, AssertedPredecessorEpoch: 0,
		TargetAlgorithm: crypto.ECDSAP384, PolicyRef: "qa-policy-v1",
		Authorization: []byte("single-use-test-approval"),
	}
	if _, err := boot(&failCompleteOnce{MintJournal: journal}).MintSuccessor(context.Background(), request); err == nil {
		t.Fatal("injected journal completion failure did not stop the RPC")
	}
	if custody.generated != 1 || approval.used != 1 {
		t.Fatalf("first mint generated=%d approvals=%d, want 1 each", custody.generated, approval.used)
	}
	result, err := boot(journal).MintSuccessor(context.Background(), request)
	if err != nil {
		t.Fatalf("restart recovery after persisted key: %v", err)
	}
	if custody.generated != 1 || approval.used != 1 {
		t.Fatalf("recovery repeated keygen or consumed approval: generated=%d approvals=%d", custody.generated, approval.used)
	}
	record, err := minter.DecodeRecord(result.EncodedRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := succession.VerifyRecord(record); err != nil {
		t.Fatalf("recovered record: %v", err)
	}
	replayed, err := boot(journal).MintSuccessor(context.Background(), request)
	if err != nil || !bytes.Equal(result.EncodedRecord, replayed.EncodedRecord) {
		t.Fatalf("completed result did not replay exactly after restart: %v", err)
	}
	changed := request
	changed.PolicyRef = "other-policy"
	if _, err := boot(journal).MintSuccessor(context.Background(), changed); err == nil {
		t.Fatal("changed request crossed the first-writer fence")
	}
}
