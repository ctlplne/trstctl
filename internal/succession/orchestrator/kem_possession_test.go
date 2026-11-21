// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/succession/kemcustody"
)

type proofOnlyKEMCustody struct {
	editionseam.KEMCustody
	store       *kemcustody.Store
	decapCalls  int
	verifyCalls int
}

func (c *proofOnlyKEMCustody) Decapsulate(context.Context, string, []byte) ([]byte, error) {
	c.decapCalls++
	return nil, errors.New("raw shared secret cannot leave signer custody")
}

func (c *proofOnlyKEMCustody) VerifyDataKey(ctx context.Context, handle string, ciphertext, wrapped, aad []byte) ([]byte, error) {
	c.verifyCalls++
	return c.store.VerifyDataKey(ctx, handle, ciphertext, wrapped, aad)
}

func TestCR185KEMPossessionProofStaysInsideSigner(t *testing.T) {
	ctx := t.Context()
	store, err := kemcustody.NewStore("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DestroyAll()
	const handle = "proof-only-kem"
	const alg = "ML-KEM-768"
	protoAlg := pqc.KEMAlgorithmToProto(crypto.Algorithm(alg))
	_, public, err := store.GenerateSuccessorKEM(ctx, handle, protoAlg)
	if err != nil {
		t.Fatal(err)
	}
	custody := &proofOnlyKEMCustody{store: store}
	worker := &BreadthWorker{kem: custody}
	if err := worker.proveSignerDecapsulation(ctx, handle, alg, public); err != nil {
		t.Fatalf("signer-held KEM key did not prove possession: %v", err)
	}
	if custody.decapCalls != 0 || custody.verifyCalls != 1 {
		t.Fatalf("possession proof exported a shared secret: decap=%d verify=%d", custody.decapCalls, custody.verifyCalls)
	}
	_, other, err := store.GenerateSuccessorKEM(ctx, "other-proof-kem", protoAlg)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.proveSignerDecapsulation(ctx, handle, alg, other); err == nil {
		t.Fatal("different KEM public key proved possession")
	}
}
