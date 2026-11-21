// SPDX-License-Identifier: BUSL-1.1

package signerwiring_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/kem"
	"trstctl.com/trstctl/internal/succession/kemcustody"
	"trstctl.com/trstctl/internal/succession/signerwiring"
)

// CR-188: the paired KEM ceremony must make a valid record with private keys
// held in signer custody, while the paired signing handle refuses generic Sign.
// A lost RPC response can retry after restart without minting a new key.
func TestCR188PairedKEMTypedCeremonySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	wrapper, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer wrapper.Destroy()
	const identity = "spiffe://example.test/kem"
	tenant := uuid.NewString()
	request := signing.PairedKEMMintRequest{
		TenantID: tenant, IdentityID: identity, RequestID: uuid.NewString(),
		PredecessorEpoch: 0, SigningAlgorithm: crypto.ECDSAP256,
		KEMAlgorithm: pqc.KEMAlgorithmToProto(pqc.MLKEM768),
	}
	newSigner := func() (*signing.Server, *signing.Client) {
		t.Helper()
		m, err := signerwiring.NewProductionMinter(signerwiring.Config{
			FloorDir: filepath.Join(dir, "keys"), JournalWrapper: wrapper,
		})
		if err != nil {
			t.Fatal(err)
		}
		kems, err := kemcustody.NewStore(filepath.Join(dir, "keys"), wrapper)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), wrapper),
			signing.WithKEMCustody(kems), signing.WithSuccessionMinter(m))
		if err != nil {
			t.Fatal(err)
		}
		return svc, serveSigner(t, svc)
	}
	first, client := newSigner()
	t.Cleanup(first.Shutdown)
	predHandle := succession.TenantKeyHandle(tenant, identity, 0)
	pred, err := first.GenerateSuccessorKey(predHandle, crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := client.MintPairedKEM(context.Background(), request)
	if err != nil {
		t.Fatalf("typed mint over signer socket: %v", err)
	}
	var record kem.PairedRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	if err := kem.VerifyPaired(record); err != nil {
		t.Fatalf("public paired record: %v", err)
	}
	if !bytes.Equal(record.Base.Fields.PredecessorPub, pred.Public().DER) ||
		record.Base.Fields.Epoch != 1 || record.Base.Fields.PolicyRef != "pcas:kem-rewrap:"+request.RequestID {
		t.Fatal("paired commitment does not bind the held predecessor, epoch and request")
	}
	first.Shutdown()
	second, restarted := newSigner()
	t.Cleanup(second.Shutdown)
	retried, err := restarted.MintPairedKEM(context.Background(), request)
	if err != nil {
		t.Fatalf("typed retry after signer restart: %v", err)
	}
	var replay kem.PairedRecord
	if err := json.Unmarshal(retried, &replay); err != nil {
		t.Fatal(err)
	}
	if err := kem.VerifyPaired(replay); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replay.Base.Fields.SuccessorPub, record.Base.Fields.SuccessorPub) || !bytes.Equal(replay.KEMPub, record.KEMPub) {
		t.Fatal("retry replaced a signer-held paired key")
	}
	remote, err := restarted.SignerForHandle(context.Background(), succession.TenantKeyHandle(tenant, identity, 1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = remote.SignDigest(crypto.SHA256Sum([]byte("attacker digest")), crypto.SignOptions{Hash: crypto.SHA256})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("paired successor generic Sign available after restart: %v", err)
	}
	prepared, err := restarted.PrepareRecoverySuccessor(context.Background(), signing.RecoveryPrepareRequest{
		TenantID: tenant, IdentityID: identity, Epoch: 2, Algorithm: crypto.ECDSAP256,
		DeploymentScope: "spiffe://example.test", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("typed recovery preparation: %v", err)
	}
	var receipt succession.RecoverySuccessorPreparedV1
	if err := json.Unmarshal(prepared, &receipt); err != nil {
		t.Fatal(err)
	}
	if err := succession.VerifyRecoverySuccessorPrepared(receipt); err != nil {
		t.Fatalf("typed recovery receipt: %v", err)
	}
	recoveryKey, err := restarted.SignerForHandle(context.Background(), receipt.Handle)
	if err != nil {
		t.Fatal(err)
	}
	_, err = recoveryKey.SignDigest(crypto.SHA256Sum([]byte("attacker digest")), crypto.SignOptions{Hash: crypto.SHA256})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("recovery successor generic Sign available: %v", err)
	}
}
