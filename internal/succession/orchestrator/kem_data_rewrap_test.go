// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/kemcustody"
	"trstctl.com/trstctl/internal/succession/orchestrator"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

// custodyDouble is the control plane's view of a signer that holds the KEM
// keys in an in-memory kemcustody store. Only the data-key operations are
// reachable; the signing-handle operations are never needed by the data half.
type custodyDouble struct {
	editionseam.KEMCustody
	store *kemcustody.Store
}

func (c custodyDouble) RewrapDataKey(ctx context.Context, pred, succ string, ct, wrapped, predAAD, succAAD []byte) ([]byte, []byte, []byte, error) {
	return c.store.RewrapDataKey(ctx, pred, succ, ct, wrapped, predAAD, succAAD)
}

func (c custodyDouble) VerifyDataKey(ctx context.Context, handle string, ct, wrapped, aad []byte) ([]byte, error) {
	return c.store.VerifyDataKey(ctx, handle, ct, wrapped, aad)
}

// The data half of a KEM re-wrap moves every envelope of the fenced
// predecessor epoch into the successor epoch through signer custody, reads each
// one back under the successor key, records a receipt per target and closes
// the stage with a completion the retirement gate reads. A second run after
// completion appends nothing and changes nothing.
func TestKEMRewrapMovesRegisteredDataKeysWithReceipts(t *testing.T) {
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cs.Close)
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	repo := pcasstore.New(cs)
	custody, err := kemcustody.NewStore("", nil)
	if err != nil {
		t.Fatal(err)
	}
	const identity = "spiffe://qa.local/kem-data-rewrap"
	predHandle := succession.TenantKEMKeyHandle(tenantA, identity, 1)
	succHandle := succession.TenantKEMKeyHandle(tenantA, identity, 2)
	protoAlg := pqc.KEMAlgorithmToProto(crypto.Algorithm("ML-KEM-768"))
	if protoAlg == signing.KEMAlgorithm(0) {
		t.Fatal("ML-KEM-768 has no proto algorithm")
	}
	_, predPub, err := custody.GenerateSuccessorKEM(ctx, predHandle, protoAlg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := custody.GenerateSuccessorKEM(ctx, succHandle, protoAlg); err != nil {
		t.Fatal(err)
	}

	// Two envelopes registered at epoch 1 in the default stage.
	deks := map[string][]byte{"backup:a": []byte("data-key-for-backup-a-32-bytes!!"), "backup:b": []byte("data-key-for-backup-b-32-bytes!!")}
	register := func(ref string, dek []byte) {
		t.Helper()
		ct, ss, err := pqc.Encapsulate(crypto.PublicKey{Algorithm: crypto.Algorithm("ML-KEM-768"), DER: predPub})
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := crypto.KEMDataKeySeal(ss, dek, succession.KEMDataKeyAAD(identity, 1, ref))
		if err != nil {
			t.Fatal(err)
		}
		ev, err := succession.Encode(succession.KEMDataKeyRegisteredV1{
			TenantID: tenantA, IdentityID: identity, Epoch: 1, TargetRef: ref, Stage: "default",
			KEMCiphertext: ct, WrappedDEK: wrapped, DEKSHA256: crypto.SHA256Sum(dek),
		})
		if err != nil {
			t.Fatal(err)
		}
		ev.ID = succession.KEMDataKeyEventID(tenantA, identity, 1, ref, false)
		recorded, err := log.Append(ctx, ev)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.ApplyKEMDataKeyEvent(ctx, recorded); err != nil {
			t.Fatalf("project registration %s: %v", ref, err)
		}
	}
	for ref, dek := range deks {
		register(ref, dek)
	}
	inventory, err := repo.KEMDataKeyInventorySequence(ctx, tenantA, identity, 1)
	if err != nil || inventory == 0 {
		t.Fatalf("inventory snapshot: %d err=%v", inventory, err)
	}

	// The request and its paired-key record, as the queued and key_ready job
	// rows the worker would have projected before the data half.
	const requestID = "kem-data-rewrap-request-1"
	requestDigest := crypto.SHA256Sum([]byte("request"))
	stages := []string{"default"}
	requested, err := succession.Encode(succession.KEMRewrapRequestedV1{
		TenantID: tenantA, IdentityID: identity, PredecessorEpoch: 1, RequestID: requestID, RequestDigest: requestDigest, Stages: stages,
		InventorySequence: inventory,
	})
	if err != nil {
		t.Fatal(err)
	}
	requested.ID = succession.KEMRewrapRequestEventID(tenantA, requestID)
	recordedRequest, err := log.Append(ctx, requested)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ApplyKEMRewrapRequestedEvent(ctx, recordedRequest); err != nil {
		t.Fatal(err)
	}
	keyReady, err := succession.Encode(succession.KEMRewrapRecordedV1{
		TenantID: tenantA, IdentityID: identity, Epoch: 2, RequestID: requestID, RequestDigest: requestDigest,
		RecordJSON: []byte(`{}`), Stages: stages,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyReady.ID = succession.KEMRewrapRecordEventID(tenantA, identity, 2)
	recordedKeyReady, err := log.Append(ctx, keyReady)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ApplyKEMPairedKeyReady(ctx, recordedKeyReady); err != nil {
		t.Fatal(err)
	}
	if complete, err := repo.RewrapComplete(ctx, tenantA, identity, 1); err != nil || complete {
		t.Fatalf("key_ready alone must not read as complete: complete=%v err=%v", complete, err)
	}

	worker := orchestrator.NewBreadthWorker(cs, custodyDouble{store: custody}, log)
	if err := worker.RewrapDataKeysForTest(ctx, tenantA, identity, 1, stages, requestID, requestDigest, inventory, false); err != nil {
		t.Fatalf("rewrap data keys: %v", err)
	}
	moved, err := repo.ListKEMDataKeys(ctx, tenantA, identity, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 2 {
		t.Fatalf("successor envelopes = %d, want 2", len(moved))
	}
	for _, row := range moved {
		want := crypto.SHA256Sum(deks[row.TargetRef])
		if !row.ReadbackVerified || row.RewrapRequestID != requestID || row.RewrappedFromEpoch != 1 || !bytes.Equal(row.DEKSHA256, want) {
			t.Fatalf("successor row %s: %+v", row.TargetRef, row)
		}
		digest, err := custody.VerifyDataKey(ctx, succHandle, row.KEMCiphertext, row.WrappedDEK, succession.KEMDataKeyAAD(identity, 2, row.TargetRef))
		if err != nil || !bytes.Equal(digest, want) {
			t.Fatalf("independent readback of %s: %v %x", row.TargetRef, err, digest)
		}
		if _, err := custody.VerifyDataKey(ctx, predHandle, row.KEMCiphertext, row.WrappedDEK, succession.KEMDataKeyAAD(identity, 2, row.TargetRef)); err == nil {
			t.Fatalf("the predecessor key still opens the successor envelope for %s", row.TargetRef)
		}
	}
	jobs, err := repo.ListRewrapJobs(ctx, tenantA, identity, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs=%+v err=%v", jobs, err)
	}
	if jobs[0].Status != "complete" || jobs[0].DataKeys != 2 || jobs[0].DataKeysRewrapped != 2 || jobs[0].DataReceiptSequence == 0 || jobs[0].CompletedStages != 1 {
		t.Fatalf("stage receipt: %+v", jobs[0])
	}
	if complete, err := repo.RewrapComplete(ctx, tenantA, identity, 1); err != nil || !complete {
		t.Fatalf("data receipt must complete the re-wrap: complete=%v err=%v", complete, err)
	}
	last, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.RewrapDataKeysForTest(ctx, tenantA, identity, 1, stages, requestID, requestDigest, inventory, false); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if again, err := log.LastSequence(ctx); err != nil || again != last {
		t.Fatalf("a completed stage appended events on replay: %d -> %d (%v)", last, again, err)
	}
	// A stage the accepted request never declared has no job row to receive a
	// data receipt, so it cannot complete.
	if err := worker.RewrapDataKeysForTest(ctx, tenantA, identity, 1, []string{"default", "undeclared"}, requestID, requestDigest, inventory, true); err == nil {
		t.Fatal("a stage the request never declared must not complete")
	}
	// A late registration at the predecessor epoch is accepted, is not moved
	// by the completed request, and closes the retirement gate again.
	register("backup:late", []byte("data-key-for-backup-c-32-bytes!!"))
	if complete, err := repo.RewrapComplete(ctx, tenantA, identity, 1); err != nil || complete {
		t.Fatalf("a late registration must re-close the gate: complete=%v err=%v", complete, err)
	}
	if err := worker.RewrapDataKeysForTest(ctx, tenantA, identity, 1, stages, requestID, requestDigest, inventory, false); err != nil {
		t.Fatalf("replay after late registration: %v", err)
	}
	if moved, err := repo.ListKEMDataKeys(ctx, tenantA, identity, 2, ""); err != nil || len(moved) != 2 {
		t.Fatalf("the completed request must not move envelopes outside its snapshot: %d err=%v", len(moved), err)
	}
}

// A stage with no registered envelopes stays key_ready unless the request
// attested that the predecessor epoch holds no data keys.
func TestKEMRewrapEmptyStageNeedsAttestation(t *testing.T) {
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cs.Close)
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	repo := pcasstore.New(cs)
	const requestID = "kem-empty-stage-request"
	requestDigest := crypto.SHA256Sum([]byte("empty"))
	for _, attested := range []bool{false, true} {
		stage := "unattested"
		if attested {
			stage = "attested"
		}
		identity := "spiffe://qa.local/kem-empty-stage-" + stage
		requested, err := succession.Encode(succession.KEMRewrapRequestedV1{
			TenantID: tenantA, IdentityID: identity, PredecessorEpoch: 0, RequestID: requestID + stage, RequestDigest: requestDigest,
			Stages: []string{stage}, EmptyInventoryAttested: attested,
		})
		if err != nil {
			t.Fatal(err)
		}
		requested.ID = succession.KEMRewrapRequestEventID(tenantA, requestID+stage)
		recorded, err := log.Append(ctx, requested)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.ApplyKEMRewrapRequestedEvent(ctx, recorded); err != nil {
			t.Fatal(err)
		}
		keyReady, err := succession.Encode(succession.KEMRewrapRecordedV1{
			TenantID: tenantA, IdentityID: identity, Epoch: 1, RequestID: requestID + stage, RequestDigest: requestDigest,
			RecordJSON: []byte(`{}`), Stages: []string{stage},
		})
		if err != nil {
			t.Fatal(err)
		}
		keyReady.ID = succession.KEMRewrapRecordEventID(tenantA, identity, 1)
		recordedReady, err := log.Append(ctx, keyReady)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.ApplyKEMPairedKeyReady(ctx, recordedReady); err != nil {
			t.Fatal(err)
		}
		worker := orchestrator.NewBreadthWorker(cs, custodyDouble{}, log)
		if err := worker.RewrapDataKeysForTest(ctx, tenantA, identity, 0, []string{stage}, requestID+stage, requestDigest, 0, attested); err != nil {
			t.Fatalf("stage %s: %v", stage, err)
		}
		jobs, err := repo.ListRewrapJobs(ctx, tenantA, identity, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range jobs {
			if job.Stage != stage {
				continue
			}
			if attested && job.Status != "complete" {
				t.Fatalf("attested empty stage: %+v", job)
			}
			if !attested && job.Status != "key_ready" {
				t.Fatalf("unattested empty stage must stay key_ready: %+v", job)
			}
		}
	}
}
