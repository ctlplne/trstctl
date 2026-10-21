// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
)

// Registering a data-key envelope needs the epoch's recorded KEM public key,
// is first-writer fenced per target, lists back as ciphertext only, and is
// refused once a re-wrap request has fenced the epoch's inventory.
func TestKEMDataKeyRegistrationFenceAndReadback(t *testing.T) {
	ctx := context.Background()
	cs := openStorePCAS(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	svc := succapi.NewService(cs, log, orchestrator.NewOutbox(cs))
	const identity = "spiffe://qa.local/kem-data-keys"

	// No KEM epoch yet: registration is refused before anything is written.
	kemKey, err := pqc.GenerateKEMKey(crypto.Algorithm("ML-KEM-768"))
	if err != nil {
		t.Fatal(err)
	}
	defer kemKey.Destroy()
	dek := []byte("data-key-for-the-orders-backup!!")
	envelope := func(epoch uint64, ref string) succapi.KEMDataKeyRequest {
		ct, ss, err := pqc.Encapsulate(kemKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := crypto.KEMDataKeySeal(ss, dek, succession.KEMDataKeyAAD(identity, epoch, ref))
		if err != nil {
			t.Fatal(err)
		}
		return succapi.KEMDataKeyRequest{IdentityID: identity, Epoch: epoch, TargetRef: ref, KEMCiphertext: ct, WrappedDEK: wrapped, DEKSHA256: crypto.SHA256Sum(dek)}
	}
	if _, err := svc.RegisterKEMDataKey(ctx, tenantA, envelope(1, "backup:a")); !isStatus(err, http.StatusConflict) || !strings.Contains(err.Error(), "no KEM public key") {
		t.Fatalf("registration without a KEM epoch: %v", err)
	}

	// The paired record for epoch 1 publishes the KEM public key.
	record, _ := json.Marshal(map[string]any{"KEMAlg": "ML-KEM-768", "KEMPub": kemKey.Public().DER})
	if err := cs.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO succession_records
			(tenant_id, identity_id, epoch, predecessor_epoch, predecessor_alg, successor_alg, successor_pub, record, idempotency_key, source_sequence)
			VALUES (current_setting('trstctl.tenant_id')::uuid, $1, 1, 0, 'ECDSA-P384', 'ECDSA-P384', $2, $3, 'seed', 1)`,
			identity, []byte("pub"), record)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pub, found, err := svc.KEMPublicKey(ctx, tenantA, identity, 1)
	if err != nil || !found || pub.KEMAlgorithm != "ML-KEM-768" || !bytes.Equal(pub.PublicKeyDER, kemKey.Public().DER) || !strings.Contains(pub.AADTemplate, identity) {
		t.Fatalf("public key: found=%v %+v err=%v", found, pub, err)
	}

	first := envelope(1, "backup:a")
	saved, err := svc.RegisterKEMDataKey(ctx, tenantA, first)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if saved.Epoch != 1 || saved.TargetRef != "backup:a" || saved.Stage != "default" || saved.ReadbackVerified || !bytes.Equal(saved.DEKSHA256, crypto.SHA256Sum(dek)) {
		t.Fatalf("registered row: %+v", saved)
	}
	if again, err := svc.RegisterKEMDataKey(ctx, tenantA, first); err != nil || again.SourceSequence != saved.SourceSequence {
		t.Fatalf("identical replay must return the same row: %+v err=%v", again, err)
	}
	if _, err := svc.RegisterKEMDataKey(ctx, tenantA, envelope(1, "backup:a")); !isStatus(err, http.StatusConflict) {
		t.Fatalf("a different envelope at an occupied target must conflict: %v", err)
	}
	if _, err := svc.RegisterKEMDataKey(ctx, tenantA, succapi.KEMDataKeyRequest{IdentityID: identity, Epoch: 1, TargetRef: "bad", KEMCiphertext: []byte{1}, WrappedDEK: []byte{2}, DEKSHA256: []byte{3}}); !isStatus(err, http.StatusBadRequest) {
		t.Fatalf("a malformed envelope must be refused: %v", err)
	}
	list, err := svc.ListKEMDataKeys(ctx, tenantA, identity, 1, "")
	if err != nil || len(list.Items) != 1 || list.Items[0].TargetRef != "backup:a" || len(list.Items[0].KEMCiphertext) == 0 {
		t.Fatalf("list: %+v err=%v", list, err)
	}
	if bytes.Contains(list.Items[0].WrappedDEK, dek) || bytes.Contains(list.Items[0].KEMCiphertext, dek) {
		t.Fatal("the listing carries the data key in clear")
	}

	// An accepted re-wrap request snapshots the epoch's inventory: a later
	// registration is accepted but belongs to the next request.
	if _, err := svc.RequestKEMRewrap(ctx, tenantA, succapi.KEMRewrapRequest{
		IdentityID: identity, PredecessorEpoch: 1, SigningAlgorithm: string(crypto.ECDSAP384), KEMAlgorithm: "ML-KEM-768",
	}); err != nil {
		t.Fatalf("request re-wrap: %v", err)
	}
	if _, err := svc.RegisterKEMDataKey(ctx, tenantA, envelope(1, "backup:b")); err != nil {
		t.Fatalf("registration after the snapshot: %v", err)
	}
	status, err := svc.RewrapStatus(ctx, tenantA, identity, 1)
	if err != nil || len(status.Jobs) != 1 || status.Jobs[0].DataKeys != 2 || status.Jobs[0].DataKeysRewrapped != 0 || status.Complete {
		t.Fatalf("status before the data half: %+v err=%v", status, err)
	}
	requestSource, found, err := log.EventByID(ctx, succession.KEMRewrapRequestEventID(tenantA, status.Jobs[0].JobID))
	if err != nil || !found {
		t.Fatalf("request source: found=%v err=%v", found, err)
	}
	if decoded, err := succession.Decode(requestSource); err != nil {
		t.Fatal(err)
	} else if p, ok := decoded.(succession.KEMRewrapRequestedV1); !ok || p.InventorySequence != saved.SourceSequence {
		t.Fatalf("request must snapshot the inventory at acceptance: %+v (want %d)", decoded, saved.SourceSequence)
	}
}

func isStatus(err error, want int) bool {
	return err != nil && api.ErrorStatus(err) == want
}
