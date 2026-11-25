// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
)

func kmipReplicaFixture(t *testing.T) (*events.Log, seal.KeyWrapper) {
	t.Helper()
	var wrapper *seal.LocalKEK
	log := openKMIPValidatedFixture(t, func() seal.KeyWrapper { return wrapper })
	key, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err = seal.NewLocalKEK(key)
	secret.Wipe(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	return log, wrapper
}

func TestKMIPReplicasMintDistinctDurableObjectIDs(t *testing.T) {
	ctx := t.Context()
	log, wrapper := kmipReplicaFixture(t)
	const tenant = "kmip-replica-ids"
	first, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	client := []byte("good-client")
	firstKey := bytes.Repeat([]byte{0x31}, 32)
	secondKey := bytes.Repeat([]byte{0x32}, 32)
	firstID, err := first.Register(ctx, client, "AES", firstKey)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := second.Register(ctx, client, "AES", secondKey)
	if err != nil {
		t.Fatal(err)
	}
	if firstID == secondID {
		t.Fatalf("two replicas minted the same durable object ID %q", firstID)
	}
	for _, tc := range []struct {
		server *Server
		id     string
		want   []byte
	}{{first, secondID, secondKey}, {second, firstID, firstKey}} {
		got, err := tc.server.Get(ctx, client, tc.id)
		if err != nil || !bytes.Equal(got, tc.want) {
			secret.Wipe(got)
			t.Fatalf("replica did not read the other replica's exact key: %v", err)
		}
		secret.Wipe(got)
	}
}

func TestKMIPReplicaStopsReleasingDestroyedAndCompromisedKeys(t *testing.T) {
	ctx := t.Context()
	log, wrapper := kmipReplicaFixture(t)
	const tenant = "kmip-replica-lifecycle"
	first, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	client := []byte("good-client")
	destroyID, err := first.Register(ctx, client, "AES", bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	compromiseID, err := first.Register(ctx, client, "AES", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.Destroy(ctx, client, destroyID); err != nil {
		t.Fatal(err)
	}
	if err := first.RevokeCompromised(ctx, client, compromiseID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{destroyID, compromiseID} {
		key, err := second.Get(ctx, client, id)
		secret.Wipe(key)
		if err == nil {
			t.Fatalf("stale replica released object %q after remote lifecycle stop", id)
		}
	}
}

func TestKMIPReplicaStopsSigningWithRemotelyCompromisedKey(t *testing.T) {
	ctx := t.Context()
	log, wrapper := kmipReplicaFixture(t)
	const tenant = "kmip-replica-sign"
	first, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	client := []byte("good-client")
	extractable := true
	privateID, _, err := first.CreateKeyPair(ctx, client, KeyPairSpec{Algorithm: "ECDSA", Length: 256, PrivateExtractable: &extractable})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Activate(ctx, client, privateID); err != nil {
		t.Fatal(err)
	}
	second, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	params := SignatureParams{Hash: crypto.SHA256}
	if _, err := second.Sign(ctx, client, privateID, params, []byte("before compromise")); err != nil {
		t.Fatal(err)
	}
	if err := first.RevokeCompromised(ctx, client, privateID); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Sign(ctx, client, privateID, params, []byte("after compromise")); err == nil {
		t.Fatal("stale replica signed with a remotely compromised private key")
	}
	view, err := second.GetKey(ctx, client, privateID)
	secret.Wipe(view.Material)
	if err == nil {
		t.Fatal("stale replica released an extractable, remotely compromised private key")
	}
}

func TestKMIPReplayRefusesDuplicateCreatedObjectID(t *testing.T) {
	ctx := context.Background()
	log, wrapper := kmipReplicaFixture(t)
	const tenant = "kmip-duplicate-created-id"
	first, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Register(ctx, []byte("good-client"), "AES", bytes.Repeat([]byte{0x51}, 32)); err != nil {
		t.Fatal(err)
	}
	first.Close()
	var duplicate json.RawMessage
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID == tenant && ev.Type == kmipStateRegisteredEventType {
			duplicate = append(duplicate[:0], ev.Data...)
		}
		return nil
	}); err != nil || len(duplicate) == 0 {
		t.Fatalf("read original object event: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{TenantID: tenant, Type: kmipStateRegisteredEventType, Data: duplicate}); err != nil {
		t.Fatal(err)
	}
	replayed, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if replayed != nil {
		replayed.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate created ID replay result = %v, want fail-closed duplicate error", err)
	}
}

func TestKMIPStaleRekeyCannotAppendAfterReplicaRevokes(t *testing.T) {
	ctx := t.Context()
	log, wrapper := kmipReplicaFixture(t)
	const tenant = "kmip-replica-rekey-race"
	first, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewDurable(ctx, tenant, certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	client := []byte("good-client")
	id, err := first.Register(ctx, client, "AES", bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	material, err := second.Get(ctx, client, id)
	secret.Wipe(material)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.RevokeCompromised(ctx, client, id); err != nil {
		t.Fatal(err)
	}
	// Model the narrow interval after a stale replica decided to rekey but
	// before its append. The shared stream must reject that stale decision.
	second.mu.Lock()
	err = second.persistState(ctx, kmipStateRekeyedEventType, kmipStateEvent{ID: id, Algorithm: "AES", State: StateActive, Version: 2, SealedKey: []byte("would-be-ciphertext")})
	second.mu.Unlock()
	if !errors.Is(err, events.ErrAppendPositionChanged) {
		t.Fatalf("stale rekey append after revocation = %v, want position conflict", err)
	}
	if _, err := second.ReKey(ctx, client, id); err == nil {
		t.Fatal("stale replica rekeyed compromised object after refreshing shared state")
	}
	material, err = second.Get(ctx, client, id)
	secret.Wipe(material)
	if err == nil {
		t.Fatal("stale replica returned compromised object after failed rekey")
	}
}

// Two shipped listeners share one durable journal and serve stock KMIP frames
// over mutual TLS. A live second listener must see lifecycle changes before it
// releases or uses a key, and both listeners must preserve their own IDs.
func TestKMIPTwoServedReplicasEnforceSharedStateOverMTLS(t *testing.T) {
	const serverName = "kmip.replicas.test"
	const tenantID = "kmip-replica-served"
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), serverName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	log, wrapper := kmipReplicaFixture(t)
	replica := func() (*kmipWireRuntime, net.Conn) {
		t.Helper()
		pools := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemKMIP, Workers: 2, Queue: 4})
		t.Cleanup(pools.Close)
		h := startKMIPWireRuntime(t, server.KMIPFactoryDeps{
			StartupContext: t.Context(),
			Protocols: config.Protocols{KMIP: config.KMIPProtocol{
				Enabled: true, TenantID: tenantID, Addr: "127.0.0.1:0",
				CertFile: material.Signer.CertFile, KeyFile: material.Signer.KeyFile,
				ClientCAFile: material.Signer.PeerCAFile,
			}},
			ProtocolTenant: tenantID,
			Bulkhead:       pools,
			Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
			EventLog:       log,
			KeyWrapper:     wrapper,
		}, material, serverName)
		conn := h.dial(t)
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
		t.Cleanup(func() { _ = conn.Close() })
		return h, conn
	}
	create := func(conn net.Conn) string {
		t.Helper()
		response := kmipWireRequest(t, conn, OperationCreate, kmipCreateAES256Payload())
		return mustFindText(t, mustKMIPSuccess(t, response, OperationCreate), TagUniqueIdentifier)
	}
	getKey := func(conn net.Conn, id string) []byte {
		t.Helper()
		response := kmipWireRequest(t, conn, OperationGet, kmipUniqueIDPayload(id))
		return append([]byte(nil), mustFindNode(t, mustKMIPSuccess(t, response, OperationGet), TagKeyMaterial).Value...)
	}
	a, connA := replica()
	aesID := create(connA)
	pair := mustKMIPSuccess(t, kmipWireRequest(t, connA, OperationCreateKeyPair,
		kmipCreateKeyPairPayload(cryptographicAlgorithmECDSA, 256, "")), OperationCreateKeyPair)
	priv := mustFindText(t, pair, TagPrivateKeyUniqueIdentifier)
	mustKMIPSuccess(t, kmipWireRequest(t, connA, OperationActivate, kmipUniqueIDPayload(priv)), OperationActivate)
	b, connB := replica()
	mustKMIPSuccess(t, kmipWireRequest(t, connA, OperationDestroy, kmipUniqueIDPayload(aesID)), OperationDestroy)
	revoke := ttlvStructure(TagRequestPayload, ttlvText(TagUniqueIdentifier, priv),
		ttlvStructure(TagRevocationReason, ttlvEnumeration(TagRevocationReasonCode, revocationReasonKeyCompromise)))
	mustKMIPSuccess(t, kmipWireRequest(t, connA, OperationRevoke, revoke), OperationRevoke)
	if status := responseStatus(t, kmipWireRequest(t, connB, OperationGet, kmipUniqueIDPayload(aesID)), OperationGet); status != resultStatusOperationFailed {
		t.Fatalf("replica B released remotely destroyed key: status=%d", status)
	}
	ecdsa := ttlvStructure(TagCryptographicParameters, ttlvEnumeration(TagDigitalSignatureAlgorithm, signatureECDSAWithSHA256))
	if status := responseStatus(t, kmipWireRequest(t, connB, OperationSign, kmipSignPayload(priv, ecdsa, []byte("manifest"))), OperationSign); status != resultStatusOperationFailed {
		t.Fatalf("replica B signed with remotely compromised key: status=%d", status)
	}
	idA, idB := create(connA), create(connB)
	if idA == idB {
		t.Fatalf("two served replicas minted the same ID %q", idA)
	}
	keyA := getKey(connA, idA)
	defer secret.Wipe(keyA)
	if keyB := getKey(connB, idB); bytes.Equal(keyA, keyB) {
		secret.Wipe(keyB)
		t.Fatal("two distinct object IDs unexpectedly contain the same key")
	} else {
		secret.Wipe(keyB)
	}
	_ = connA.Close()
	_ = connB.Close()
	a.stop(t)
	b.stop(t)
	_, connC := replica()
	after := getKey(connC, idA)
	defer secret.Wipe(after)
	if !bytes.Equal(after, keyA) {
		t.Fatal("restart replay changed the key associated with replica A's ID")
	}
}
