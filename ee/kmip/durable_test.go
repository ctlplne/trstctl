// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/tenantseal"
)

type switchableKMIPTenantAccess struct {
	tenantID string
	cipher   tenantseal.Cipher
	blocked  bool
}

func (a *switchableKMIPTenantAccess) WithTenant(_ context.Context, tenantID string, fn func(tenantseal.Cipher) error) error {
	if tenantID != a.tenantID {
		return errors.New("test KMIP tenant selection refused")
	}
	if a.blocked {
		return errors.New("test KMIP tenant sealed")
	}
	return fn(a.cipher)
}

type kmipDomainCipher struct {
	key     seal.KeyWrapper
	binding []byte
}

func (c kmipDomainCipher) Seal(plaintext, aad []byte) ([]byte, error) {
	return seal.SealDomain(c.key, plaintext, aad, c.binding)
}

func (c kmipDomainCipher) Open(container, aad []byte) ([]byte, error) {
	return seal.OpenDomain(c.key, container, aad, c.binding)
}

func TestKMIPDurableStateReplaysSealedKeysAndLifecycle(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	kekBytes, err := seal.GenerateKEK()
	if err != nil {
		t.Fatalf("generate KEK: %v", err)
	}
	wrapper, err := seal.NewLocalKEK(kekBytes)
	secret.Wipe(kekBytes)
	if err != nil {
		t.Fatalf("construct KEK: %v", err)
	}
	t.Cleanup(wrapper.Destroy)
	good := []byte("good-client")
	keyMaterial := []byte("0123456789abcdef0123456789abcdef")

	first, err := NewDurable(ctx, "tenant-a", certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatalf("first durable server: %v", err)
	}
	createdID, err := first.Create(ctx, good, "AES")
	if err != nil {
		t.Fatalf("create durable key: %v", err)
	}
	registeredID, err := first.Register(ctx, good, "AES", keyMaterial)
	if err != nil {
		t.Fatalf("register durable key: %v", err)
	}
	first.Close()

	second, err := NewDurable(ctx, "tenant-a", certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatalf("replay durable server: %v", err)
	}
	replayed, err := second.Get(ctx, good, registeredID)
	if err != nil {
		t.Fatalf("get replayed registered key: %v", err)
	}
	if !bytes.Equal(replayed, keyMaterial) {
		t.Fatalf("replayed key = %x, want %x", replayed, keyMaterial)
	}
	secret.Wipe(replayed)
	if err := second.Revoke(ctx, good, createdID); err != nil {
		t.Fatalf("revoke replayed key: %v", err)
	}
	second.Close()

	third, err := NewDurable(ctx, "tenant-a", certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatalf("replay revoked server: %v", err)
	}
	if _, err := third.Get(ctx, good, createdID); err == nil {
		t.Fatal("replayed revoked key remained available")
	}
	if err := third.Destroy(ctx, good, registeredID); err != nil {
		t.Fatalf("destroy replayed key: %v", err)
	}
	third.Close()

	fourth, err := NewDurable(ctx, "tenant-a", certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatalf("replay destroyed server: %v", err)
	}
	defer fourth.Close()
	if _, err := fourth.Get(ctx, good, registeredID); err == nil {
		t.Fatal("replayed destroyed key remained available")
	}
	otherTenant, err := NewDurable(ctx, "tenant-b", certAuth{}, &auditsink.Recorder{}, log, wrapper)
	if err != nil {
		t.Fatalf("other tenant durable server: %v", err)
	}
	defer otherTenant.Close()
	ids, err := otherTenant.Locate(ctx, good, "AES")
	if err != nil {
		t.Fatalf("other tenant Locate: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("other tenant observed ids %v", ids)
	}

	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if bytes.Contains(ev.Data, keyMaterial) {
			t.Fatalf("state event %q contains plaintext key material", ev.Type)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect state events: %v", err)
	}
}

func TestKMIPDurableReplayKeepsTenantDomainCiphertextAndSealBlocksWholeFrame(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	deployment, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deployment.Destroy)
	domainKey, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(domainKey.Destroy)
	const tenantID = "tenant-domain-kmip"
	const objectID = "kmip-1"
	binding := []byte("tenant-domain-kmip/domain-1/generation-1")
	keyMaterial := []byte("0123456789abcdef0123456789abcdef")
	aad := (&Server{tenantID: tenantID}).stateAAD(objectID, 1)
	sealedKey, err := seal.SealDomain(domainKey, keyMaterial, aad, binding)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(kmipStateEvent{
		ID: objectID, Algorithm: "AES", State: StateActive, Version: 1, SealedKey: sealedKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: kmipStateCreatedEventType, TenantID: tenantID, Data: data}); err != nil {
		t.Fatal(err)
	}
	access := &switchableKMIPTenantAccess{
		tenantID: tenantID,
		cipher:   kmipDomainCipher{key: domainKey, binding: binding},
	}
	service, err := NewDurable(ctx, tenantID, certAuth{}, &auditsink.Recorder{}, log, deployment, access)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if cached := service.objects[objectID].sealedKey; bytes.Contains(cached, keyMaterial) {
		t.Fatal("KMIP replay cached plaintext managed-key bytes")
	}
	opened, err := service.Get(ctx, []byte("good-client"), objectID)
	if err != nil || !bytes.Equal(opened, keyMaterial) {
		secret.Wipe(opened)
		t.Fatalf("tenant-domain KMIP Get failed: %v", err)
	}
	secret.Wipe(opened)
	if plaintext, err := seal.Open(deployment, sealedKey, aad); err == nil {
		secret.Wipe(plaintext)
		t.Fatal("deployment KEK opened tenant-domain KMIP state")
	}

	access.blocked = true
	if _, err := service.Get(ctx, []byte("good-client"), objectID); err == nil {
		t.Fatal("sealed tenant opened KMIP managed object")
	}
	if _, err := service.HandleFrame(ctx, []byte("good-client"), kmipRequestFrame(OperationQuery, nil)); err == nil {
		t.Fatal("sealed tenant entered KMIP frame dispatch")
	}
}
