// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
)

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
