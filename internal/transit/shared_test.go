// SPDX-License-Identifier: BUSL-1.1

package transit_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/transit"
)

// memKeyringStore is one database's transit_keyrings table: sealed rows with a
// compare-and-swap revision.
type memKeyringStore struct {
	mu     sync.Mutex
	rows   map[string][]byte
	revs   map[string]int64
	saves  int
	failOn int // fail the Nth save with an error
	// beforeSave runs once before the next save, under no lock: a test uses
	// it to let another replica save first.
	beforeSave func()
}

func newMemKeyringStore() *memKeyringStore {
	return &memKeyringStore{rows: map[string][]byte{}, revs: map[string]int64{}}
}

func (m *memKeyringStore) LoadTransitKeyring(_ context.Context, tenantID string) ([]byte, int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[tenantID]
	return append([]byte(nil), row...), m.revs[tenantID], ok, nil
}

func (m *memKeyringStore) SaveTransitKeyring(_ context.Context, tenantID string, sealed []byte, expected int64) (int64, bool, error) {
	if hook := m.takeHook(); hook != nil {
		hook()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	if m.failOn > 0 && m.saves == m.failOn {
		return 0, false, errors.New("database unavailable")
	}
	if m.revs[tenantID] != expected {
		return 0, false, nil
	}
	m.revs[tenantID]++
	m.rows[tenantID] = append([]byte(nil), sealed...)
	return m.revs[tenantID], true, nil
}

func (m *memKeyringStore) takeHook() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	hook := m.beforeSave
	m.beforeSave = nil
	return hook
}

// kekSealer seals tenant keyrings under one local KEK, as a tenant on the
// legacy deployment KEK is sealed.
type kekSealer struct {
	kek      *seal.LocalKEK
	failOpen bool
}

func newKEKSealer(t *testing.T) *kekSealer {
	t.Helper()
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := seal.NewLocalKEK(raw)
	secret.Wipe(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	return &kekSealer{kek: kek}
}

func (k *kekSealer) SealTenantKeyring(_ context.Context, _ string, plaintext, aad []byte) ([]byte, error) {
	return seal.Seal(k.kek, plaintext, aad)
}

func (k *kekSealer) OpenTenantKeyring(_ context.Context, _ string, sealed, aad []byte) ([]byte, error) {
	if k.failOpen {
		return nil, errors.New("tenant key domain sealed")
	}
	return seal.Open(k.kek, sealed, aad)
}

func sharedReplica(t *testing.T, store transit.TenantKeyringStore, sealer transit.TenantSealer) *transit.Service {
	t.Helper()
	svc := transit.NewService(nil)
	if err := svc.SetSharedPersistence(store, sealer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Destroy)
	return svc
}

const tenantA = "11111111-1111-4111-8111-111111111111"

// A125: two replicas over one keyring table. A key created and rotated on one
// encrypts there and decrypts on the other; HMAC agrees; a signature from a
// newer version verifies on the other; listing shows the other's keys; and a
// restarted replica decrypts what came before it. The stored row is sealed.
func TestTransitKeysAreSharedByReplicas(t *testing.T) {
	ctx := context.Background()
	store, sealer := newMemKeyringStore(), newKEKSealer(t)
	a, b := sharedReplica(t, store, sealer), sharedReplica(t, store, sealer)

	if _, err := a.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err != nil {
		t.Fatal(err)
	}
	v1, err := a.Encrypt(ctx, tenantA, "orders", []byte("order 1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Decrypt(ctx, tenantA, "orders", v1, nil); err != nil || string(got) != "order 1" {
		t.Fatalf("decrypt on the other replica = %q, %v", got, err)
	}
	if info, err := a.Rotate(ctx, tenantA, "orders"); err != nil || info.Version != 2 {
		t.Fatalf("rotate = %+v, %v", info, err)
	}
	v2, err := a.Encrypt(ctx, tenantA, "orders", []byte("order 2"), nil)
	if err != nil || !strings.HasPrefix(v2, "trv:2:") {
		t.Fatalf("encrypt after rotate = %q, %v", v2, err)
	}
	if got, err := b.Decrypt(ctx, tenantA, "orders", v2, nil); err != nil || string(got) != "order 2" {
		t.Fatalf("decrypt of the new version on the other replica = %q, %v", got, err)
	}
	if keys, err := b.ListKeys(ctx, tenantA); err != nil || len(keys) != 1 || keys[0].Version != 2 {
		t.Fatalf("list on the other replica = %+v, %v", keys, err)
	}

	if _, err := b.CreateKey(ctx, tenantA, "tokens", transit.KindHMAC); err != nil {
		t.Fatal(err)
	}
	macB, err := b.HMAC(ctx, tenantA, "tokens", []byte("t-1"))
	if err != nil {
		t.Fatal(err)
	}
	if macA, err := a.HMAC(ctx, tenantA, "tokens", []byte("t-1")); err != nil || !bytes.Equal(macA, macB) {
		t.Fatalf("HMAC across replicas = %x vs %x, %v", macA, macB, err)
	}

	if _, err := a.CreateKey(ctx, tenantA, "release", transit.KindSign); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Rotate(ctx, tenantA, "release"); err != nil {
		t.Fatal(err)
	}
	sig, pub, err := a.Sign(ctx, tenantA, "release", []byte("v1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.VerifyNamed(ctx, tenantA, "release", []byte("v1.2.3"), sig, pub); err != nil {
		t.Fatalf("verify of the newer signing version on the other replica: %v", err)
	}

	restarted := sharedReplica(t, store, sealer)
	for ct, want := range map[string]string{v1: "order 1", v2: "order 2"} {
		if got, err := restarted.Decrypt(ctx, tenantA, "orders", ct, nil); err != nil || string(got) != want {
			t.Fatalf("decrypt after a restart = %q, %v", got, err)
		}
	}
	row, _, _, _ := store.LoadTransitKeyring(ctx, tenantA)
	if bytes.Contains(row, []byte("trstctl.transit")) || bytes.Contains(row, []byte(`"keys"`)) {
		t.Fatal("the stored keyring row is not sealed")
	}
	if keys, err := a.ListKeys(ctx, "22222222-2222-4222-8222-222222222222"); err != nil || len(keys) != 0 {
		t.Fatalf("an empty tenant lists %+v, %v", keys, err)
	}
}

// A replica that loses a save to another replica catches up and applies its
// change again: both keys survive, and creating a key the other replica
// already made reports it exists.
func TestATransitSaveLostToAnotherReplicaIsReapplied(t *testing.T) {
	ctx := context.Background()
	store, sealer := newMemKeyringStore(), newKEKSealer(t)
	a, b := sharedReplica(t, store, sealer), sharedReplica(t, store, sealer)
	if _, err := a.ListKeys(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	store.beforeSave = func() {
		if _, err := b.CreateKey(ctx, tenantA, "from-b", transit.KindAEAD); err != nil {
			t.Errorf("the other replica's create: %v", err)
		}
	}
	if _, err := a.CreateKey(ctx, tenantA, "from-a", transit.KindAEAD); err != nil {
		t.Fatalf("a create that lost one save: %v", err)
	}
	for _, svc := range []*transit.Service{a, b} {
		keys, err := svc.ListKeys(ctx, tenantA)
		if err != nil || len(keys) != 2 {
			t.Fatalf("keys after the conflict = %+v, %v", keys, err)
		}
	}
	if _, err := a.CreateKey(ctx, tenantA, "from-b", transit.KindAEAD); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("creating a key the other replica made = %v, want exists", err)
	}
}

// A save that fails rolls the change back, so the key is neither usable nor
// stuck as "exists"; a keyring that cannot be opened fails the operation.
func TestASharedTransitKeyringFailsClosed(t *testing.T) {
	ctx := context.Background()
	store, sealer := newMemKeyringStore(), newKEKSealer(t)
	a := sharedReplica(t, store, sealer)
	store.failOn = 1
	if _, err := a.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err == nil {
		t.Fatal("a create whose save failed reported success")
	}
	if _, err := a.Encrypt(ctx, tenantA, "orders", []byte("x"), nil); err == nil {
		t.Fatal("a key whose save failed encrypts")
	}
	if _, err := a.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err != nil {
		t.Fatalf("the retried create: %v", err)
	}
	locked := &kekSealer{kek: sealer.kek, failOpen: true}
	other := sharedReplica(t, store, locked)
	if _, err := other.Encrypt(ctx, tenantA, "orders", []byte("x"), nil); err == nil {
		t.Fatal("a replica that cannot open the keyring encrypted anyway")
	}
}
