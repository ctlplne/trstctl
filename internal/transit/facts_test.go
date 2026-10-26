// SPDX-License-Identifier: BUSL-1.1

package transit_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/transit"
)

// memFactLog is the event log's transit facts: one record per fact ID.
type memFactLog struct {
	mu      sync.Mutex
	facts   map[string]transit.Fact
	at      map[string]time.Time
	order   []transit.Fact
	failing bool
}

func newMemFactLog() *memFactLog {
	return &memFactLog{facts: map[string]transit.Fact{}, at: map[string]time.Time{}}
}

func (l *memFactLog) Recorded(_ context.Context, _ string, ids []string) (map[string]time.Time, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]time.Time{}
	for _, id := range ids {
		if at, ok := l.at[id]; ok {
			out[id] = at
		}
	}
	return out, nil
}

func (l *memFactLog) Record(_ context.Context, _ string, f transit.Fact) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failing {
		return errors.New("event log unavailable")
	}
	if _, ok := l.facts[f.ID]; ok {
		return nil
	}
	l.facts[f.ID], l.at[f.ID] = f, time.Now()
	l.order = append(l.order, f)
	return nil
}

func (l *memFactLog) recorded() []transit.Fact {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]transit.Fact(nil), l.order...)
}

func (l *memFactLog) setFailing(v bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failing = v
}

func factReplica(t *testing.T, store transit.TenantKeyringStore, sealer transit.TenantSealer, log transit.FactRecorder) *transit.Service {
	t.Helper()
	svc := sharedReplica(t, store, sealer)
	svc.SetFactRecorder(log)
	return svc
}

// A126: a create and each rotation become facts in the event log naming the
// key, its kind and the version, each under its own fact ID, appended only
// after the version's material is saved. A rotation on another replica adds
// its own fact, the versions listing on either replica names every version's
// fact as recorded, and a rotation whose save fails records nothing.
func TestTransitLifecycleFactsFollowTheSave(t *testing.T) {
	ctx := context.Background()
	store, sealer, log := newMemKeyringStore(), newKEKSealer(t), newMemFactLog()
	a, b := factReplica(t, store, sealer, log), factReplica(t, store, sealer, log)

	if _, err := a.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Rotate(ctx, tenantA, "orders"); err != nil {
		t.Fatal(err)
	}
	if info, err := b.Rotate(ctx, tenantA, "orders"); err != nil || info.Version != 3 {
		t.Fatalf("rotate on the other replica = %+v, %v", info, err)
	}
	facts := log.recorded()
	if len(facts) != 3 {
		t.Fatalf("facts = %+v, want a creation and two rotations", facts)
	}
	seen := map[string]bool{}
	for i, f := range facts {
		wantType := transit.EventKeyRotated
		if i == 0 {
			wantType = transit.EventKeyCreated
		}
		if f.Key != "orders" || f.Kind != transit.KindAEAD || f.Version != i+1 || f.EventType() != wantType ||
			!transit.ValidFactID(f.ID) || seen[f.ID] {
			t.Fatalf("fact %d = %+v (%s)", i, f, f.EventType())
		}
		seen[f.ID] = true
	}
	for _, replica := range []*transit.Service{a, b} {
		_, versions, err := replica.ListKeyVersions(ctx, tenantA, "orders")
		if err != nil || len(versions) != 3 {
			t.Fatalf("versions = %+v, %v", versions, err)
		}
		for i, v := range versions {
			if v.FactID != facts[i].ID || !v.Recorded || v.RecordedAt.IsZero() {
				t.Fatalf("version %d = %+v, want fact %s recorded", v.Version, v, facts[i].ID)
			}
		}
	}

	store.mu.Lock()
	store.failOn = store.saves + 1
	store.mu.Unlock()
	if _, err := a.Rotate(ctx, tenantA, "orders"); err == nil {
		t.Fatal("a rotation whose save failed was reported")
	}
	if got := len(log.recorded()); got != 3 {
		t.Fatalf("a rotation whose save failed recorded a fact (%d facts)", got)
	}
}

// When the event log is down the key is still created and usable; its version
// lists as not recorded, and a reconcile records the fact once.
func TestATransitFactWhoseAppendFailedIsRecordedByReconcile(t *testing.T) {
	ctx := context.Background()
	store, sealer, log := newMemKeyringStore(), newKEKSealer(t), newMemFactLog()
	a := factReplica(t, store, sealer, log)

	log.setFailing(true)
	if _, err := a.CreateKey(ctx, tenantA, "tokens", transit.KindHMAC); err != nil {
		t.Fatalf("create while the event log is down: %v", err)
	}
	if _, err := a.HMAC(ctx, tenantA, "tokens", []byte("x")); err != nil {
		t.Fatalf("the created key is not usable: %v", err)
	}
	_, versions, err := a.ListKeyVersions(ctx, tenantA, "tokens")
	if err != nil || len(versions) != 1 || versions[0].Recorded || versions[0].FactID == "" {
		t.Fatalf("versions while the fact is missing = %+v, %v", versions, err)
	}
	if err := a.ReconcileFacts(ctx, tenantA); err == nil {
		t.Fatal("a reconcile while the event log is down reported success")
	}

	log.setFailing(false)
	for range 2 {
		if err := a.ReconcileFacts(ctx, tenantA); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	facts := log.recorded()
	if len(facts) != 1 || facts[0].ID != versions[0].FactID || facts[0].EventType() != transit.EventKeyCreated {
		t.Fatalf("facts after reconcile = %+v", facts)
	}
	if _, versions, err = a.ListKeyVersions(ctx, tenantA, "tokens"); err != nil || !versions[0].Recorded {
		t.Fatalf("versions after reconcile = %+v, %v", versions, err)
	}
}

// A keyring saved before facts existed has versions with no fact ID. Reconcile
// gives each one a fact ID saved with its material (so every replica names the
// same fact) and records a creation and a rotation; a second reconcile changes
// nothing.
func TestReconcileRecordsFactsForAKeyringSavedBeforeFacts(t *testing.T) {
	ctx := context.Background()
	store, sealer, log := newMemKeyringStore(), newKEKSealer(t), newMemFactLog()
	v1, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(map[string]any{
		"format": "trstctl.transit.tenant-keyring.v1", "tenant_id": tenantA,
		"keys": map[string]any{"legacy": map[string]any{
			"kind": "hmac", "latest": 2,
			"hmac": []any{nil, base64.StdEncoding.EncodeToString(v1), base64.StdEncoding.EncodeToString(v2)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.SealTenantKeyring(ctx, tenantA, legacy, []byte("trstctl.transit.tenant-keyring.v1|"+tenantA))
	if err != nil {
		t.Fatal(err)
	}
	if _, saved, err := store.SaveTransitKeyring(ctx, tenantA, sealed, 0); err != nil || !saved {
		t.Fatalf("store the legacy keyring: %v", err)
	}

	a, b := factReplica(t, store, sealer, log), factReplica(t, store, sealer, log)
	before := store.saves
	if err := a.ReconcileFacts(ctx, tenantA); err != nil {
		t.Fatalf("reconcile the legacy keyring: %v", err)
	}
	facts := log.recorded()
	if len(facts) != 2 || facts[0].EventType() != transit.EventKeyCreated || facts[1].EventType() != transit.EventKeyRotated ||
		facts[0].Kind != transit.KindHMAC || store.saves != before+1 {
		t.Fatalf("facts = %+v after %d saves", facts, store.saves-before)
	}
	_, versions, err := b.ListKeyVersions(ctx, tenantA, "legacy")
	if err != nil || len(versions) != 2 || versions[0].FactID != facts[0].ID || versions[1].FactID != facts[1].ID ||
		!versions[0].Recorded || !versions[1].Recorded {
		t.Fatalf("the other replica's versions = %+v, %v", versions, err)
	}
	if err := b.ReconcileFacts(ctx, tenantA); err != nil || len(log.recorded()) != 2 || store.saves != before+1 {
		t.Fatalf("a second reconcile changed something: %v (%d facts, %d saves)", err, len(log.recorded()), store.saves-before)
	}
	if _, err := b.HMAC(ctx, tenantA, "legacy", []byte("still works")); err != nil {
		t.Fatalf("the legacy key after reconcile: %v", err)
	}
}

// Without a fact recorder the service keeps the audit record, now only after
// the save: a create whose save fails records nothing.
func TestTransitAuditRecordFollowsTheSaveWithoutAFactRecorder(t *testing.T) {
	ctx := context.Background()
	audit := &auditsink.Recorder{}
	store, sealer := newMemKeyringStore(), newKEKSealer(t)
	svc := transit.NewService(audit)
	if err := svc.SetSharedPersistence(store, sealer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Destroy)
	store.failOn = 1
	if _, err := svc.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err == nil {
		t.Fatal("a create whose save failed was reported")
	}
	if n := audit.Count(transit.EventKeyCreated); n != 0 {
		t.Fatalf("a create whose save failed was audited %d times", n)
	}
	if _, err := svc.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err != nil {
		t.Fatal(err)
	}
	if n := audit.Count(transit.EventKeyCreated); n != 1 {
		t.Fatalf("a saved create was audited %d times", n)
	}
}
