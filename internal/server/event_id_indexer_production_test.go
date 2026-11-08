// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/store"
)

// A266: the production event log keeps its identity projection within one
// lookup's reach in the background. After a burst of commands no lookup
// touched — an inventory import records one event per certificate — a keyed
// command such as an issuance finds or refutes its event identity at once,
// instead of failing with ErrEventIDIndexBehind until enough lookups have
// caught the index up (each lookup advances it by a bounded step of 1,024
// events and then refuses).
func TestProductionEventLogIndexesIdentitiesInTheBackground(t *testing.T) {
	ctx := context.Background()
	const tenantID = "a2660000-0000-4000-8000-000000000266"
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "identity index burst"}); err != nil {
		t.Fatal(err)
	}
	auditKey, err := jose.GenerateRSASigningKey("a266-identity-index")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, st, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()

	const burst = 2600 // more than two bounded lookup steps
	for i := 0; i < burst; i++ {
		if _, err := srv.orch.CreateOwnerRecord(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerTeam,
			Name: fmt.Sprintf("burst team %04d", i), Email: fmt.Sprintf("team-%04d@a266.test", i)}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Minute)
	for {
		covered, head, err := log.EventIDIndexCovered(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if head >= burst && head-covered < 1024 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the production log left its identity projection at %d of %d after the burst", covered, head)
		}
		time.Sleep(25 * time.Millisecond)
	}
	_, head, err := log.EventIDIndexCovered(ctx)
	if err != nil {
		t.Fatal(err)
	}
	last, found, err := log.EventAtSequence(ctx, head)
	if err != nil || !found || last.ID == "" {
		t.Fatalf("head event %d = %+v, %t, %v", head, last, found, err)
	}
	if got, found, err := log.EventByID(ctx, last.ID); err != nil || !found || got.Sequence != head {
		t.Fatalf("the first lookup after the burst = %+v, %t, %v; want the indexed head", got, found, err)
	}
	if _, found, err := log.EventByID(ctx, "a266-never-appended"); err != nil || found {
		t.Fatalf("an absent identity after the burst = %t, %v; want a definite miss", found, err)
	}
}
