package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/federation"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const federationTenantA = "11111111-1111-1111-1111-111111111111"

func TestFederationReplicatesTrustAndReadStateForFailover(t *testing.T) {
	ctx := context.Background()
	sourceStore := newIsolatedServerTestStore(t, "fed_src")
	targetStore := newIsolatedServerTestStore(t, "fed_dst")
	sourceLog := openServerTestLog(t)
	targetLog := openServerTestLog(t)

	sourceProjector := projections.New(sourceStore)
	targetProjector := projections.New(targetStore)
	tenantEvent := mustJSON(t, struct {
		Name string `json:"name"`
	}{Name: "Acme East"})
	trustEvent := mustJSON(t, projections.IssuerCreated{
		ID:       "00000000-0000-0000-0000-00000000f001",
		Kind:     string(store.IssuerX509CA),
		Name:     "east-root-ca",
		Chain:    []string{"-----BEGIN CERTIFICATE-----\nsource-trust-root\n-----END CERTIFICATE-----"},
		Internal: true,
	})

	if _, err := sourceLog.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: federationTenantA, Data: tenantEvent}); err != nil {
		t.Fatalf("append source tenant event: %v", err)
	}
	if _, err := sourceLog.Append(ctx, events.Event{Type: projections.EventIssuerCreated, TenantID: federationTenantA, Data: trustEvent}); err != nil {
		t.Fatalf("append source trust event: %v", err)
	}
	if err := sourceProjector.Project(ctx, sourceLog); err != nil {
		t.Fatalf("project source read state: %v", err)
	}

	const (
		rpo = 2 * time.Second
		rto = 2 * time.Second
	)
	target, err := Build(ctx, Deps{
		Store: targetStore,
		Log:   targetLog,
		Federation: federation.Config{
			Enabled:   true,
			ClusterID: "us-west-passive",
			Region:    "us-west-2",
			Interval:  25 * time.Millisecond,
			RPO:       rpo,
			RTO:       rto,
			Peers: []federation.Peer{{
				ID:        "us-east-primary",
				Region:    "us-east-1",
				SourceLog: sourceLog,
			}},
		},
	})
	if err != nil {
		t.Fatalf("build target cluster: %v", err)
	}
	t.Cleanup(func() { _ = target.Shutdown(context.Background()) })

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go target.RunFederation(runCtx)
	tailErr := make(chan error, 1)
	go func() {
		tailErr <- projections.NewTailWorker(targetLog, targetProjector, nil, 25*time.Millisecond).Run(runCtx)
	}()

	start := time.Now()
	waitForFederatedReadState(t, targetStore, rpo+rto)
	if elapsed := time.Since(start); elapsed > rpo+rto {
		t.Fatalf("federated failover read state became ready after %s, beyond documented RPO+RTO %s", elapsed, rpo+rto)
	}
	cancel()
	select {
	case err := <-tailErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("projection tail exited with error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("projection tail did not stop after cancellation")
	}
}

func waitForFederatedReadState(t *testing.T, st *store.Store, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		tenant, terr := st.GetTenant(context.Background(), federationTenantA)
		issuers, ierr := st.ListIssuers(context.Background(), federationTenantA)
		if terr == nil && tenant.Name == "Acme East" && ierr == nil && len(issuers) == 1 && issuers[0].Name == "east-root-ca" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	tenants, _ := st.ListTenants(context.Background())
	issuers, _ := st.ListIssuers(context.Background(), federationTenantA)
	t.Fatalf("target cluster did not replicate trust/read state in time; tenants=%v issuers=%v", tenants, issuers)
}

func openServerTestLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func newIsolatedServerTestStore(t *testing.T, prefix string) *store.Store {
	t.Helper()
	ctx := context.Background()
	base := serverTestPostgresDSN(t)
	dbName := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect postgres admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create isolated database: %v", err)
	}
	t.Cleanup(func() {
		admin.Close()
		cleanup, err := pgxpool.New(context.Background(), base)
		if err == nil {
			_, _ = cleanup.Exec(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
			cleanup.Close()
		}
	})
	st, err := store.Open(ctx, databaseDSN(t, base, dbName))
	if err != nil {
		t.Fatalf("open isolated store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate isolated store: %v", err)
	}
	return st
}

func databaseDSN(t *testing.T, base, dbName string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse postgres dsn: %v", err)
	}
	u.Path = "/" + dbName
	return u.String()
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return b
}
