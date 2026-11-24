// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestCR873HistoricalNULDoesNotBlockServedBootForHealthyTenant(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "cr873-served-boot", JetStream: true, StoreDir: t.TempDir(), Port: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		t.Fatal("external file-backed NATS did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSExternal, URL: srv.ClientURL(), Replicas: 1, AllowSingleReplica: true},
		events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)), events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	const poisoned = "11111111-1111-1111-1111-111111111111"
	const healthy = "22222222-2222-2222-2222-222222222222"
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: poisoned,
		Data: json.RawMessage(`{"name":"Poisoned"}`)}); err != nil {
		t.Fatal(err)
	}
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	poisonPayload, err := json.Marshal(projections.TenantMemberUpserted{
		Subject: "old-user", DisplayName: "bad\x00name", Email: "member@example.test", Source: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(map[string]any{
		"id": uuid.NewString(), "type": projections.EventTenantMemberUpserted,
		"tenant_id": poisoned, "time": time.Now().UTC(), "data": poisonPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, "events."+projections.EventTenantMemberUpserted, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: healthy,
		Data: json.RawMessage(`{"name":"Healthy"}`)}); err != nil {
		t.Fatal(err)
	}
	app, err := Build(ctx, Deps{Store: st, Log: log})
	if err != nil {
		t.Fatalf("poisoned tenant prevented healthy tenant boot: %v", err)
	}
	t.Cleanup(func() { _ = app.Shutdown(context.Background()) })
	if err := st.RequireLiveTenantService(ctx, healthy); err != nil {
		t.Errorf("healthy tenant refused after boot: %v", err)
	}
	if err := st.RequireLiveTenantService(ctx, poisoned); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Errorf("poisoned tenant served after boot: %v", err)
	}
	// Exercise the public bearer route too: a stored token for the quarantined
	// tenant cannot read an incomplete inventory, while the neighbor can.
	poisonedToken := seedServedAPIToken(t, ctx, st, poisoned, "poisoned-reader", []string{string(authz.OwnersRead)})
	healthyToken := seedServedAPIToken(t, ctx, st, healthy, "healthy-reader", []string{string(authz.OwnersRead)})
	ts := httptest.NewServer(app.Handler())
	t.Cleanup(ts.Close)
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/owners", poisonedToken, "", nil); code != http.StatusForbidden {
		t.Errorf("poisoned tenant owners read = %d, want 403; body=%s", code, body)
	}
	if code, body := doBearer(t, ts, http.MethodGet, "/api/v1/owners", healthyToken, "", nil); code != http.StatusOK {
		t.Errorf("healthy tenant owners read = %d, want 200; body=%s", code, body)
	}
}
