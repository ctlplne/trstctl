// SPDX-License-Identifier: BUSL-1.1
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"
)

type commandHistoryReadKey struct{}

type commandHistoryReadCoordinator struct{}

func (commandHistoryReadCoordinator) WithRead(ctx context.Context, fn func(context.Context) error) error {
	return fn(context.WithValue(ctx, commandHistoryReadKey{}, true))
}

func (commandHistoryReadCoordinator) WithCutover(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (commandHistoryReadCoordinator) WithRewriteOperation(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func TestTenantCommandBindsSharedKeyStateOwnerBeforeCallback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	dir := t.TempDir()
	// #nosec G115 -- net.TCPAddr.Port is bounded to the 16-bit TCP port range
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).Port(uint32(port)).
		RuntimePath(dir + "/rt").DataPath(dir + "/data").BinariesPath(dir + "/bin").
		Logger(io.Discard).StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Stop() })
	s, err := store.Open(t.Context(), fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{store: s}
	const tenantID = "11111111-1111-1111-1111-111111111111"
	if err := o.withTenantCommand(t.Context(), tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return s.RequireKeyStateOwnerTx(ctx, tx, tenantID, store.KeyStateShared)
	}); err != nil {
		t.Fatalf("ordinary command did not own global A and transaction B before callback: %v", err)
	}
	const eventID = "plain-command-projection-rollback"
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenantID, eventID)
	})
	rollback := errors.New("plain command transaction rollback")
	err = o.withTenantCommand(t.Context(), tenantID, func(ctx context.Context, _ pgx.Tx) error {
		if err := s.WithRestoreEventIngress(ctx, tenantID, eventID, "tenant.registered",
			func(context.Context) error { return nil }); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("owner rollback=%v, want caller error", err)
	}
	var pending int
	if err := s.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND event_id=$2 AND activity_kind='projection' AND phase='started'`,
		tenantID, eventID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("owner rollback after ingress callback left %d pending projection tokens, want one", pending)
	}
	// The broker ACK survives a PostgreSQL command rollback. Its separate
	// projection token must likewise survive for a later canonical tail replay.
	const brokerEventID = "plain-command-broker-ack-rollback"
	t.Cleanup(func() {
		_, _ = s.SystemPool().Exec(context.Background(),
			`DELETE FROM trstctl_recovery.restore_activity_tokens WHERE tenant_id=$1 AND event_id=$2`, tenantID, brokerEventID)
	})
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithHistoryRewriteCoordinator(commandHistoryReadCoordinator{}),
		events.WithRequiredAppendAdmission(),
		events.WithAppendAdmission(func(ctx context.Context, event events.Event,
			publish func(context.Context) (events.Event, error),
		) (events.Event, error) {
			var published events.Event
			err := s.WithRestoreEventIngress(ctx, event.TenantID, event.ID, event.Type,
				func(admitted context.Context) error {
					var publishErr error
					published, publishErr = publish(admitted)
					return publishErr
				})
			return published, err
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	o.log = log
	err = o.withTenantCommand(t.Context(), tenantID, func(ctx context.Context, _ pgx.Tx) error {
		if ctx.Value(commandHistoryReadKey{}) != true {
			return errors.New("command transaction opened before the event history read session")
		}
		appended, err := log.Append(ctx, events.Event{
			ID: brokerEventID, Type: "owner.created", TenantID: tenantID,
			Data: []byte(`{"id":"11111111-1111-4111-8111-111111111112","kind":"person","name":"Plain Owner","email":"owner@example.test"}`),
		})
		if err != nil || appended.Sequence != 1 {
			return fmt.Errorf("broker append: event=%+v err=%w", appended, err)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("broker-backed command rollback=%v", err)
	}
	if _, found, err := log.EventByID(t.Context(), brokerEventID); err != nil || !found {
		t.Fatalf("broker ACK disappeared with SQL rollback: found=%t err=%v", found, err)
	}
	if err := s.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND event_id=$2 AND activity_kind='projection' AND phase='started'`,
		tenantID, brokerEventID).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("broker-backed command left projection starts=%d err=%v", pending, err)
	}
	// CR-045: a new projector has no pointer to the rolled-back command owner.
	// Its canonical replay must settle the durable second token as part of the
	// projection commit, so restore cannot stay fenced forever after a broker ACK.
	if err := s.UpsertTenant(t.Context(), store.Tenant{TenantID: tenantID, Name: "replay fixture"}); err != nil {
		t.Fatal(err)
	}
	canonical, found, err := log.EventByID(t.Context(), brokerEventID)
	if err != nil || !found {
		t.Fatalf("canonical replay event: found=%t err=%v", found, err)
	}
	projector := projections.New(s, projections.WithCanonicalEventSource(log))
	if err := projector.Apply(t.Context(), canonical); err != nil {
		t.Fatalf("canonical replay after owner rollback: %v", err)
	}
	var phase string
	if err := s.SystemPool().QueryRow(t.Context(), `SELECT phase FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND event_id=$2 AND activity_kind='projection' AND lane='command-apply'`,
		tenantID, brokerEventID).Scan(&phase); err != nil || phase != "terminal" {
		t.Fatalf("canonical replay projection phase=%q err=%v, want terminal", phase, err)
	}
}
