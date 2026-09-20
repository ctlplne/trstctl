// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/store"
)

func TestNotificationOwnershipClosesExactlyOnceWhenEditionAttacherFails(t *testing.T) {
	original := &closeProbeNotificationChannel{}
	attached := &closeProbeNotificationChannel{}
	deps := Deps{NotificationChannels: []notify.Notifier{original}}
	wantErr := errors.New("edition attach failed")
	err := applyEditionAttachers(
		context.Background(), &config.Config{}, nil, license.Community(), &deps,
		func(context.Context, *config.Config, *slog.Logger, *license.Manager, *Deps) error {
			// A failing attacher may replace rather than append. The ownership
			// boundary must retain the original credential as well as adopting
			// the replacement so neither can leak.
			deps.NotificationChannels = []notify.Notifier{attached}
			return wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("applyEditionAttachers error = %v, want %v", err, wantErr)
	}
	// A second defensive Run cleanup must be harmless.
	ensureNotificationChannelOwnership(&deps).closeUntransferred()
	if got := original.closed.Load(); got != 1 {
		t.Fatalf("original notifier close count = %d, want exactly 1", got)
	}
	if got := attached.closed.Load(); got != 1 {
		t.Fatalf("attacher-added notifier close count = %d, want exactly 1", got)
	}
}

func TestBuildClosesNotificationExactlyOnceBeforeDispatcherOwnership(t *testing.T) {
	channel := &closeProbeNotificationChannel{}
	_, err := Build(context.Background(), Deps{NotificationChannels: []notify.Notifier{channel}})
	if err == nil {
		t.Fatal("Build without store/log succeeded")
	}
	if got := channel.closed.Load(); got != 1 {
		t.Fatalf("notifier close count = %d, want exactly 1", got)
	}
}

func TestBuildClosesNotificationExactlyOnceAfterDispatcherOwnership(t *testing.T) {
	st, log := notificationOwnershipTestStack(t)
	channel := &closeProbeNotificationChannel{}
	wantErr := errors.New("licensed outbox construction failed")
	factoryCalled := false
	_, err := Build(context.Background(), Deps{
		Store:                st,
		Log:                  log,
		NotificationChannels: []notify.Notifier{channel},
		LicensedOutboxFactory: func(LicensedOutboxDeps) (LicensedOutboxHandler, error) {
			factoryCalled = true
			return nil, wantErr
		},
	})
	if !factoryCalled {
		t.Fatal("Build failed before the post-dispatcher ownership window")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("Build error = %v, want %v", err, wantErr)
	}
	if got := channel.closed.Load(); got != 1 {
		t.Fatalf("notifier close count = %d, want exactly 1", got)
	}
}

func TestSuccessfulBuildTransfersNotificationOwnershipToShutdown(t *testing.T) {
	st, log := notificationOwnershipTestStack(t)
	channel := &closeProbeNotificationChannel{}
	srv, err := Build(context.Background(), Deps{
		Store: st, Log: log, NotificationChannels: []notify.Notifier{channel},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := channel.closed.Load(); got != 0 {
		t.Fatalf("notifier close count after successful Build = %d, want 0", got)
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := channel.closed.Load(); got != 1 {
		t.Fatalf("notifier close count after Shutdown = %d, want exactly 1", got)
	}
	// Dispatcher.Close itself is defensive and must not re-close credentials.
	srv.notifications.Close()
	if got := channel.closed.Load(); got != 1 {
		t.Fatalf("notifier close count after repeated dispatcher close = %d, want exactly 1", got)
	}
}

func notificationOwnershipTestStack(t *testing.T) (*store.Store, *events.Log) {
	t.Helper()
	st := newServerTestStore(t)
	log, err := events.Open(context.Background(), config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return st, log
}
