package server

import (
	"context"
	"log/slog"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

type fakeFederationWorker struct{}

func (fakeFederationWorker) Run(context.Context) error { return nil }
func (fakeFederationWorker) Close() error              { return nil }

func TestFederationFactoryIsOnlyConstructionPath(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	log := openServerFederationSeamTestLog(t)

	core, err := Build(ctx, Deps{Store: st, Log: log})
	if err != nil {
		t.Fatalf("build core server: %v", err)
	}
	if core.federation != nil {
		t.Fatal("core build without an edition federation factory must not configure federation")
	}
	t.Cleanup(func() { _ = core.Shutdown(context.Background()) })

	var called bool
	licensed, err := Build(ctx, Deps{
		Store: st,
		Log:   log,
		FederationFactory: func(ctx context.Context, dst *events.Log, proj *projections.Projector, checkpoints FederationCheckpointStore, logger *slog.Logger) (FederationWorker, error) {
			called = true
			if dst != log || checkpoints == nil || proj == nil || logger == nil {
				t.Fatal("federation factory did not receive the server spine dependencies")
			}
			return fakeFederationWorker{}, nil
		},
	})
	if err != nil {
		t.Fatalf("build licensed server: %v", err)
	}
	t.Cleanup(func() { _ = licensed.Shutdown(context.Background()) })
	if !called || licensed.federation == nil {
		t.Fatal("licensed federation factory was not used")
	}
}

func openServerFederationSeamTestLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}
