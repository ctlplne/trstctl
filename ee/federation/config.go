package federation

import (
	"context"
	"fmt"
	"log/slog"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/server"
)

// FactoryFromConfig resolves the operator's federation config and returns the
// worker factory consumed by core. A disabled config returns nil, nil so licensed
// deployments with federation off do not start a dormant worker.
func FactoryFromConfig(ctx context.Context, cfg config.Federation) (server.FederationFactory, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	resolved, err := ConfigFromConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return NewFactory(resolved), nil
}

// ConfigFromConfig opens peer source logs and translates core config into the
// EE worker config. The checkpoint store remains core; only the cross-cluster
// worker and peer-source ownership live in ee/.
func ConfigFromConfig(ctx context.Context, cfg config.Federation) (Config, error) {
	if !cfg.Enabled {
		return Config{}, nil
	}
	interval, err := cfg.IntervalDuration()
	if err != nil {
		return Config{}, fmt.Errorf("federation interval: %w", err)
	}
	rpo, err := cfg.RPODuration()
	if err != nil {
		return Config{}, fmt.Errorf("federation rpo: %w", err)
	}
	rto, err := cfg.RTODuration()
	if err != nil {
		return Config{}, fmt.Errorf("federation rto: %w", err)
	}
	out := Config{
		Enabled: cfg.Enabled, ClusterID: cfg.ClusterID, Region: cfg.Region,
		Interval: interval, RPO: rpo, RTO: rto,
	}
	for _, p := range cfg.Peers {
		source, err := events.OpenExternalSource(ctx, p.NATSURL)
		if err != nil {
			closeOwnedPeers(out)
			return Config{}, fmt.Errorf("open federation peer %q: %w", p.ID, err)
		}
		out.Peers = append(out.Peers, Peer{
			ID: p.ID, Region: p.Region, SourceNATSURL: p.NATSURL,
			SourceLog: source, OwnsSourceLog: true,
		})
	}
	return out, nil
}

func closeOwnedPeers(cfg Config) {
	for _, opened := range cfg.Peers {
		if opened.OwnsSourceLog && opened.SourceLog != nil {
			_ = opened.SourceLog.Close()
		}
	}
}

// NewFactory adapts the EE federation worker to the core server seam.
func NewFactory(cfg Config) server.FederationFactory {
	return func(ctx context.Context, dst *events.Log, proj *projections.Projector, checkpoints server.FederationCheckpointStore, logger *slog.Logger) (server.FederationWorker, error) {
		return New(ctx, dst, proj, checkpoints, cfg, WithLogger(logger))
	}
}
