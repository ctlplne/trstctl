// Package federation imports a peer cluster's trstctl event log into the local
// event log, then projects the imported events into the local read model. The
// target cluster's local JetStream remains the source of truth after failover.
package federation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

const (
	DefaultInterval = time.Second
	DefaultRPO      = 5 * time.Second
	DefaultRTO      = 30 * time.Second
)

// Peer is one source cluster this cluster imports from.
type Peer struct {
	ID            string
	Region        string
	SourceNATSURL string
	SourceLog     *events.Log
	OwnsSourceLog bool
}

// Config is the resolved federation configuration. Server.Run fills SourceLog for
// URL-configured peers before constructing the worker; tests may inject SourceLog
// directly.
type Config struct {
	Enabled   bool
	ClusterID string
	Region    string
	Interval  time.Duration
	RPO       time.Duration
	RTO       time.Duration
	Peers     []Peer
}

// CheckpointStore is the durable peer-cursor store. store.Store implements it.
type CheckpointStore interface {
	EnsureFederationCheckpoint(ctx context.Context, peerID string) error
	FederationCheckpoint(ctx context.Context, peerID string) (uint64, error)
	AdvanceFederationCheckpoint(ctx context.Context, peerID string, seq uint64) error
}

// Worker continuously imports source events from configured peers.
type Worker struct {
	dstLog      *events.Log
	projector   *projections.Projector
	checkpoints CheckpointStore
	cfg         Config
	logger      *slog.Logger
}

// Option customizes a Worker.
type Option func(*Worker)

func WithLogger(logger *slog.Logger) Option {
	return func(w *Worker) { w.logger = logger }
}

// New validates cfg, initializes peer checkpoint rows, and returns a worker. A
// disabled config returns nil, nil so callers can keep the served path fail-closed
// until explicitly enabled.
func New(ctx context.Context, dstLog *events.Log, projector *projections.Projector, checkpoints CheckpointStore, cfg Config, opts ...Option) (*Worker, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if dstLog == nil {
		return nil, errors.New("federation: destination event log is required")
	}
	if projector == nil {
		return nil, errors.New("federation: projector is required")
	}
	if checkpoints == nil {
		return nil, errors.New("federation: checkpoint store is required")
	}
	if cfg.ClusterID == "" {
		return nil, errors.New("federation: cluster_id is required")
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("federation: at least one peer is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.RPO <= 0 {
		cfg.RPO = DefaultRPO
	}
	if cfg.RTO <= 0 {
		cfg.RTO = DefaultRTO
	}
	for _, peer := range cfg.Peers {
		if peer.ID == "" {
			return nil, errors.New("federation: peer id is required")
		}
		if peer.ID == cfg.ClusterID {
			return nil, fmt.Errorf("federation: peer %q must not be this cluster", peer.ID)
		}
		if peer.SourceLog == nil {
			return nil, fmt.Errorf("federation: peer %q source log is required", peer.ID)
		}
		if err := checkpoints.EnsureFederationCheckpoint(ctx, peer.ID); err != nil {
			return nil, err
		}
	}
	w := &Worker{dstLog: dstLog, projector: projector, checkpoints: checkpoints, cfg: cfg}
	for _, opt := range opts {
		opt(w)
	}
	return w, nil
}

// Run imports peers immediately, then on the configured interval until ctx ends.
func (w *Worker) Run(ctx context.Context) error {
	if w == nil {
		return nil
	}
	if err := w.RunOnce(ctx); err != nil {
		return err
	}
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := w.RunOnce(ctx); err != nil {
				return err
			}
		}
	}
}

// RunOnce imports and projects all currently available peer events.
func (w *Worker) RunOnce(ctx context.Context) error {
	if w == nil {
		return nil
	}
	for _, peer := range w.cfg.Peers {
		if err := w.replicatePeer(ctx, peer); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) replicatePeer(ctx context.Context, peer Peer) error {
	checkpoint, err := w.checkpoints.FederationCheckpoint(ctx, peer.ID)
	if err != nil {
		return err
	}
	imported := 0
	err = peer.SourceLog.Replay(ctx, checkpoint+1, func(source events.Event) error {
		sourceSeq := source.Sequence
		local, err := w.dstLog.Import(ctx, source)
		if err != nil {
			return fmt.Errorf("federation: import peer %q seq %d: %w", peer.ID, sourceSeq, err)
		}
		if err := w.projector.Apply(ctx, local); err != nil {
			return fmt.Errorf("federation: project peer %q seq %d: %w", peer.ID, sourceSeq, err)
		}
		if err := w.projector.AdvanceCheckpoint(ctx, local.Sequence); err != nil {
			return fmt.Errorf("federation: advance projection checkpoint for peer %q seq %d: %w", peer.ID, sourceSeq, err)
		}
		if err := w.checkpoints.AdvanceFederationCheckpoint(ctx, peer.ID, sourceSeq); err != nil {
			return err
		}
		imported++
		return nil
	})
	if err != nil {
		return err
	}
	if imported > 0 && w.logger != nil {
		w.logger.Info("federation peer import applied",
			slog.String("peer_id", peer.ID), slog.String("peer_region", peer.Region), slog.Int("events", imported))
	}
	return nil
}

// Close releases any source logs this worker opened from configuration.
func (w *Worker) Close() error {
	if w == nil {
		return nil
	}
	var errs []error
	for _, peer := range w.cfg.Peers {
		if peer.OwnsSourceLog && peer.SourceLog != nil {
			if err := peer.SourceLog.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close federation peer %q: %w", peer.ID, err))
			}
		}
	}
	return errors.Join(errs...)
}
