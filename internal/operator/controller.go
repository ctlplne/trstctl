package operator

import (
	"context"
	"log/slog"
	"time"
)

// Options configures the operator's run loop.
type Options struct {
	// Namespace scopes the reconcile. When empty, the operator reconciles the
	// namespace it runs in (the in-cluster service-account namespace). Watching
	// all namespaces would require a list across the cluster; this minimal
	// operator stays namespaced (documented in deploy/operator/doc.go).
	Namespace string
	// ReconcileEvery is the poll interval for the level-based reconcile. A poll
	// loop (rather than informers) keeps the operator dependency-free; a missed
	// change is picked up on the next tick.
	ReconcileEvery time.Duration
	// Logger receives structured, secret-free progress logs. The operator only
	// ever logs resource names, namespaces, actions, and counts — never tokens,
	// keys, or resource bodies.
	Logger *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.ReconcileEvery <= 0 {
		o.ReconcileEvery = 30 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// Run drives the reconcile loop until ctx is cancelled. It reconciles once
// immediately, then on every tick. A transient reconcile error is logged and the
// loop continues (the next tick retries) so a flaky API call does not crash the
// operator. The Kubernetes service-account token authenticating the client is
// never logged.
func Run(ctx context.Context, r *Reconciler, opts Options) error {
	opts = opts.withDefaults()
	log := opts.Logger.With(
		slog.String("component", "trstctl-operator"),
		slog.String("namespace", opts.Namespace),
	)
	log.Info("operator starting", slog.Duration("reconcile_every", opts.ReconcileEvery))

	tick := func() {
		actions, err := r.ReconcileNamespace(ctx, opts.Namespace)
		if err != nil {
			// ctx cancellation surfaces here too; the select below exits cleanly.
			if ctx.Err() != nil {
				return
			}
			log.Error("reconcile failed", slog.String("error", err.Error()))
			return
		}
		created, updated, noop := 0, 0, 0
		for name, a := range actions {
			switch a {
			case ActionCreate:
				created++
			case ActionUpdate:
				updated++
			default:
				noop++
			}
			if a != ActionNone {
				log.Info("converged control plane",
					slog.String("resource", name),
					slog.String("action", string(a)),
				)
			}
		}
		log.Debug("reconcile complete",
			slog.Int("resources", len(actions)),
			slog.Int("created", created),
			slog.Int("updated", updated),
			slog.Int("in_sync", noop),
		)
	}

	tick()
	ticker := time.NewTicker(opts.ReconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("operator stopping")
			return nil
		case <-ticker.C:
			tick()
		}
	}
}
