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
	// LeaderElection makes this process campaign for a Kubernetes Lease before
	// each reconcile. Followers stay hot but do not mutate cluster state.
	LeaderElection bool
	// LeaderIdentity is the holderIdentity written to the Lease. It should be a
	// pod name or hostname so operators can see which replica is active.
	LeaderIdentity string
	// LeaseName is the coordination.k8s.io Lease resource name.
	LeaseName string
	// LeaseDuration is how long a holder can be silent before another replica may
	// acquire leadership.
	LeaseDuration time.Duration
}

func (o Options) withDefaults() Options {
	if o.ReconcileEvery <= 0 {
		o.ReconcileEvery = 30 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.LeaseName == "" {
		o.LeaseName = "trstctl-operator"
	}
	if o.LeaseDuration <= 0 {
		o.LeaseDuration = 15 * time.Second
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
	var elector *LeaseElector
	if opts.LeaderElection {
		elector = NewLeaseElector(r.client, opts.Namespace, opts.LeaseName, opts.LeaderIdentity, opts.LeaseDuration, nil)
		log = log.With(slog.String("leader_identity", opts.LeaderIdentity), slog.String("lease", opts.LeaseName))
	}

	tick := func() {
		if elector != nil {
			leader, err := elector.TryAcquireOrRenew(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Error("leader election failed", slog.String("error", err.Error()))
				return
			}
			if !leader {
				log.Debug("leader election follower; skipping reconcile")
				return
			}
		}
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

		secretActions, err := r.ReconcileSecretSyncNamespace(ctx, opts.Namespace)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("secret sync reconcile failed", slog.String("error", err.Error()))
			return
		}
		secretCreated, secretUpdated, secretNoop := 0, 0, 0
		for name, a := range secretActions {
			switch a {
			case ActionCreate:
				secretCreated++
			case ActionUpdate:
				secretUpdated++
			default:
				secretNoop++
			}
			if a != ActionNone {
				log.Info("converged secret sync",
					slog.String("resource", name),
					slog.String("action", string(a)),
				)
			}
		}
		log.Debug("secret sync reconcile complete",
			slog.Int("resources", len(secretActions)),
			slog.Int("created", secretCreated),
			slog.Int("updated", secretUpdated),
			slog.Int("in_sync", secretNoop),
		)

		injectionActions, err := r.ReconcileSecretInjectionNamespace(ctx, opts.Namespace)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("secret injection reconcile failed", slog.String("error", err.Error()))
			return
		}
		injectionUpdated, injectionNoop := 0, 0
		for name, a := range injectionActions {
			switch a {
			case ActionUpdate:
				injectionUpdated++
			default:
				injectionNoop++
			}
			if a != ActionNone {
				log.Info("converged secret injection",
					slog.String("resource", name),
					slog.String("action", string(a)),
				)
			}
		}
		log.Debug("secret injection reconcile complete",
			slog.Int("resources", len(injectionActions)),
			slog.Int("updated", injectionUpdated),
			slog.Int("in_sync", injectionNoop),
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
