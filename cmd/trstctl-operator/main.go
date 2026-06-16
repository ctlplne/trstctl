// Command trstctl-operator is the trstctl Kubernetes Operator.
//
// It watches TrstctlControlPlane custom resources (group trstctl.com,
// deploy/operator/crd.yaml) and reconciles each one's declared desired state —
// the control-plane replica count and image — into a managed control-plane
// Deployment, then writes the observed phase back to the resource's status. The
// reconcile is level-based (read the world → diff against the spec → converge),
// so a missed change is corrected on the next poll.
//
// It speaks the Kubernetes API directly over JSON-over-HTTPS with no client-go /
// controller-runtime dependency (none is in go.mod). TLS trust to the API server
// is built through the crypto boundary (internal/crypto/mtls), so this binary
// imports no crypto/* (AN-3). The operator ships inside the same multi-binary
// control-plane image the release pipeline builds (deploy/docker/Dockerfile) and
// runs via an entrypoint override (the same packaging the agent uses, OPS-002).
//
// Maturity is documented honestly in deploy/operator/doc.go: this is a small,
// functional reconcile loop that owns the Deployment's replicas+image; it does
// not yet manage Services, secrets, NetworkPolicy, or the isolated-signer
// topology — those remain the Helm chart's job.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/operator"
)

func main() {
	showVersion := flag.Bool("version", false, "print version information and exit")
	namespace := flag.String("namespace", "", "namespace to reconcile TrstctlControlPlane resources in (default: the operator's own namespace)")
	reconcileEvery := flag.Duration("reconcile-every", 30*time.Second, "how often the level-based reconcile runs")
	// Accepted for forward compatibility with the manifest's args; a single
	// replica is the supported topology today, so this is a no-op that keeps the
	// Deployment's `--leader-elect` arg from being an undefined flag.
	leaderElect := flag.Bool("leader-elect", false, "reserved: run a single active operator replica (single-replica is the supported topology today)")
	logLevel := flag.String("log-level", "info", "log level: debug | info | warn | error")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("trstctl-operator"))
		return
	}
	_ = *leaderElect

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client, podNamespace, err := operator.InCluster()
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-operator:", err)
		os.Exit(1)
	}
	ns := *namespace
	if ns == "" {
		ns = podNamespace
	}
	if ns == "" {
		fmt.Fprintln(os.Stderr, "trstctl-operator: no namespace to reconcile (pass --namespace or run in-cluster)")
		os.Exit(1)
	}

	r := operator.NewReconciler(client)
	if err := operator.Run(ctx, r, operator.Options{
		Namespace:      ns,
		ReconcileEvery: *reconcileEvery,
		Logger:         logger,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-operator:", err)
		os.Exit(1)
	}
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
