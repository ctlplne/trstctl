// SPDX-License-Identifier: BUSL-1.1

// Command trstctl-operator is the trstctl Kubernetes Operator.
//
// It watches TrstctlControlPlane and TrstctlSecretSync custom resources (group
// trstctl.com, deploy/operator/crd.yaml). It reconciles each control-plane
// resource's declared desired state into a managed control-plane Deployment, and
// each secret-sync resource into a Kubernetes Secret plus pod-template content
// hash annotations for opted-in workload reload, then writes the observed phase
// back to the resource status. The reconcile is level-based (read the world →
// diff against the spec → converge), so a missed change is corrected on the next
// poll.
//
// It speaks the Kubernetes API directly over JSON-over-HTTPS with no client-go /
// controller-runtime dependency (none is in go.mod). TLS trust to the API server
// is built through the crypto boundary (internal/crypto/mtls), so this binary
// imports no crypto/* (AN-3). The operator ships inside the same multi-binary
// control-plane image the release pipeline builds (deploy/docker/Dockerfile) and
// runs via an entrypoint override (the same packaging the agent uses, OPS-002).
//
// Maturity is documented honestly in deploy/operator/doc.go: this is a small,
// functional reconcile loop that owns the Deployment, its runtime config, and
// TrstctlSecretSync projections; Services, ingress, and NetworkPolicy remain the
// Helm chart's richer path.
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
	leaderElect := flag.Bool("leader-elect", false, "campaign for a Kubernetes Lease so only one operator replica reconciles at a time")
	leaderLease := flag.String("leader-lease", "trstctl-operator", "coordination.k8s.io Lease name used when --leader-elect is set")
	leaderLeaseDuration := flag.Duration("leader-lease-duration", 15*time.Second, "how long a silent leader keeps the Lease before another replica may acquire it")
	leaderIdentity := flag.String("leader-identity", "", "identity written to the leader-election Lease (default: POD_NAME, HOSTNAME, or os.Hostname)")
	logLevel := flag.String("log-level", "info", "log level: debug | info | warn | error")
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("trstctl-operator"))
		return
	}

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
		LeaderElection: *leaderElect,
		LeaderIdentity: operatorIdentity(*leaderIdentity),
		LeaseName:      *leaderLease,
		LeaseDuration:  *leaderLeaseDuration,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-operator:", err)
		os.Exit(1)
	}
}

func operatorIdentity(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if pod := os.Getenv("POD_NAME"); pod != "" {
		return pod
	}
	if host := os.Getenv("HOSTNAME"); host != "" {
		return host
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "trstctl-operator"
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
