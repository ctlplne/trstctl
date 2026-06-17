package events

import (
	"context"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
)

func TestReplicaStatusSatisfiedWhenObservedMatchesDesired(t *testing.T) {
	log := &Log{mode: config.NATSExternal, desiredReplicas: 3}
	status := log.replicaStatus(&jetstream.StreamInfo{
		Config: jetstream.StreamConfig{Replicas: 3},
	})
	if status.Degraded || status.Actual != 3 || status.Desired != 3 {
		t.Fatalf("replica status = %+v, want not degraded actual=desired=3", status)
	}
}

func TestPingFailsWhenObservedReplicasBelowDesired(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "ext-degraded", JetStream: true, StoreDir: t.TempDir(), Port: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("external server not ready")
	}
	defer srv.Shutdown()

	ctx := context.Background()
	log, err := Open(ctx, config.NATS{
		Mode:               config.NATSExternal,
		URL:                srv.ClientURL(),
		Replicas:           1,
		AllowSingleReplica: true,
	})
	if err != nil {
		t.Fatalf("Open eval single-replica: %v", err)
	}
	defer func() { _ = log.Close() }()

	log.desiredReplicas = 3
	err = log.Ping(ctx)
	if err == nil {
		t.Fatal("Ping succeeded with actual replicas below desired; want degraded readiness")
	}
	if !strings.Contains(err.Error(), "durability degraded") || !strings.Contains(err.Error(), "replicas=1 desired=3") {
		t.Fatalf("Ping error = %v, want explicit durability degradation", err)
	}

	status, err := log.StreamReplicaStatus(ctx)
	if err != nil {
		t.Fatalf("StreamReplicaStatus: %v", err)
	}
	if !status.Degraded || status.Actual != 1 || status.Desired != 3 {
		t.Fatalf("replica status = %+v, want degraded actual=1 desired=3", status)
	}
}
