// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type answeringSigner struct {
	signerpb.UnimplementedSignerServiceServer
}

func (answeringSigner) Health(context.Context, *signerpb.HealthRequest) (*signerpb.HealthResponse, error) {
	return &signerpb.HealthResponse{}, nil
}

// CI-L37: an installed observer hears each RPC's method and wall time, and
// nothing once it is removed. It measures only.
func TestObserveRPCsTimesEachCall(t *testing.T) {
	socketDir, err := os.MkdirTemp("/tmp", "trstctl-signing-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "obs.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	signerpb.RegisterSignerServiceServer(srv, answeringSigner{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	client, err := Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var mu sync.Mutex
	var heard []string
	client.ObserveRPCs(func(method string, d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		if d > 0 {
			heard = append(heard, method)
		}
	})
	if _, err := client.svc.Health(context.Background(), &signerpb.HealthRequest{}); err != nil {
		t.Fatal(err)
	}
	client.ObserveRPCs(nil)
	if _, err := client.svc.Health(context.Background(), &signerpb.HealthRequest{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(heard) != 1 || heard[0] != "/trstctl.signing.v1.SignerService/Health" {
		t.Fatalf("heard %q", heard)
	}
}
