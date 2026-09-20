// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// hungSigner accepts RPCs and never answers — the pathological slow
// dependency OPS-TIMEOUTS-001 exists for.
type hungSigner struct {
	signerpb.UnimplementedSignerServiceServer
}

func (hungSigner) Health(ctx context.Context, _ *signerpb.HealthRequest) (*signerpb.HealthResponse, error) {
	<-ctx.Done() // block until the caller's deadline fires
	return nil, ctx.Err()
}

// TestSignerCallDeadlineBoundsSlowDependency proves every signer RPC carries
// a per-call deadline even when the caller supplied none: a hung signer
// yields a bounded DeadlineExceeded instead of stalling issuance forever.
func TestSignerCallDeadlineBoundsSlowDependency(t *testing.T) {
	original := SignerCallTimeout()
	if err := SetSignerCallTimeout(200 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := SetSignerCallTimeout(original); err != nil {
			t.Fatal(err)
		}
	})

	// Darwin caps AF_UNIX paths at 104 bytes. testing.T.TempDir includes the
	// full test name and can exceed that cap before gRPC is exercised, so use a
	// short private directory under /tmp and retain automatic cleanup.
	socketDir, err := os.MkdirTemp("/tmp", "trstctl-signing-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "hung.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	signerpb.RegisterSignerServiceServer(srv, hungSigner{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	client, err := Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	start := time.Now()
	_, err = client.svc.Health(context.Background(), &signerpb.HealthRequest{})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("hung signer RPC returned success")
	}
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("hung signer RPC error = %v, want DeadlineExceeded from the per-call deadline", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("hung signer RPC bounded in %v, want well under 2s for a 200ms per-call deadline", elapsed)
	}

	// A caller with a TIGHTER deadline keeps it (the interceptor only floors).
	tightCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = client.svc.Health(tightCtx, &signerpb.HealthRequest{})
	if status.Code(err) != codes.DeadlineExceeded || time.Since(start) > time.Second {
		t.Fatalf("tighter caller deadline was not honored: err=%v elapsed=%v", err, time.Since(start))
	}

	// Bounds fail closed.
	for _, bad := range []time.Duration{0, -time.Second, 3 * time.Minute} {
		if err := SetSignerCallTimeout(bad); err == nil {
			t.Fatalf("SetSignerCallTimeout(%v) accepted; want rejection", bad)
		}
	}
}
