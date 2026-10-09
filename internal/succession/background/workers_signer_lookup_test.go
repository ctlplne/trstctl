// SPDX-License-Identifier: BUSL-1.1

package background

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

type unavailableCheckpointSigner struct {
	signerpb.UnimplementedSignerServiceServer
	generated atomic.Int64
}

func (*unavailableCheckpointSigner) GetPublicKey(context.Context, *signerpb.GetPublicKeyRequest) (*signerpb.GetPublicKeyResponse, error) {
	return nil, status.Error(codes.Unavailable, "signer key store is recovering")
}

func (s *unavailableCheckpointSigner) GenerateKey(context.Context, *signerpb.GenerateKeyRequest) (*signerpb.GenerateKeyResponse, error) {
	s.generated.Add(1)
	return nil, status.Error(codes.Internal, "unexpected key generation")
}

func TestCheckpointSignerDoesNotMintOnSignerOutage(t *testing.T) {
	// Keep the AF_UNIX path short enough for Darwin's socket-path limit.
	dir, err := os.MkdirTemp(os.TempDir(), "trstctl-pcas-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "signer.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &unavailableCheckpointSigner{}
	signerpb.RegisterSignerServiceServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client, err := signing.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	worker := &checkpointWorker{signer: staticCheckpointSigner{client}, handle: "checkpoint", alg: crypto.ECDSAP256}
	_, err = worker.checkpointSigner(context.Background())
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("lookup error = %v, want the original signer outage", err)
	}
	if calls := fake.generated.Load(); calls != 0 {
		t.Fatalf("signer outage triggered %d new key requests", calls)
	}
}

type staticCheckpointSigner struct{ client *signing.Client }

func (s staticCheckpointSigner) Client() *signing.Client { return s.client }
