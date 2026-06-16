package signing

import (
	"context"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// RawGenerateKeyForTest drives a GenerateKey RPC with a raw algorithm and
// returns the raw gRPC error, so saturation tests can inspect the status code
// (e.g. codes.ResourceExhausted) without the higher-level helpers swallowing it.
// Test-only: it is compiled solely into the package's test binary.
func (c *Client) RawGenerateKeyForTest(ctx context.Context, alg signerpb.Algorithm) (*signerpb.GenerateKeyResponse, error) {
	return c.svc.GenerateKey(ctx, &signerpb.GenerateKeyRequest{Algorithm: alg})
}

// RawSignForTest drives a Sign RPC with a fully-specified request and returns the
// raw gRPC error, so saturation tests can observe codes.ResourceExhausted from
// the served path. Test-only.
func (c *Client) RawSignForTest(ctx context.Context, req *signerpb.SignRequest) (*signerpb.SignResponse, error) {
	return c.svc.Sign(ctx, req)
}

// SetSignGateForTest installs a hook called inside Sign while it holds its
// in-flight bulkhead slot, so a served saturation test can deterministically
// fill the pool. Test-only seam; nil in production.
func (s *Server) SetSignGateForTest(gate func()) { s.signGate = gate }
