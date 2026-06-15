// Package transport provides the agent gRPC channel: the control-plane server
// that agents connect to, and the agent-side dialer, both over mutual TLS.
//
// All TLS material — the server and client certificates, the TLS 1.3 / AEAD-only
// configuration, and server-certificate pinning — comes from
// internal/crypto/mtls as opaque gRPC credentials, so this package holds no
// crypto/* imports (AN-3) and there is no plaintext code path.
package transport

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// NewServer builds the agent-facing gRPC server secured by the given mutual-TLS
// credentials. It registers the standard health service — the agent's liveness
// check — and, when svc is non-nil, the agent steady-state service (heartbeat +
// renewal, WIRE-004). The server has no insecure listener; a nil svc serves only
// health (used by the transport-level tests).
func NewServer(creds credentials.TransportCredentials, svc AgentServiceServer) *grpc.Server {
	s := grpc.NewServer(grpc.Creds(creds))
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, hs)
	if svc != nil {
		RegisterAgentService(s, svc)
	}
	return s
}

// Dial connects an agent to the control plane at target over mutual TLS. The
// credentials carry the agent's (rotating) client certificate and the server
// trust/pinning policy.
func Dial(target string, creds credentials.TransportCredentials) (*grpc.ClientConn, error) {
	return grpc.NewClient(target, grpc.WithTransportCredentials(creds))
}
