// SPDX-License-Identifier: MPL-2.0

package workloadapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

// The Workload API, served on the host that runs the workloads (epic B3).
//
// The shape is SPIRE's, because the clients are SPIRE's: a stock go-spiffe
// client, a spiffe-helper sidecar and an Envoy SDS integration all dial a local
// UDS and speak this contract, and the only way to be usable by them is to be
// the thing they already dial.
//
// What changes versus the control plane's implementation is where the key is
// born. This process generates the SVID key, sends only its public half up the
// agent channel, and hands the private half to the workload over a socket that
// never leaves the machine. The control plane signs an SVID for a key it has
// never seen — the same inversion B2 made for endpoint certificates, applied to
// workload identity.

// Upstream is the control-plane call this server makes on a workload's behalf.
//
// An interface rather than the transport client directly, so the server can be
// exercised without a gRPC control plane — and so the one place that talks
// upward is explicit and small.
type Upstream interface {
	FetchWorkloadSVID(ctx context.Context, publicKeyDER []byte, selectors, audience []string) (*SVIDSet, error)
}

// SVIDSet is what the control plane issued.
type SVIDSet struct {
	X509 []X509SVID
	JWT  []JWTSVID
	// Bundle is the trust domain's X.509 authorities, DER-encoded.
	Bundle [][]byte
}

// X509SVID is one issued identity. It carries no private key: the workload's key
// was generated here and is added on the way out, never received.
type X509SVID struct {
	SPIFFEID     string
	CertChainDER [][]byte
	ExpiresAt    time.Time
	Hint         string
}

// JWTSVID is one issued JWT identity.
type JWTSVID struct {
	SPIFFEID  string
	Token     string
	ExpiresAt time.Time
}

// The mandatory SPIFFE Workload API metadata, defined HERE rather than imported
// from internal/protocols/spiffe.
//
// Two string constants are not worth a dependency edge. Importing the control
// plane's SPIFFE package for them pulled its audit and graph sinks — and through
// them the PostgreSQL driver — into the agent binary, which must stay a small
// standalone process with no database client in it. The agent-binary import
// boundary test caught it, correctly.
//
// The values are fixed by the SPIFFE specification, so the two definitions
// cannot drift in any way that matters: if they ever disagree, one of them is
// simply not speaking the Workload API.
const (
	SecurityHeaderKey   = "workload.spiffe.io"
	SecurityHeaderValue = "true"
)

// shutdownGrace is how long open workload streams get to finish on shutdown.
//
// Short on purpose. Workloads reconnect — that is what a Workload API client
// does — so the cost of cutting a stream is one reconnect, and the cost of
// waiting is a restart that appears to hang.
const shutdownGrace = 2 * time.Second

// Server is the host-local SPIFFE Workload API.
type Server struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer
	up Upstream
	// onIssue reports an issuance for the agent's heartbeat, so the console can
	// show per-host Workload API health. Nil disables reporting.
	onIssue func(spiffeID string, selectors []string)
}

// New builds the host-local Workload API server.
func New(up Upstream, onIssue func(string, []string)) *Server {
	return &Server{up: up, onIssue: onIssue}
}

// Serve runs the Workload API on a UDS until ctx is cancelled.
//
// The socket's directory is owner-only, and the socket itself is created with a
// restrictive umask: this endpoint is an identity oracle for every workload on
// the host, so who can reach it IS the access control.
func (s *Server) Serve(ctx context.Context, socketPath string) error {
	if !peerAttestationSupported() {
		return ErrAttestationUnsupported
	}
	if err := PrepareSocket(socketPath); err != nil {
		return err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("workloadapi: listen on %s: %w", socketPath, err)
	}
	// Credentials that attest at the handshake: a connection whose peer cannot
	// be identified never reaches a handler.
	grpcServer := grpc.NewServer(grpc.Creds(udsPeerCredentials{}))
	workloadpb.RegisterSpiffeWorkloadAPIServer(grpcServer, s)

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		// Graceful first, then forced. GracefulStop waits for open connections
		// to finish, and a Workload API connection is long-lived by design — the
		// X.509 stream stays open so the server can push a rotated SVID ahead of
		// expiry. Waiting on it unboundedly would mean one idle workload could
		// stop the agent from ever shutting down, which turns a routine restart
		// into a hang an operator has to go kill by hand.
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(shutdownGrace):
			grpcServer.Stop()
			<-stopped
		}
	}()
	err = grpcServer.Serve(ln)
	<-done
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// requireSecurityHeader enforces the mandatory workload.spiffe.io:true metadata.
//
// Part of the SPIFFE contract, and a real check rather than a formality: it is
// what stops an ambient gRPC client that wandered onto the socket from being
// treated as a workload asking for an identity.
func requireSecurityHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.InvalidArgument, "workloadapi: missing gRPC metadata (security header required)")
	}
	for _, v := range md.Get(SecurityHeaderKey) {
		if v == SecurityHeaderValue {
			return nil
		}
	}
	return status.Errorf(codes.InvalidArgument,
		"workloadapi: security header %s:%s required", SecurityHeaderKey, SecurityHeaderValue)
}

// attest resolves the caller's selectors from the kernel's view of the peer.
func attest(ctx context.Context) ([]string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return nil, status.Error(codes.Internal, "workloadapi: no peer on this connection")
	}
	// The attestation already happened, at the handshake, where the raw socket
	// was available. Reading it back here rather than re-deriving it means the
	// selectors a handler acts on are exactly the ones the connection was
	// admitted with.
	info, ok := p.AuthInfo.(peerAuthInfo)
	if !ok {
		return nil, status.Error(codes.Internal,
			"workloadapi: this connection was not attested, so no identity can be issued for it")
	}
	return info.identity.Selectors(), nil
}

// FetchX509SVID streams X.509-SVIDs to the calling workload.
func (s *Server) FetchX509SVID(_ *workloadpb.X509SVIDRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	if err := requireSecurityHeader(ctx); err != nil {
		return err
	}
	selectors, err := attest(ctx)
	if err != nil {
		return err
	}

	// The key is generated HERE, on the machine that runs the workload asking
	// for it. It is a LockedSigner (AN-8) destroyed before this call returns;
	// only its public half crosses the network, and only its PKCS#8 encoding
	// crosses the local socket to the process that will use it.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return status.Errorf(codes.Internal, "workloadapi: generate workload key: %v", err)
	}
	defer key.Destroy()

	set, err := s.up.FetchWorkloadSVID(ctx, key.Public().DER, selectors, nil)
	if err != nil {
		return err
	}
	if set == nil || len(set.X509) == 0 {
		return status.Error(codes.PermissionDenied, "workloadapi: no identity issued for this workload")
	}

	keyPKCS8, err := key.PKCS8()
	if err != nil {
		return status.Errorf(codes.Internal, "workloadapi: marshal workload key: %v", err)
	}
	defer secret.Wipe(keyPKCS8)

	resp := &workloadpb.X509SVIDResponse{}
	for _, svid := range set.X509 {
		resp.Svids = append(resp.Svids, &workloadpb.X509SVID{
			SpiffeId:    svid.SPIFFEID,
			X509Svid:    concatDER(svid.CertChainDER),
			X509SvidKey: append([]byte(nil), keyPKCS8...),
			Bundle:      concatDER(set.Bundle),
			Hint:        svid.Hint,
		})
		if s.onIssue != nil {
			s.onIssue(svid.SPIFFEID, selectors)
		}
	}
	defer destroyX509SVIDResponse(resp)
	return stream.Send(resp)
}

// FetchJWTSVID issues JWT-SVIDs for the calling workload.
func (s *Server) FetchJWTSVID(ctx context.Context, req *workloadpb.JWTSVIDRequest) (*workloadpb.JWTSVIDResponse, error) {
	if err := requireSecurityHeader(ctx); err != nil {
		return nil, err
	}
	if len(req.GetAudience()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "workloadapi: audience is required for a JWT-SVID")
	}
	selectors, err := attest(ctx)
	if err != nil {
		return nil, err
	}
	// No key: a JWT-SVID is signed by the trust domain's JWT authority, so
	// nothing is generated here and nothing needs wiping.
	set, err := s.up.FetchWorkloadSVID(ctx, nil, selectors, req.GetAudience())
	if err != nil {
		return nil, err
	}
	if set == nil || len(set.JWT) == 0 {
		return nil, status.Error(codes.PermissionDenied, "workloadapi: no identity issued for this workload")
	}
	out := &workloadpb.JWTSVIDResponse{}
	for _, svid := range set.JWT {
		out.Svids = append(out.Svids, &workloadpb.JWTSVID{SpiffeId: svid.SPIFFEID, Svid: svid.Token})
		if s.onIssue != nil {
			s.onIssue(svid.SPIFFEID, selectors)
		}
	}
	return out, nil
}

// concatDER joins DER blobs, the encoding the Workload API uses for chains and
// bundles.
func concatDER(ders [][]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, der...)
	}
	return out
}

// destroyX509SVIDResponse wipes the private keys in a response after it is sent.
//
// The response holds one copy of the PKCS#8 key per SVID, and they are the only
// copies of the workload's private key that exist outside its own process. They
// live for the length of one Send.
func destroyX509SVIDResponse(resp *workloadpb.X509SVIDResponse) {
	if resp == nil {
		return
	}
	for _, svid := range resp.Svids {
		secret.Wipe(svid.X509SvidKey)
	}
}
