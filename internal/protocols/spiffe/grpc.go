package spiffe

import (
	"context"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

// SecurityHeaderKey/Value is the mandatory SPIFFE Workload API metadata key/value a
// conformant client (go-spiffe, spiffe-helper, Envoy SDS) sets on every call so the
// server can reject ambient/non-SPIFFE callers. The server requires it on every RPC
// (SPIFFE Workload API spec §"Workload API gRPC Metadata"). They are exported so a
// differential client / the wire-in test set the same value the real clients do.
const (
	SecurityHeaderKey   = "workload.spiffe.io"
	SecurityHeaderValue = "true"
)

// WorkloadAPIServer adapts the SPIFFE Workload API gRPC contract (workloadpb,
// vendored from go-spiffe) onto the in-tree spiffe.Server (INTEROP-004). It is the
// served transport the audit found missing: a real gRPC service on a UDS that a
// stock go-spiffe / spiffe-helper / Envoy SDS client dials to FetchX509SVID.
//
// Unlike the library FetchX509SVIDs (which signs over a caller-supplied public key),
// the Workload API mints the key pair server-side and returns the PKCS#8 private key
// in the response, as the SPIFFE spec requires. The key is generated in-process for
// the SVID (AN-8: a LockedSigner, mlock'd + zeroized; it never reaches the signer —
// only the CA key does, AN-4), the SVID is signed through spiffe.Server (which routes
// to the isolated signer via the crypto boundary, AN-3/AN-4), and issuance is audited
// and tenant-scoped by the underlying Server (AN-1/AN-2).
type WorkloadAPIServer struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer
	wl *Server
	// selectors are the selectors the server attributes to a local caller over the
	// UDS. A UDS peer is host-local and already authenticated by filesystem
	// permissions on the socket; richer peer-credential attestation (uid/gid/path)
	// is layered on top (S11.2). Empty means every registration entry with no
	// selectors is unreachable and entries are matched by these defaults.
	selectors []string
}

// NewWorkloadAPIServer wraps a spiffe.Server as the gRPC Workload API service.
// callerSelectors are the selectors attributed to a local UDS caller (so the
// registration entries whose selectors are a subset are issued).
func NewWorkloadAPIServer(wl *Server, callerSelectors []string) *WorkloadAPIServer {
	return &WorkloadAPIServer{wl: wl, selectors: append([]string(nil), callerSelectors...)}
}

// requireSecurityHeader enforces the mandatory workload.spiffe.io:true metadata on
// every RPC (the SPIFFE Workload API contract). A caller that omits it — e.g. an
// ambient gRPC client that is not a SPIFFE Workload API client — is rejected with
// InvalidArgument, exactly as SPIRE's agent does.
func requireSecurityHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.InvalidArgument, "spiffe: missing gRPC metadata (security header required)")
	}
	for _, v := range md.Get(SecurityHeaderKey) {
		if v == SecurityHeaderValue {
			return nil
		}
	}
	return status.Errorf(codes.InvalidArgument, "spiffe: security header %s:%s required", SecurityHeaderKey, SecurityHeaderValue)
}

// FetchX509SVID streams X.509-SVIDs to the caller (SPIFFE Workload API). It mints a
// fresh key pair per SVID, signs the SVID over it through the issuing CA in the
// signer, and returns the leaf, its PKCS#8 key, and the trust bundle — the response a
// go-spiffe client validates and a spiffe-helper writes to disk. The stream sends one
// response now; a production server also re-sends ahead of expiry (rotation), which
// the client drives via NeedsRotation.
func (s *WorkloadAPIServer) FetchX509SVID(_ *workloadpb.X509SVIDRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	if err := requireSecurityHeader(ctx); err != nil {
		return err
	}
	resp, err := s.buildX509SVIDResponse(ctx)
	if err != nil {
		return err
	}
	return stream.Send(resp)
}

// buildX509SVIDResponse mints the SVID set for the caller's selectors and assembles
// the Workload API response. It is separated out so the wire-in test can assert the
// exact response the stream sends.
func (s *WorkloadAPIServer) buildX509SVIDResponse(ctx context.Context) (*workloadpb.X509SVIDResponse, error) {
	// Mint the workload key pair server-side (the Workload API owns the key). It is a
	// LockedSigner (AN-8) destroyed before we return; only its public key crosses to
	// the SVID signer and only its PKCS#8 encoding is returned to the local caller.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "spiffe: generate workload key: %v", err)
	}
	defer key.Destroy()

	svids, err := s.wl.FetchX509SVIDs(ctx, key.Public().DER, s.selectors)
	if err != nil {
		if err == ErrNoIdentity {
			return nil, status.Error(codes.PermissionDenied, "spiffe: no identity issued for caller selectors")
		}
		return nil, status.Errorf(codes.Internal, "spiffe: fetch X509-SVID: %v", err)
	}
	keyPKCS8, err := key.PKCS8()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "spiffe: marshal workload key: %v", err)
	}

	resp := &workloadpb.X509SVIDResponse{}
	for _, svid := range svids {
		// SPIFFE Workload API X509SVID: x509_svid is the leaf+intermediates DER
		// concatenated, x509_svid_key is the PKCS#8 DER private key, bundle is the
		// trust-domain CA DER concatenated.
		resp.Svids = append(resp.Svids, &workloadpb.X509SVID{
			SpiffeId:    svid.SPIFFEID,
			X509Svid:    concatDER(svid.CertChain),
			X509SvidKey: keyPKCS8,
			Bundle:      concatDER(svid.Bundle),
		})
	}
	if len(resp.Svids) == 0 {
		return nil, status.Error(codes.PermissionDenied, "spiffe: no identity issued for caller selectors")
	}
	return resp, nil
}

// FetchX509Bundles streams the trust-domain X.509 bundle (for clients that only
// validate SVIDs). One snapshot is sent; a production server re-sends on bundle
// change.
func (s *WorkloadAPIServer) FetchX509Bundles(_ *workloadpb.X509BundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()
	if err := requireSecurityHeader(ctx); err != nil {
		return err
	}
	bundle, err := s.wl.FetchX509Bundle(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "spiffe: fetch X509 bundle: %v", err)
	}
	td := s.wl.cfg.TrustDomain
	resp := &workloadpb.X509BundlesResponse{
		Bundles: map[string][]byte{td: concatDER(bundle)},
	}
	return stream.Send(resp)
}

// concatDER concatenates DER blocks (the SPIFFE wire form for a cert chain / bundle:
// raw DER, no PEM framing).
func concatDER(blocks [][]byte) []byte {
	var n int
	for _, b := range blocks {
		n += len(b)
	}
	out := make([]byte, 0, n)
	for _, b := range blocks {
		out = append(out, b...)
	}
	return out
}

// ServeWorkloadAPI registers the Workload API service on a new gRPC server and serves
// it on the given Unix domain socket until ctx is cancelled. It removes a stale
// socket file first and sets 0600 perms so only the owning user can dial (the UDS
// peer-trust boundary; AN-1's tenant scoping is enforced inside the wrapped Server).
// It is the served entry point cmd/trstctl uses when protocols.spiffe.enabled.
func ServeWorkloadAPI(ctx context.Context, socketPath string, srv *WorkloadAPIServer) error {
	if socketPath == "" {
		return fmt.Errorf("spiffe: workload API socket path required")
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("spiffe: listen on %s: %w", socketPath, err)
	}
	// Restrict the socket to the owning user; the Workload API is host-local.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("spiffe: chmod socket: %w", err)
	}
	gs := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(gs, srv)
	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()
	if err := gs.Serve(ln); err != nil && ctx.Err() == nil {
		return fmt.Errorf("spiffe: workload API serve: %w", err)
	}
	return nil
}

// TrustDomain returns the trust domain the wrapped Server serves (for callers that
// need to label the bundle). Exposed for the server mount.
func (s *Server) TrustDomain() string { return s.cfg.TrustDomain }
