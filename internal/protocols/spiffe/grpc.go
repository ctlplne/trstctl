// SPDX-License-Identifier: MPL-2.0

package spiffe

import (
	"context"
	"encoding/json"
	"fmt"

	"net"
	"os"
	"time"
	"trstctl.com/trstctl/internal/auditsink"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
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
// stock go-spiffe / spiffe-helper / Envoy SDS client dials for X.509-SVID and
// JWT-SVID issuance, bundle fetches, and JWT validation.
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
	selectors                []string
	additionalX509SVIDIssuer AdditionalX509SVIDIssuer
}

// AdditionalX509SVID is one extra key/certificate pair in the standard
// repeated X509SVID response. It is the feature-neutral extension point used by
// a licensed hybrid issuer; core neither names nor implements that algorithm.
type AdditionalX509SVID struct {
	CertificateDER  []byte
	PrivateKeyPKCS8 []byte
	Hint            string
}

// AdditionalX509SVIDIssuer mints a second key/certificate pair for the same
// authorized SPIFFE ID. Implementations receive the classical SVID expiry so
// both halves of the hybrid identity rotate together.
type AdditionalX509SVIDIssuer interface {
	IssueAdditionalX509SVID(context.Context, string, time.Time) (AdditionalX509SVID, error)
}

type WorkloadAPIOption func(*WorkloadAPIServer)

func WithAdditionalX509SVIDIssuer(issuer AdditionalX509SVIDIssuer) WorkloadAPIOption {
	return func(s *WorkloadAPIServer) { s.additionalX509SVIDIssuer = issuer }
}

// NewWorkloadAPIServer wraps a spiffe.Server as the gRPC Workload API service.
// callerSelectors are the selectors attributed to a local UDS caller (so the
// registration entries whose selectors are a subset are issued).
func NewWorkloadAPIServer(wl *Server, callerSelectors []string, opts ...WorkloadAPIOption) *WorkloadAPIServer {
	s := &WorkloadAPIServer{wl: wl, selectors: append([]string(nil), callerSelectors...)}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
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
	defer destroyX509SVIDResponse(resp)
	return stream.Send(resp)
}

// buildX509SVIDResponse mints the SVID set for the caller's selectors and assembles
// the Workload API response. It is separated out so the wire-in test can assert the
// exact response the stream sends.
// recordLocalSocketDeprecation notes that a workload used the CONTROL PLANE's
// socket rather than its own host's (epic B3).
//
// Retained for one release, and recorded every time, because the migration is
// otherwise invisible: an operator who moves their agents to the host Workload
// API has no way to tell which workloads are still dialling the old socket, and
// "we think everything moved" is exactly the kind of belief this workstream
// exists to replace with evidence.
//
// Best-effort: failing to record the deprecation must not fail an issuance a
// workload is depending on today.
func (s *WorkloadAPIServer) recordLocalSocketDeprecation(ctx context.Context, kind string) {
	_ = auditsink.Emit(ctx, s.wl.cfg.Audit, nil, "spiffe.workload_api.local_socket_used", s.wl.cfg.TenantID,
		[]byte(fmt.Sprintf(`{"type":%q,"detail":%q}`, kind,
			"this SVID was issued on the control plane's own Workload API socket, which can only "+
				"serve workloads on this machine and mints the SVID key here rather than on the "+
				"host that runs the workload. Move the workload to its host agent's socket "+
				"(--workload-api-socket) and scope its registration entry to that node.")))
}

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
	defer secret.Wipe(keyPKCS8)

	resp := &workloadpb.X509SVIDResponse{}
	complete := false
	defer func() {
		if !complete {
			destroyX509SVIDResponse(resp)
		}
	}()
	for _, svid := range svids {
		// SPIFFE Workload API X509SVID: x509_svid is the leaf+intermediates DER
		// concatenated, x509_svid_key is the PKCS#8 DER private key, bundle is the
		// trust-domain CA DER concatenated.
		classical := &workloadpb.X509SVID{
			SpiffeId:    svid.SPIFFEID,
			X509Svid:    concatDER(svid.CertChain),
			X509SvidKey: append([]byte(nil), keyPKCS8...),
			Bundle:      concatDER(svid.Bundle),
		}
		if s.additionalX509SVIDIssuer != nil {
			classical.Hint = "trstctl-hybrid-classical"
		}
		resp.Svids = append(resp.Svids, classical)
		if s.additionalX509SVIDIssuer != nil {
			additional, err := s.additionalX509SVIDIssuer.IssueAdditionalX509SVID(ctx, svid.SPIFFEID, svid.ExpiresAt)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "spiffe: issue additional X509-SVID: %v", err)
			}
			if len(additional.CertificateDER) == 0 || len(additional.PrivateKeyPKCS8) == 0 || additional.Hint == "" || additional.Hint == classical.Hint {
				secret.Wipe(additional.PrivateKeyPKCS8)
				return nil, status.Error(codes.Internal, "spiffe: additional X509-SVID issuer returned an incomplete pair")
			}
			resp.Svids = append(resp.Svids, &workloadpb.X509SVID{
				SpiffeId: svid.SPIFFEID, X509Svid: append([]byte(nil), additional.CertificateDER...),
				X509SvidKey: additional.PrivateKeyPKCS8, Bundle: concatDER(svid.Bundle), Hint: additional.Hint,
			})
			// Parity with the classical SVID (AN-2): the additional issuer's
			// mint is audited into the event log and the credential graph with
			// the same shape, carrying its hint so posture can tell the pair
			// apart. Without this the second SVID was invisible to audit.
			s.wl.recordIssued(ctx, "x509-additional:"+additional.Hint, svid.SPIFFEID)
		}
	}
	if len(resp.Svids) == 0 {
		return nil, status.Error(codes.PermissionDenied, "spiffe: no identity issued for caller selectors")
	}
	// Recorded AFTER the issuance, and only on success. "The deprecated socket
	// was used" is a statement about an SVID that exists; a refused request did
	// not use the old path, it was turned away by it.
	s.recordLocalSocketDeprecation(ctx, "x509")
	complete = true
	return resp, nil
}

func destroyX509SVIDResponse(resp *workloadpb.X509SVIDResponse) {
	if resp == nil {
		return
	}
	for _, svid := range resp.Svids {
		if svid != nil {
			secret.Wipe(svid.X509SvidKey)
			svid.X509SvidKey = nil
		}
	}
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

// FetchJWTSVID returns JWT-SVIDs for the caller's authorized SPIFFE identities and
// requested audiences. It uses the same registration entry matching as X.509-SVIDs,
// then shapes the result into the SPIFFE Workload API protobuf contract.
func (s *WorkloadAPIServer) FetchJWTSVID(ctx context.Context, req *workloadpb.JWTSVIDRequest) (*workloadpb.JWTSVIDResponse, error) {
	if err := requireSecurityHeader(ctx); err != nil {
		return nil, err
	}
	audience := req.GetAudience()
	if len(audience) == 0 {
		return nil, status.Error(codes.InvalidArgument, "spiffe: JWT-SVID audience required")
	}
	wantID := req.GetSpiffeId()
	if wantID != "" {
		if _, err := crypto.ParseSPIFFEID(wantID); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "spiffe: invalid requested SPIFFE ID: %v", err)
		}
	}
	svids, err := s.wl.FetchJWTSVIDs(ctx, audience, s.selectors)
	if err != nil {
		if err == ErrNoIdentity {
			return nil, status.Error(codes.PermissionDenied, "spiffe: no identity issued for caller selectors")
		}
		return nil, status.Errorf(codes.Internal, "spiffe: fetch JWT-SVID: %v", err)
	}
	resp := &workloadpb.JWTSVIDResponse{}
	for _, svid := range svids {
		if wantID != "" && svid.SPIFFEID != wantID {
			continue
		}
		resp.Svids = append(resp.Svids, &workloadpb.JWTSVID{
			SpiffeId: svid.SPIFFEID,
			Svid:     svid.Token,
		})
	}
	if len(resp.Svids) == 0 {
		return nil, status.Error(codes.PermissionDenied, "spiffe: requested SPIFFE ID is not authorized for caller selectors")
	}
	s.recordLocalSocketDeprecation(ctx, "jwt")
	return resp, nil
}

// FetchJWTBundles streams the JWT trust bundle as JWKS bytes keyed by trust domain.
// The value is a JWKS JSON document because stock go-spiffe parses it through
// jwtbundle.Parse.
func (s *WorkloadAPIServer) FetchJWTBundles(_ *workloadpb.JWTBundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()
	if err := requireSecurityHeader(ctx); err != nil {
		return err
	}
	bundle, err := s.wl.FetchJWTBundle(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "spiffe: fetch JWT bundle: %v", err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return status.Errorf(codes.Internal, "spiffe: marshal JWT bundle: %v", err)
	}
	td := s.wl.cfg.TrustDomain
	resp := &workloadpb.JWTBundlesResponse{
		Bundles: map[string][]byte{td: raw},
	}
	return stream.Send(resp)
}

// ValidateJWTSVID verifies a compact JWT-SVID against the served JWT bundle and
// requested audience, then returns the validated SPIFFE ID and claims. Signature
// verification stays inside internal/crypto; this adapter validates the standard JWT
// fields the Workload API caller asked about.
func (s *WorkloadAPIServer) ValidateJWTSVID(ctx context.Context, req *workloadpb.ValidateJWTSVIDRequest) (*workloadpb.ValidateJWTSVIDResponse, error) {
	if err := requireSecurityHeader(ctx); err != nil {
		return nil, err
	}
	if req.GetAudience() == "" {
		return nil, status.Error(codes.InvalidArgument, "spiffe: validation audience required")
	}
	if req.GetSvid() == "" {
		return nil, status.Error(codes.InvalidArgument, "spiffe: JWT-SVID token required")
	}
	bundle, err := s.wl.FetchJWTBundle(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "spiffe: fetch JWT bundle: %v", err)
	}
	claimsJSON, err := crypto.VerifyJWT(req.GetSvid(), bundle)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "spiffe: verify JWT-SVID: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "spiffe: parse JWT-SVID claims: %v", err)
	}
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, status.Error(codes.InvalidArgument, "spiffe: JWT-SVID subject claim required")
	}
	if _, err := crypto.ParseSPIFFEID(sub); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "spiffe: invalid JWT-SVID subject: %v", err)
	}
	exp, ok := numericClaim(claims["exp"])
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "spiffe: JWT-SVID exp claim required")
	}
	now := time.Now().Unix()
	if now >= int64(exp) {
		return nil, status.Error(codes.PermissionDenied, "spiffe: JWT-SVID expired")
	}
	if !audienceContains(claims["aud"], req.GetAudience()) {
		return nil, status.Error(codes.PermissionDenied, "spiffe: JWT-SVID audience mismatch")
	}
	pbClaims, err := structpb.NewStruct(claims)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "spiffe: encode JWT-SVID claims: %v", err)
	}
	return &workloadpb.ValidateJWTSVIDResponse{SpiffeId: sub, Claims: pbClaims}, nil
}

func numericClaim(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}

func audienceContains(v any, want string) bool {
	switch aud := v.(type) {
	case string:
		return aud == want
	case []any:
		for _, item := range aud {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
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
