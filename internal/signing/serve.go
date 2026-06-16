package signing

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"

	"trstctl.com/trstctl/internal/crypto/mtls"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// maxMessageBytes bounds gRPC request/response size; the signer signs digests,
// not bulk data.
const maxMessageBytes = 1 << 20 // 1 MiB

// maxConcurrentStreams caps concurrent HTTP/2 streams at the gRPC transport as a
// first AN-7 bound (gRPC's default is effectively unbounded). The application
// layer adds a tighter semaphore over the expensive RPCs (see bulkhead.go). It
// is set above defaultMaxInflight so cheap RPCs (Health/GetPublicKey/DestroyKey)
// still get through while expensive ones are shedding load.
const maxConcurrentStreams = 256

// ServeOptions tunes the serving path. The zero value uses safe defaults.
type ServeOptions struct {
	// MaxInflight bounds concurrent expensive (key-using) RPCs; excess is
	// rejected with RESOURCE_EXHAUSTED (AN-7, SIGNER-001). <=0 means
	// defaultMaxInflight.
	MaxInflight int
}

// Serve runs an in-memory signing service on a Unix domain socket at socketPath
// (keys do not survive a restart). For persistent CA-key custody, build a
// persistent server and use ServeServer.
func Serve(ctx context.Context, socketPath string) error {
	return ServeServer(ctx, socketPath, NewServer())
}

// ServeServer runs the given signing server on a Unix domain socket at
// socketPath until ctx is cancelled, then drains in-flight requests and zeroizes
// all keys. The socket lives in a 0700 directory as a 0600 socket, and
// connections are restricted to the signer's own uid (SO_PEERCRED on Linux). A
// persistent server (NewPersistentServer) gives the issuing CA key custody that
// survives a restart (R3.2).
func ServeServer(ctx context.Context, socketPath string, svc *Server) error {
	return ServeServerWithOptions(ctx, socketPath, svc, ServeOptions{})
}

// ServeServerWithOptions is ServeServer with explicit AN-7 tuning.
func ServeServerWithOptions(ctx context.Context, socketPath string, svc *Server, opts ServeOptions) error {
	ln, err := listenUDS(socketPath)
	if err != nil {
		return err
	}
	return serveGRPC(ctx, ln, svc, opts, nil)
}

// ServeServerMTLS runs the signing server on a TCP listener bound to addr, over
// gRPC-on-mTLS, until ctx is cancelled, then drains in-flight requests and
// zeroizes all keys. This is the cross-node alternative to the UDS path (AN-4
// multi-node mode, SIGNER-005 / design §3, §5.2): the channel is TLS 1.3,
// AEAD-only, with the signer and the control plane each PINNING the other's
// certificate (see internal/crypto/mtls.SignerServerCredentials) — an untrusted
// or merely CA-signed-but-unpinned peer is rejected at the handshake. The signer
// keeps no HTTP server and no SQL driver (AN-4); mTLS is just a transport
// credential on the same gRPC SignerService. addr is a host:port (use ":9443"
// for all interfaces). The same AN-7 bulkhead bounds apply as on the UDS path.
func ServeServerMTLS(ctx context.Context, addr string, svc *Server, tlsCfg mtls.SignerPeerConfig, opts ServeOptions) error {
	creds, err := mtls.SignerServerCredentials(tlsCfg)
	if err != nil {
		return fmt.Errorf("signer mTLS credentials: %w", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	return serveGRPC(ctx, ln, svc, opts, grpc.Creds(creds))
}

// serveGRPC registers svc on a gRPC server over ln and serves until ctx is
// cancelled, then drains and zeroizes. When creds is nil the channel is the bare
// (UDS) transport whose security is filesystem permissions + SO_PEERCRED; when
// creds is non-nil (mTLS) the transport is mutually authenticated and pinned. The
// AN-7 bulkhead and message bounds are identical on both paths.
func serveGRPC(ctx context.Context, ln net.Listener, svc *Server, opts ServeOptions, creds grpc.ServerOption) error {
	// AN-7 backpressure: bound concurrent expensive RPCs and reject the excess
	// fast with RESOURCE_EXHAUSTED, so a flood of Sign/GenerateKey calls cannot
	// exhaust the signer (SIGNER-001). MaxConcurrentStreams caps HTTP/2 streams
	// at the transport; the unary interceptor enforces the in-flight semaphore
	// and a per-RPC deadline at the application layer.
	inflight := opts.MaxInflight
	if inflight <= 0 {
		inflight = defaultMaxInflight
	}
	lim := newLimiter(inflight)
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.MaxSendMsgSize(maxMessageBytes),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.UnaryInterceptor(bulkheadInterceptor(lim)),
	}
	if creds != nil {
		serverOpts = append(serverOpts, creds)
	}
	srv := grpc.NewServer(serverOpts...)
	signerpb.RegisterSignerServiceServer(srv, svc)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		srv.GracefulStop() // wait for in-flight RPCs to finish...
		svc.Shutdown()     // ...then zeroize keys (no handler is running now)
		<-errc             // Serve returns nil after GracefulStop
		return nil
	case err := <-errc:
		svc.Shutdown()
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	}
}

// listenUDS creates the socket directory (0700), removes any stale socket,
// listens, tightens the socket to 0600, and wraps the listener with peer-uid
// authentication.
func listenUDS(socketPath string) (net.Listener, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod socket dir: %w", err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return newPeerAuthListener(ln, os.Geteuid()), nil
}
