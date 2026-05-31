package signing

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"

	signerpb "certctl.io/certctl/internal/signing/proto"
)

// maxMessageBytes bounds gRPC request/response size; the signer signs digests,
// not bulk data.
const maxMessageBytes = 1 << 20 // 1 MiB

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
	ln, err := listenUDS(socketPath)
	if err != nil {
		return err
	}

	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxMessageBytes),
		grpc.MaxSendMsgSize(maxMessageBytes),
	)
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
