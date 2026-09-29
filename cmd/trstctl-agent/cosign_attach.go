// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/workloadapi"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/succession/agent"
)

// cosign_attach.go is the workload-agent co-sign seam (INT-16, claim 19). PCAS is
// part of the core, so every agent build carries it. When configured, the agent
// serves the internal/succession/agent CoSignerService: it holds the workload's predecessor
// key and co-signs succession commitments the control plane forms, over a real gRPC
// transport, enforcing the FIG. 5 oracle-prevention rules server-side. Only the
// predecessor signature (public) ever leaves the agent.

// workloadCoSignConfig configures the workload-held predecessor co-sign service.
type workloadCoSignConfig struct {
	Listen             string // "unix:/path" or "host:port"; empty disables the service
	DeploymentScope    string
	IdentityID         string
	TenantID           string
	PredecessorKeyPath string // PKCS#8 PEM holding the workload predecessor key

	// Caller authentication (F261). The service signs with the workload's
	// predecessor key, so an unauthenticated listener is a signing oracle for
	// anyone who reaches it. A host:port listener requires pinned mutual TLS: this
	// end's certificate and key, the CA that anchors the caller's certificate, and
	// the caller's public-key pin (the same transport the isolated signer uses). A
	// unix socket is owner-only and admits only PeerUID (default: the agent's own
	// uid); it may add the same TLS on top.
	TLSCertFile string
	TLSKeyFile  string
	PeerCAFile  string
	PeerPinHex  string
	PeerUID     int // -1 means the agent's effective uid
}

func (c workloadCoSignConfig) tlsConfigured() bool {
	return c.TLSCertFile != "" || c.TLSKeyFile != "" || c.PeerCAFile != "" || c.PeerPinHex != ""
}

// AN-7 bounds for the co-sign server. A request is a few KiB of structured
// commitment fields; anything larger is refused before it reaches the signer.
const (
	coSignMaxMessageBytes   = 64 << 10
	coSignMaxStreams        = 16
	coSignMaxInflight       = 8
	coSignPerRequestTimeout = 10 * time.Second
)

// runWorkloadCoSign serves the co-sign service until ctx is canceled, then stops it
// gracefully. It is a self-contained agent mode (like --secret-inject): it needs no
// enrollment/connection settings. It refuses to start rather than serve an
// unauthenticated listener, and it checks this before loading the key.
func runWorkloadCoSign(ctx context.Context, cfg workloadCoSignConfig) error {
	network, addr := workloadCoSignAddress(cfg.Listen)
	var serverOptions []grpc.ServerOption
	if network == "tcp" || cfg.tlsConfigured() {
		creds, err := mtls.SignerServerCredentials(mtls.SignerPeerConfig{
			CertFile: cfg.TLSCertFile, KeyFile: cfg.TLSKeyFile, PeerCAFile: cfg.PeerCAFile, PeerPinHex: cfg.PeerPinHex,
		})
		if err != nil {
			return fmt.Errorf("workload co-sign: a network listener requires pinned mutual TLS "+
				"(--workload-cosign-tls-cert, --workload-cosign-tls-key, --workload-cosign-peer-ca, --workload-cosign-peer-pin); "+
				"use unix:/path for an owner-only local socket: %w", err)
		}
		serverOptions = append(serverOptions, grpc.Creds(creds))
	}
	peerUID := cfg.PeerUID
	if peerUID < 0 {
		peerUID = os.Geteuid()
	}

	signer, cleanup, err := loadPredecessorSigner(cfg.PredecessorKeyPath)
	if err != nil {
		return err
	}
	defer cleanup()

	cs, err := agent.New(agent.Config{
		DeploymentScope: cfg.DeploymentScope,
		IdentityID:      cfg.IdentityID,
		TenantID:        cfg.TenantID,
		Signer:          signer,
	})
	if err != nil {
		return err
	}

	lis, err := listenWorkloadCoSign(network, addr, peerUID)
	if err != nil {
		return fmt.Errorf("workload co-sign: listen %s: %w", cfg.Listen, err)
	}

	gs := grpc.NewServer(append(serverOptions,
		grpc.MaxRecvMsgSize(coSignMaxMessageBytes),
		grpc.MaxSendMsgSize(coSignMaxMessageBytes),
		grpc.MaxConcurrentStreams(coSignMaxStreams),
		grpc.UnaryInterceptor(coSignBulkhead(coSignMaxInflight, coSignPerRequestTimeout)),
	)...)
	agent.NewCoSignServer(cs).Register(gs)
	errc := make(chan error, 1)
	go func() { errc <- gs.Serve(lis) }()

	fmt.Fprintf(os.Stderr, "trstctl-agent: serving workload co-sign for %s on %s\n", cfg.IdentityID, cfg.Listen)
	select {
	case <-ctx.Done():
		gs.GracefulStop()
		return nil
	case err := <-errc:
		return err
	}
}

// workloadCoSignAddress splits "unix:/path" from "host:port".
func workloadCoSignAddress(listen string) (network, addr string) {
	if rest, ok := strings.CutPrefix(listen, "unix:"); ok {
		return "unix", rest
	}
	return "tcp", listen
}

// listenWorkloadCoSign opens the listener. A unix socket gets an owner-only 0700
// directory, loses any stale socket, is created 0600 at bind time (never left to
// the umask), is checked to be exactly that, and admits only allowedUID; a peer
// whose uid cannot be read is refused (F261).
func listenWorkloadCoSign(network, addr string, allowedUID int) (net.Listener, error) {
	if network != "unix" {
		return net.Listen(network, addr)
	}
	if err := workloadapi.PrepareSocket(addr); err != nil {
		return nil, err
	}
	lis, err := listenPrivateUnixSocket(addr)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(addr)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		_ = lis.Close()
		return nil, fmt.Errorf("co-sign socket %s is not an owner-only socket", addr)
	}
	return &coSignPeerListener{Listener: lis, allowedUID: allowedUID, peerUID: func(c net.Conn) (int, error) {
		id, err := workloadapi.AttestPeer(c)
		return id.UID, err
	}}, nil
}

// coSignPeerListener admits only connections from allowedUID.
type coSignPeerListener struct {
	net.Listener
	allowedUID int
	peerUID    func(net.Conn) (int, error)
}

func (l *coSignPeerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, err := l.peerUID(c); err == nil && uid == l.allowedUID {
			return c, nil
		}
		_ = c.Close()
	}
}

// coSignBulkhead bounds concurrent co-sign calls and gives each a deadline; excess
// calls are refused at once with RESOURCE_EXHAUSTED rather than queued (AN-7).
func coSignBulkhead(maxInflight int, timeout time.Duration) grpc.UnaryServerInterceptor {
	slots := make(chan struct{}, maxInflight)
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			return nil, status.Error(codes.ResourceExhausted, "workload co-sign is at capacity; retry")
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return handler(ctx, req)
	}
}

// loadPredecessorSigner loads the workload predecessor key from a PKCS#8 PEM file into
// a locked (mlock/zeroize) signer, returning a cleanup that zeroizes the key material.
func loadPredecessorSigner(path string) (crypto.Signer, func(), error) {
	if path == "" {
		return nil, nil, errors.New("workload co-sign: --workload-predecessor-key is required")
	}
	pemBytes, err := os.ReadFile(path) // #nosec G304 -- operator-configured local path from the agent's own config (CWE-22)
	if err != nil {
		return nil, nil, fmt.Errorf("workload co-sign: read predecessor key: %w", err)
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, nil, errors.New("workload co-sign: predecessor key is not PEM")
	}
	ls, err := crypto.LockedKeyFromPKCS8(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("workload co-sign: parse predecessor key: %w", err)
	}
	return crypto.SignerFromDigestSigner(ls), ls.Destroy, nil
}
