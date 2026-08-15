// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/server"
)

const defaultAddr = ":5696"

// NewFactory adapts the licensed KMIP runtime to the core server seam.
func NewFactory() server.KMIPFactory {
	return func(d server.KMIPFactoryDeps) (server.KMIPRuntime, error) {
		cfg := d.Protocols.KMIP
		if !cfg.Enabled {
			return nil, nil
		}
		if err := errors.Join(config.Protocols{KMIP: cfg}.ValidateTenantBindings(d.ProtocolTenant)...); err != nil {
			return nil, fmt.Errorf("served KMIP tenant/TLS binding: %w", err)
		}
		bulk := d.Bulkhead
		if bulk == nil {
			bulk = bulkhead.Default()
		}
		// KMIP takes its OWN pool. A worker here is held for a whole client
		// connection — TLS handshake included — not for one request, so drawing
		// from the shared protocols pool let a handful of TCP connects that never
		// send a frame occupy every protocol worker until their deadline,
		// starving ACME, EST, SCEP, CMP, SSH and SPIFFE. That is the
		// cross-subsystem starvation AN-7 exists to prevent, so the fix is a
		// separate bulkhead rather than a bigger shared one.
		pool := bulk.Pool(bulkhead.SubsystemKMIP)
		if pool == nil {
			// No silent fallback: sharing another subsystem's lane is exactly the
			// AN-7 starvation this pool exists to prevent, and a fallback is how
			// the config-derived production set ran KMIP on the shared protocols
			// pool for a whole release (AUD-201 follow-up A2/V11). A set without
			// the lane is a wiring bug — refuse to serve rather than starve
			// ACME/EST/SCEP/CMP/SSH/SPIFFE.
			return nil, errors.New("KMIP requires its own bulkhead lane (bulkheads.kmip); refusing to fall back to a pool other subsystems depend on")
		}
		addr := strings.TrimSpace(cfg.Addr)
		if addr == "" {
			addr = defaultAddr
		}
		logger := d.Log
		if logger == nil {
			logger = slog.Default()
		}
		if d.EventLog == nil {
			return nil, errors.New("KMIP requires the source-of-truth event log")
		}
		if d.KeyWrapper == nil {
			return nil, errors.New("KMIP requires a stable envelope key wrapper")
		}
		replayCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		service, err := NewDurable(
			replayCtx,
			firstNonEmpty(cfg.TenantID, d.ProtocolTenant),
			VerifiedClientCertAuthenticator{},
			audit.NewAuditor(d.EventLog),
			d.EventLog,
			d.KeyWrapper,
			d.TenantCrypto,
		)
		if err != nil {
			return nil, fmt.Errorf("restore KMIP managed-object state: %w", err)
		}
		return &Runtime{
			addr:         addr,
			certFile:     cfg.CertFile,
			keyFile:      cfg.KeyFile,
			clientCAFile: cfg.ClientCAFile,
			service:      service,
			pool:         pool,
			log:          logger,
		}, nil
	}
}

// Runtime is the licensed KMIP listener implementation.
type Runtime struct {
	addr         string
	certFile     string
	keyFile      string
	clientCAFile string
	service      *Server
	pool         *bulkhead.Pool
	log          *slog.Logger
}

func (r *Runtime) Addr() string { return r.addr }

func (r *Runtime) Serve(ctx context.Context, ln net.Listener) error {
	tlsLn, err := mtls.MutualTLSServerListenerFromFiles(ln, r.certFile, r.keyFile, r.clientCAFile)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("configure KMIP mTLS: %w", err)
	}
	return r.serve(ctx, tlsLn)
}

func (r *Runtime) serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("kmip accept: %w", err)
		}
		if err := r.pool.Submit(func() { r.handleConn(ctx, conn) }); err != nil {
			r.log.Warn("KMIP connection rejected by bulkhead", slog.String("error", err.Error()))
			_ = conn.Close()
		}
	}
}

func (r *Runtime) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	clientCertDER, err := mtls.PeerCertificateDER(conn)
	if err != nil {
		r.log.Warn("KMIP mTLS peer rejected", slog.String("error", err.Error()))
		return
	}
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, err := ReadFrame(conn, 1<<20)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return
			}
			r.log.Warn("KMIP frame read failed", slog.String("error", err.Error()))
			return
		}
		resp, err := r.service.HandleFrame(ctx, clientCertDER, frame)
		if err != nil {
			r.log.Warn("KMIP frame handling failed", slog.String("error", err.Error()))
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(resp); err != nil {
			r.log.Warn("KMIP frame write failed", slog.String("error", err.Error()))
			return
		}
	}
}

func (r *Runtime) Close() {
	if r.service != nil {
		r.service.Close()
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
