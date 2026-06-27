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
		pool := bulk.Pool(bulkhead.SubsystemProtocols)
		if pool == nil {
			pool = bulk.Pool(bulkhead.SubsystemAPI)
		}
		if pool == nil {
			return nil, errors.New("KMIP requires a protocols or API bulkhead pool")
		}
		addr := strings.TrimSpace(cfg.Addr)
		if addr == "" {
			addr = defaultAddr
		}
		logger := d.Log
		if logger == nil {
			logger = slog.Default()
		}
		return &Runtime{
			addr:         addr,
			certFile:     cfg.CertFile,
			keyFile:      cfg.KeyFile,
			clientCAFile: cfg.ClientCAFile,
			service:      New(firstNonEmpty(cfg.TenantID, d.ProtocolTenant), VerifiedClientCertAuthenticator{}, audit.NewAuditor(d.EventLog)),
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
