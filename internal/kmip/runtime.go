// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/server"
)

const (
	defaultAddr               = ":5696"
	maxKMIPConnectionLifetime = 15 * time.Minute
)

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
		// Recovery reads the complete immutable KMIP history. A fixed ten-second
		// deadline made a healthy large deployment fail every cold start; use the
		// caller's startup lifetime so shutdown still cancels a pending replay.
		if d.StartupContext == nil {
			return nil, errors.New("KMIP requires a startup context for durable recovery")
		}
		open := func(tenantID string) (*Server, error) {
			service, err := NewDurable(d.StartupContext, tenantID, VerifiedClientCertAuthenticator{},
				audit.NewAuditor(d.EventLog), d.EventLog, d.KeyWrapper, d.TenantCrypto)
			if err != nil {
				return nil, fmt.Errorf("restore KMIP managed-object state: %w", err)
			}
			service.tenantServiceCheck = d.TenantServiceCheck
			return service, nil
		}
		r := &Runtime{
			addr:                      addr,
			certFile:                  cfg.CertFile,
			keyFile:                   cfg.KeyFile,
			clientCAFile:              cfg.ClientCAFile,
			pool:                      pool,
			log:                       logger,
			clientCertificateStanding: d.ClientCertificateStanding,
		}
		r.connectionLifetime.Store(int64(maxKMIPConnectionLifetime))
		// A197: with client registrations on, every tenant's enrolled clients
		// share the listener; the configured tenant, when there is one, keeps
		// the clients the deployment's client CA issued.
		if cfg.ClientRegistrations {
			if d.Clients == nil {
				return nil, errors.New("KMIP client registrations need the core client directory")
			}
			r.clients = d.Clients
			r.tenants = &tenantServers{servers: map[string]*Server{}, open: open}
			if strings.TrimSpace(cfg.ClientCAFile) != "" {
				verifier, err := mtls.NewClientChainVerifier(cfg.ClientCAFile)
				if err != nil {
					return nil, fmt.Errorf("KMIP client CA: %w", err)
				}
				r.clientCAs = verifier
			}
		}
		if tenantID := firstNonEmpty(cfg.TenantID, d.ProtocolTenant); tenantID != "" || r.clients == nil {
			service, err := open(tenantID)
			if err != nil {
				return nil, err
			}
			r.service = service
		}
		return r, nil
	}
}

// Runtime is the licensed KMIP listener implementation.
type Runtime struct {
	addr         string
	certFile     string
	keyFile      string
	clientCAFile string
	// service is the configured tenant's server: every client without client
	// registrations, the CA-issued clients with them. Nil when registrations
	// serve every client.
	service *Server
	// clients, tenants and clientCAs serve tenants' registered clients (A197).
	clients                   server.KMIPClientDirectory
	tenants                   *tenantServers
	clientCAs                 *mtls.ClientChainVerifier
	pool                      *bulkhead.Pool
	log                       *slog.Logger
	clientCertificateStanding func(context.Context, string, []byte) error
	connectionLifetime        atomic.Int64
}

func (r *Runtime) Addr() string { return r.addr }

func (r *Runtime) Serve(ctx context.Context, ln net.Listener) error {
	var tlsLn net.Listener
	var err error
	if r.clients != nil {
		// Registered clients bring their own certificates: the handshake
		// proves the client holds its certificate's key, and each request is
		// then served for the tenant the certificate belongs to, or refused.
		tlsLn, err = mtls.SelfAuthorizingClientTLSServerListenerFromFiles(ln, r.certFile, r.keyFile)
	} else {
		verify := func(leafDER []byte) error {
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := r.checkClientStanding(checkCtx, r.service, leafDER); err != nil {
				r.refuseClient(ctx, r.service, leafDER, err)
				return err
			}
			return nil
		}
		tlsLn, err = mtls.MutualTLSServerListenerFromFilesWithClientVerifier(ln, r.certFile, r.keyFile, r.clientCAFile, verify)
	}
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
	lifetime := time.Duration(r.connectionLifetime.Load())
	if lifetime <= 0 {
		lifetime = maxKMIPConnectionLifetime
	}
	end := time.Now().Add(lifetime)
	_ = conn.SetDeadline(end)
	chain, err := mtls.PeerCertificateChainDER(conn)
	if err != nil {
		r.log.Warn("KMIP mTLS peer rejected", slog.String("error", err.Error()))
		return
	}
	info, err := certinfo.Inspect(chain[0])
	if err != nil {
		r.log.Warn("KMIP client certificate inspection failed", slog.String("error", err.Error()))
		return
	}
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		now := time.Now()
		if !now.Before(end) || now.Before(info.NotBefore) || !now.Before(info.NotAfter) {
			r.log.Warn("KMIP connection lifetime or client certificate validity ended")
			return
		}
		readUntil := now.Add(30 * time.Second)
		if readUntil.After(end) || readUntil.After(info.NotAfter) {
			readUntil = end
			if info.NotAfter.Before(end) {
				readUntil = info.NotAfter
			}
		}
		_ = conn.SetReadDeadline(readUntil)
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
		// A frame may have arrived just before its read deadline. Re-check
		// validity before resolving a tenant or executing any KMIP operation.
		now = time.Now()
		if !now.Before(end) || now.Before(info.NotBefore) || !now.Before(info.NotAfter) {
			secret.Wipe(frame)
			r.log.Warn("KMIP connection lifetime or client certificate validity ended")
			return
		}
		var resp []byte
		refused := false
		service, err := r.serverFor(ctx, chain, frame)
		switch {
		case errors.Is(err, errClientNotRecognized):
			resp = refusedResponse(frame, err.Error())
		case err != nil:
			secret.Wipe(frame)
			r.log.Warn("KMIP tenant resolution failed", slog.String("error", err.Error()))
			return
		default:
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			standingErr := r.checkClientStanding(checkCtx, service, chain[0])
			cancel()
			if standingErr != nil {
				r.refuseClient(ctx, service, chain[0], standingErr)
				resp = refusedResponse(frame, "client certificate is no longer authorized")
				refused = true
			} else {
				resp, err = service.HandleFrame(ctx, chain[0], frame)
				if err != nil {
					secret.Wipe(frame)
					r.log.Warn("KMIP frame handling failed", slog.String("error", err.Error()))
					return
				}
			}
		}
		secret.Wipe(frame)
		writeNow := time.Now()
		if !writeNow.Before(end) || !writeNow.Before(info.NotAfter) {
			secret.Wipe(resp)
			r.log.Warn("KMIP connection lifetime or client certificate validity ended before response")
			return
		}
		writeUntil := writeNow.Add(30 * time.Second)
		if writeUntil.After(end) {
			writeUntil = end
		}
		if writeUntil.After(info.NotAfter) {
			writeUntil = info.NotAfter
		}
		_ = conn.SetWriteDeadline(writeUntil)
		_, err = conn.Write(resp)
		secret.Wipe(resp)
		if err != nil {
			r.log.Warn("KMIP frame write failed", slog.String("error", err.Error()))
			return
		}
		if refused {
			return
		}
	}
}

func (r *Runtime) checkClientStanding(ctx context.Context, service *Server, leafDER []byte) error {
	if service == nil {
		return errors.New("kmip: client certificate has no tenant service")
	}
	if r.clientCertificateStanding == nil {
		return nil
	}
	return r.clientCertificateStanding(ctx, service.tenantID, leafDER)
}

func (r *Runtime) refuseClient(ctx context.Context, service *Server, leafDER []byte, cause error) {
	if service == nil {
		r.log.Warn("KMIP client certificate refused", slog.String("error", cause.Error()))
		return
	}
	r.log.Warn("KMIP client certificate refused", slog.String("tenant_id", service.tenantID), slog.String("error", cause.Error()))
	data := []byte(fmt.Sprintf(`{"fingerprint":%q,"reason":"not_in_good_standing"}`, crypto.SHA256Hex(leafDER)))
	auditCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = auditsink.Emit(auditCtx, service.audit, r.log, "kmip.client_certificate_refused", service.tenantID, data)
}

func (r *Runtime) Close() {
	if r.service != nil {
		r.service.Close()
	}
	if r.tenants != nil {
		r.tenants.close()
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
