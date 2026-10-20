// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/protocols/est"
)

// ESTMTLSAddr returns the dedicated mutual-TLS EST listener address, or "" when
// the listener is not configured or EST is not served.
func (s *Server) ESTMTLSAddr() string {
	if s == nil || s.estMTLSAddr == "" || s.protocols == nil || s.protocols.estServer == nil {
		return ""
	}
	return s.estMTLSAddr
}

// RunESTMTLS serves EST on a second HTTPS listener that requires a client
// certificate issued by this control plane's enrollment CA. On that listener
// `/.well-known/est/simplereenroll` authenticates the device by the certificate
// it presents and binds the renewal CSR to that certificate's identifiers; no
// bootstrap token is involved. The main listener keeps its token-authenticated
// routes and never requests a client certificate, so browsers are not prompted.
func (s *Server) RunESTMTLS(ctx context.Context) {
	addr := s.ESTMTLSAddr()
	if addr == "" {
		return
	}
	if s.serverTLS.Mode == config.TLSDisabled {
		s.logger.Error("EST mutual-TLS listener refused: server.tls.mode=disabled cannot authenticate a client certificate", "addr", addr)
		return
	}
	sc, err := controlPlaneServerCert(s.serverTLS)
	if err != nil {
		s.logger.Error("EST mutual-TLS listener credentials failed", "addr", addr, "error", err.Error())
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("EST mutual-TLS listen failed", "addr", addr, "error", err.Error())
		return
	}
	s.serveESTMTLS(ctx, ln, sc)
}

// estMTLSClientCAs is the trust anchor set a re-enrolling device chains to: the
// enrollment CA whose leaves EST itself issues.
func (s *Server) estMTLSClientCAs() ([][]byte, error) {
	if len(s.caCertDER) == 0 {
		return nil, errors.New("server: EST mutual-TLS listener needs the enrollment CA certificate")
	}
	return [][]byte{append([]byte(nil), s.caCertDER...)}, nil
}

func (s *Server) serveESTMTLS(ctx context.Context, ln net.Listener, sc *mtls.ServerCert) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	estServer := s.protocols.estServer
	if estServer == nil {
		_ = ln.Close()
		return
	}
	casDER, err := s.estMTLSClientCAs()
	if err != nil {
		s.logger.Error("EST mutual-TLS listener trust failed", "error", err.Error())
		_ = ln.Close()
		return
	}
	estServer.SetMTLSClientCAs(casDER)
	// Same serving context as the main mount: the bound tenant for audit
	// attribution (AN-1/AN-2), the eval activation gate, and the API bulkhead.
	handler := tenantCtxHandler(est.MTLSRouteHandler(estServer), func(ctx context.Context) context.Context {
		return est.WithTenant(ctx, s.protocols.estTenant)
	})
	handler = bulkheadHandler(s.bulk, bulkhead.SubsystemAPI, protocolActivationHandler(s.protocols.activation, handler))
	httpSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { // #nosec G118 -- shutdown grace period must outlive the already-canceled parent context (CWE-664)
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()
	if serr := sc.ServeMutualHTTPS(httpSrv, ln, casDER); serr != nil &&
		!errors.Is(serr, http.ErrServerClosed) && ctx.Err() == nil {
		s.logger.Warn("EST mutual-TLS server stopped", "error", serr.Error())
	}
}
