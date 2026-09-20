// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// AgentHTTPRenewalServed reports whether the embedded-agent HTTP renewal listener
// has all required production pieces: signer-custodied agent CA material, a narrow
// renewal handler, and a listen address.
func (s *Server) AgentHTTPRenewalServed() bool {
	return s.agentCASigner != nil &&
		len(s.agentCACertDER) > 0 &&
		s.agentHTTPRenewalHandler != nil &&
		s.agentHTTPRenewalAddr != ""
}

// AgentHTTPRenewalAddr returns the dedicated mTLS HTTP renewal listener address, or
// "" when it is not served.
func (s *Server) AgentHTTPRenewalAddr() string {
	if !s.AgentHTTPRenewalServed() {
		return ""
	}
	return s.agentHTTPRenewalAddr
}

// RunAgentHTTPRenewal serves POST /enroll/renewal for embedded clients over a
// dedicated HTTPS listener that requires and verifies agent client certificates
// against the signer-custodied agent CA.
func (s *Server) RunAgentHTTPRenewal(ctx context.Context) {
	if !s.AgentHTTPRenewalServed() {
		return
	}
	ln, err := net.Listen("tcp", s.agentHTTPRenewalAddr)
	if err != nil {
		s.logger.Error("agent HTTP renewal listen failed", "addr", s.agentHTTPRenewalAddr, "error", err.Error())
		return
	}
	s.serveAgentHTTPRenewal(ctx, ln)
}

func (s *Server) serveAgentHTTPRenewal(ctx context.Context, ln net.Listener) {
	s.serveAgentHTTPRenewalWithLifetime(ctx, ln, agentServerCertTTL)
}

func (s *Server) serveAgentHTTPRenewalWithLifetime(ctx context.Context, ln net.Listener, lifetime time.Duration) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !s.AgentHTTPRenewalServed() {
		_ = ln.Close()
		return
	}
	httpSrv := &http.Server{
		Handler:           s.agentHTTPRenewalHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	cert, err := s.agentChannelServerCertificate(s.agentChannelHosts(), lifetime)
	if err != nil {
		s.logger.Error("agent HTTP renewal credentials failed", "error", err.Error())
		_ = ln.Close()
		return
	}
	httpSrv.TLSConfig = cert.TLSConfig()
	stopRenewal := s.startAgentServerRenewal(ctx, cert, "https")
	defer stopRenewal()
	go func() { // #nosec G118 -- shutdown grace period must outlive the already-canceled parent context (CWE-664)
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()
	if serr := httpSrv.ServeTLS(ln, "", ""); serr != nil &&
		!errors.Is(serr, http.ErrServerClosed) &&
		ctx.Err() == nil {
		s.logger.Warn("agent HTTP renewal server stopped", "error", serr.Error())
	}
}
