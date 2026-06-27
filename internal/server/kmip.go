package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// KMIPRuntime is the core-owned lifecycle contract for the licensed KMIP server.
type KMIPRuntime interface {
	Addr() string
	Serve(context.Context, net.Listener) error
	Close()
}

// KMIPFactory is supplied by the tagged EE attach seam. Nil means the raw KMIP
// listener is not mounted, even if config carries a protocols.kmip block.
type KMIPFactory func(KMIPFactoryDeps) (KMIPRuntime, error)

// KMIPFactoryDeps are the core spine dependencies the licensed KMIP runtime
// consumes without importing server internals.
type KMIPFactoryDeps struct {
	Protocols      config.Protocols
	ProtocolTenant string
	Bulkhead       *bulkhead.Set
	Log            *slog.Logger
	EventLog       *events.Log
}

func (s *Server) configureKMIPSurface(d Deps) error {
	if d.KMIPFactory == nil {
		s.kmip = nil
		return nil
	}
	runtime, err := d.KMIPFactory(KMIPFactoryDeps{
		Protocols:      d.Protocols,
		ProtocolTenant: d.ProtocolTenant,
		Bulkhead:       s.bulk,
		Log:            s.logger,
		EventLog:       d.Log,
	})
	if err != nil {
		return fmt.Errorf("server: configure KMIP: %w", err)
	}
	s.kmip = runtime
	return nil
}

// KMIPServed reports whether the running server has the KMS-02 KMIP listener
// configured. It is a served-path wiring assertion for tests and startup logs.
func (s *Server) KMIPServed() bool { return s.kmip != nil }

// KMIPAddr returns the configured KMIP listener address, or empty when KMIP is off.
func (s *Server) KMIPAddr() string {
	if s.kmip == nil {
		return ""
	}
	return s.kmip.Addr()
}

// RunKMIP binds and serves the configured KMIP listener until ctx is cancelled.
func (s *Server) RunKMIP(ctx context.Context) {
	if s.kmip == nil {
		return
	}
	addr := s.kmip.Addr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("KMIP listener failed to bind", slog.String("addr", addr), slog.String("error", err.Error()))
		}
		return
	}
	if err := s.ServeKMIP(ctx, ln); err != nil && s.logger != nil {
		s.logger.Error("KMIP listener stopped with error", slog.String("addr", addr), slog.String("error", err.Error()))
	}
}

// ServeKMIP serves the licensed KMIP runtime on an already-open listener. Tests
// pass an ephemeral listener; production calls RunKMIP so the configured address is
// used.
func (s *Server) ServeKMIP(ctx context.Context, ln net.Listener) error {
	if s.kmip == nil {
		_ = ln.Close()
		return errors.New("server: KMIP is not configured")
	}
	return s.kmip.Serve(ctx, ln)
}
