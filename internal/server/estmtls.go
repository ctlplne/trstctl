// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/est"
	"trstctl.com/trstctl/internal/store"
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
// bootstrap token is involved. Only an active EST certificate of the mount's
// tenant renews there (estMTLSClientCertificate), and enrollment and server-side
// keygen are refused (CR-059). The main listener keeps its token-authenticated
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

// estMTLSClientCertificate is the EST mount's mutual-TLS client gate (CR-059,
// CR-058): a verified leaf renews only when it is an active EST certificate the
// platform issuing CA issued into the mount's own tenant. The leaf's standing is
// read as the OCSP responder reads it (pending revocation, then the issued-
// certificate ledger); the tenant's inventory row for its fingerprint must carry
// the same serial, must not be revoked, and must be an EST leaf. Any error refuses.
func (s *Server) estMTLSClientCertificate(tenantID string) func(context.Context, []byte) error {
	return func(ctx context.Context, leafDER []byte) error {
		if strings.TrimSpace(tenantID) == "" {
			return errors.New("server: the EST mount has no tenant")
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil {
			return fmt.Errorf("server: inspect the EST client certificate: %w", err)
		}
		caID := IssuingCAID()
		standing, _, err := issuedCertStatus(ctx, s.store, tenantID, caID, info.SerialNumber)
		if err != nil {
			return fmt.Errorf("server: read the EST client certificate's standing: %w", err)
		}
		if standing != issuedCertGood {
			return errors.New("server: the EST client certificate is not in good standing at the issuing CA")
		}
		row, err := s.store.GetCertificateByFingerprint(ctx, tenantID, info.SHA256Fingerprint)
		if err != nil {
			return fmt.Errorf("server: the EST client certificate is not in the mount's inventory: %w", err)
		}
		if !strings.EqualFold(row.Serial, info.SerialNumber) || row.Status == "revoked" {
			return errors.New("server: the EST client certificate's inventory row does not match or is revoked")
		}
		// Only a leaf the EST enrollment path issued renews here, so a credential
		// another platform-CA path issued (a per-attempt SVID, a just-in-time or
		// broker leaf) cannot become a long-lived EST leaf. The recorded
		// enrollment path is kept from the first issuance record; a row recorded
		// before it was kept proves its path by the ledger's mint instead.
		switch row.EnrollmentProtocol {
		case "est":
			return nil
		case "":
			minted, err := s.estLedgerMintIsEST(ctx, tenantID, caID, info)
			if err != nil {
				return fmt.Errorf("server: read the EST client certificate's issuance record: %w", err)
			}
			if minted {
				return nil
			}
		}
		return errors.New("server: the client certificate was not issued by EST enrollment")
	}
}

// estLedgerMintIsEST reports whether a certificate's CA ledger row was minted by
// EST enrollment. The inventory row's source is current observation provenance
// that a later import may relabel, so it proves nothing; the ledger instead binds
// the serial to the event that first created it, never backfilled or replaced,
// and that event, read back from the log, must be this tenant's issuance record
// of this certificate from the EST path. A ledger row an older writer recorded
// without its mint proves nothing either.
func (s *Server) estLedgerMintIsEST(ctx context.Context, tenantID, caID string, info certinfo.Info) (bool, error) {
	var mint store.IssuedCertMint
	var found bool
	if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		mint, found, err = s.store.IssuedCertEventTx(ctx, tx, tenantID, caID, info.SerialNumber)
		return err
	}); err != nil {
		return false, err
	}
	if !found || mint.EventID == "" || mint.EventType != projections.EventCertificateRecorded || s.log == nil {
		return false, nil
	}
	event, found, err := s.log.EventByID(ctx, mint.EventID)
	if err != nil || !found {
		return false, err
	}
	if event.TenantID != tenantID || event.Type != projections.EventCertificateRecorded {
		return false, nil
	}
	var recorded projections.CertificateRecorded
	if err := json.Unmarshal(event.Data, &recorded); err != nil {
		return false, err
	}
	return recorded.Source == "protocol:est" && strings.EqualFold(recorded.CAID, caID) &&
		strings.EqualFold(recorded.Serial, info.SerialNumber) &&
		strings.EqualFold(recorded.Fingerprint, info.SHA256Fingerprint), nil
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
	httpSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10}
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
