package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/protocols/cmp"
	"trstctl.com/trstctl/internal/protocols/est"
	"trstctl.com/trstctl/internal/protocols/scep"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/protocols/ssh"
	"trstctl.com/trstctl/internal/signing"
)

const (
	// protocolRATTL is the validity of the in-process SCEP/CMP transport RA cert.
	protocolRATTL = 365 * 24 * time.Hour
	// sshCAHandle is the fixed signer handle for the SSH CA key (stable across
	// restarts, constrained to PurposeSSHCert).
	sshCAHandle = "ssh-ca"
	// spiffeJWTHandle is the fixed signer handle for the SPIFFE JWT-SVID signing key.
	spiffeJWTHandle = "spiffe-jwt-ca"
	// defaultSPIFFESocket is the default UDS path the SPIFFE Workload API binds when
	// the operator does not configure one. It matches the SPIRE-style default
	// location a spiffe-helper / Envoy SDS client looks for.
	defaultSPIFFESocket = "/tmp/trstctl-spiffe-workload.sock"
)

// servedProtocols holds the issuance-protocol servers the control plane mounts on
// its TLS listener (EXC-WIRE-02). It is assembled only when an issuing CA is
// provisioned (a signer is configured); each protocol routes issuance through the
// shared protocolIssuer, which signs via the signer (AN-3/AN-4), records the cert as
// an event (AN-2), is tenant-scoped (AN-1), idempotent (AN-5), and profile-gated. The
// SPIFFE Workload API is a gRPC service on a UDS, so it is run by RunSPIFFE rather
// than mounted on the HTTP mux.
type servedProtocols struct {
	acme   *acme.Server
	est    *est.Server
	scep   *scep.Server
	cmp    *cmp.Server
	ssh    *sshProtocol
	spiffe *spiffeProtocol

	estTenant  string
	scepTenant string
	cmpTenant  string

	names []string // protocols actually served (logging / assertions)
}

// buildServedProtocols constructs the enabled protocol servers over the served
// issuance seam. It returns nil (no error) when no issuing CA is provisioned — like
// revocation, protocol serving is then unavailable rather than backed by an
// in-process key. tenantFallback is the platform default tenant a protocol binds when
// its own TenantID is unset.
func (s *Server) buildServedProtocols(ctx context.Context, cfg config.Protocols, tenantFallback string, acmeValidators *acme.Validators) (*servedProtocols, error) {
	if s.caSigner == nil || len(s.caCertDER) == 0 {
		return nil, nil // no issuing CA → protocols not served (fail closed)
	}
	issuer := &protocolIssuer{
		issue:          s.IssueLeaf,
		orch:           s.orch,
		idem:           s.idem,
		store:          s.store,
		log:            s.log,
		caID:           IssuingCAID(),
		defaultProfile: s.defaultProfile,
		ensureCRL: func(ctx context.Context, tenantID string) error {
			if s.revoc == nil {
				return nil
			}
			return s.revoc.ensureCRL(ctx, tenantID)
		},
		publishCRL: func(ctx context.Context, tenantID string) error {
			if s.revoc == nil {
				return nil
			}
			_, err := s.revoc.generateCRL(ctx, tenantID)
			return err
		},
	}
	sp := &servedProtocols{}

	// Protocols run on their own bounded pool (AN-7) so an enrollment burst sheds
	// rather than starving the API/liveness pools; fall back to the API pool when a
	// custom bulkhead set omits a protocols pool.
	pool := s.bulk.Pool(bulkhead.SubsystemProtocols)
	if pool == nil {
		pool = s.bulk.Pool(bulkhead.SubsystemAPI)
	}

	if cfg.ACME.Enabled {
		// ACME (RFC 8555) brokers issuance to a ca.CA; we hand it an adapter minting
		// through the served signer path. Validation uses the production validators
		// (real HTTP-01/DNS-01/TLS-ALPN-01, fail closed) unless an override is injected
		// (the acceptance test points a loopback-capable validator at a test challenge
		// server; production never sets the override).
		acmeTenant := firstNonEmpty(cfg.ACME.TenantID, tenantFallback)
		validators := acme.DefaultValidators()
		if acmeValidators != nil {
			validators = *acmeValidators
		}
		sp.acme = acme.New(protocolCAAdapter{tenantID: acmeTenant, issuer: issuer}, validators).
			WithRevocationHook(func(ctx context.Context, req acme.RevocationRequest) error {
				return issuer.RevokeProtocolLeaf(ctx, acmeTenant, "acme", req.Fingerprint, req.Serial, req.Reason, req.CertDER)
			})
		sp.names = append(sp.names, "acme")
	}

	if cfg.EST.Enabled {
		sp.estTenant = firstNonEmpty(cfg.EST.TenantID, tenantFallback)
		sp.est = est.New(est.Config{
			Enroller:   enrollerAdapter{tenantID: sp.estTenant, issuer: issuer},
			Auth:       servedEnrollAuth{store: s.store, tenantID: sp.estTenant},
			CAChainDER: [][]byte{s.caCertDER},
			Pool:       pool,
			Log:        s.log,
		})
		sp.names = append(sp.names, "est")
	}

	// SCEP / CMP need an in-process RSA transport key for CMS transport that is
	// DELIBERATELY NOT the CA key (AN-4): the CA key stays in the signer and the
	// transport key never enters the signer process. Leaf signing still routes
	// through the signer via the Enroller.
	if cfg.SCEP.Enabled || cfg.CMP.Enabled {
		raCertDER, raKeyPKCS8, err := s.protocolTransportKey()
		if err != nil {
			return nil, fmt.Errorf("server: provision protocol transport key: %w", err)
		}
		if cfg.SCEP.Enabled {
			sp.scepTenant = firstNonEmpty(cfg.SCEP.TenantID, tenantFallback)
			// GetCACert returns the RSA RA cert FIRST (the CMS recipient a SCEP client
			// envelops its request to — the issuing CA key is ECDSA in the signer and
			// cannot be a CMS recipient, AN-4), followed by the issuing CA cert so the
			// client can also build the chain. The issued leaf is still signed by the
			// signer via the Enroller and verifies against the issuing CA.
			sp.scep = scep.New(scep.Config{
				Enroller:   enrollerAdapter{tenantID: sp.scepTenant, issuer: issuer},
				CAChainDER: [][]byte{raCertDER, s.caCertDER},
				RACertDER:  raCertDER,
				RAKeyPKCS8: raKeyPKCS8,
				Pool:       pool,
				Log:        s.log,
			})
			sp.names = append(sp.names, "scep")
		}
		if cfg.CMP.Enabled {
			sp.cmpTenant = firstNonEmpty(cfg.CMP.TenantID, tenantFallback)
			sp.cmp = cmp.New(cmp.Config{
				Enroller:   enrollerAdapter{tenantID: sp.cmpTenant, issuer: issuer},
				CACertDER:  raCertDER,
				CAKeyPKCS8: raKeyPKCS8,
				Pool:       pool,
				Log:        s.log,
			})
			sp.names = append(sp.names, "cmp")
		}
	}

	if cfg.SSH.Enabled {
		sshTenant := firstNonEmpty(cfg.SSH.TenantID, tenantFallback)
		sshCA, err := s.buildSSHCA(ctx, sshTenant, pool)
		if err != nil {
			return nil, fmt.Errorf("server: build SSH CA: %w", err)
		}
		sp.ssh = sshCA
		sp.names = append(sp.names, "ssh")
	}

	if cfg.SPIFFE.Enabled && cfg.SPIFFE.TrustDomain != "" {
		spf, err := s.buildSPIFFE(ctx, cfg.SPIFFE, tenantFallback, pool)
		if err != nil {
			return nil, fmt.Errorf("server: build SPIFFE Workload API: %w", err)
		}
		sp.spiffe = spf
		sp.names = append(sp.names, "spiffe")
	}

	return sp, nil
}

// routes mounts the HTTP-served protocols (ACME/EST/SCEP/CMP/SSH) on mux, each on the
// API bulkhead pool. The EST/SCEP/CMP handlers carry their bound tenant into the
// serving context so their protocol audit events are tenant-attributed (AN-1/AN-2);
// the actual mint is already tenant-correct via the Enroller. SPIFFE is not mounted
// here (a gRPC UDS service).
func (sp *servedProtocols) routes(mux *http.ServeMux, bulk *bulkhead.Set) {
	wrap := func(h http.Handler) http.Handler { return bulkheadHandler(bulk, bulkhead.SubsystemAPI, h) }
	if sp.acme != nil {
		mux.Handle("/directory", wrap(sp.acme))
		mux.Handle("/acme/", wrap(sp.acme))
	}
	if sp.est != nil {
		mux.Handle("/.well-known/est/", wrap(tenantCtxHandler(sp.est, func(ctx context.Context) context.Context {
			return est.WithTenant(ctx, sp.estTenant)
		})))
	}
	if sp.scep != nil {
		h := tenantCtxHandler(sp.scep, func(ctx context.Context) context.Context { return scep.WithTenant(ctx, sp.scepTenant) })
		mux.Handle("/scep", wrap(h))
		mux.Handle("/scep/", wrap(h))
	}
	if sp.cmp != nil {
		mux.Handle("/cmp", wrap(tenantCtxHandler(sp.cmp, func(ctx context.Context) context.Context {
			return cmp.WithTenant(ctx, sp.cmpTenant)
		})))
	}
	if sp.ssh != nil {
		mux.Handle("/ssh/", wrap(sp.ssh))
	}
}

// tenantCtxHandler returns an http.Handler that injects a per-protocol tenant into
// the request context (via the protocol's WithTenant) before delegating, so the
// protocol's audit events are tenant-attributed.
func tenantCtxHandler(next http.Handler, with func(context.Context) context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(with(r.Context())))
	})
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// protocolTransportKey mints (once per process) the in-process RSA transport key
// SCEP/CMP use for CMS transport. It is NOT the CA key (AN-4: the CA key stays in the
// signer). It is memoized so SCEP and CMP share one.
func (s *Server) protocolTransportKey() (certDER, keyPKCS8 []byte, err error) {
	if s.protoRACertDER != nil && s.protoRAKeyPKCS8 != nil {
		return s.protoRACertDER, s.protoRAKeyPKCS8, nil
	}
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		return nil, nil, err
	}
	der, err := crypto.SelfSignedCACert(signer, "trstctl Protocol RA", protocolRATTL)
	if err != nil {
		signer.Destroy()
		return nil, nil, err
	}
	pkcs8, err := signer.PKCS8()
	if err != nil {
		signer.Destroy()
		return nil, nil, err
	}
	s.protoRACertDER = der
	s.protoRAKeyPKCS8 = pkcs8
	return der, pkcs8, nil
}

// buildSSHCA provisions the SSH CA key in the signer (its own handle, constrained to
// PurposeSSHCert) and returns the served SSH protocol surface.
func (s *Server) buildSSHCA(ctx context.Context, tenantID string, pool *bulkhead.Pool) (*sshProtocol, error) {
	c := s.signer.Client()
	if c == nil {
		return nil, fmt.Errorf("server: signer unavailable for SSH CA")
	}
	sshSigner, err := s.sshCASigner(ctx, c)
	if err != nil {
		return nil, err
	}
	ca, err := ssh.New(ssh.Config{TenantID: tenantID, Signer: sshSigner, Pool: pool, Audit: audit.NewAuditor(s.log)})
	if err != nil {
		return nil, err
	}
	return newSSHProtocol(ca, tenantID)
}

// sshCASigner returns a signer-backed DigestSigner for the SSH CA key, generated in
// the signer under a fixed handle constrained to PurposeSSHCert (stable across
// restarts; cannot be coerced into X.509 signing). The CA key never leaves the
// signer (AN-4).
func (s *Server) sshCASigner(ctx context.Context, c *signing.Client) (crypto.DigestSigner, error) {
	if remote, err := s.signerForPrivilegedHandle(ctx, c, sshCAHandle, signing.PurposeSSHCert); err == nil {
		return remote, nil
	}
	return s.generatePrivilegedKeyHandle(ctx, c, crypto.ECDSAP256, sshCAHandle,
		[]signing.KeyPurpose{signing.PurposeSSHCert}, signing.PurposeSSHCert)
}

// buildSPIFFE provisions the SPIFFE Workload API server: the X509-SVID CA is the
// served issuing CA in the signer; the JWT-SVID signing key gets its own signer
// handle. It returns the assembled gRPC server + socket (served by RunSPIFFE).
func (s *Server) buildSPIFFE(ctx context.Context, cfg config.SPIFFEProtocol, tenantFallback string, pool *bulkhead.Pool) (*spiffeProtocol, error) {
	c := s.signer.Client()
	if c == nil {
		return nil, fmt.Errorf("server: signer unavailable for SPIFFE")
	}
	jwtSigner, err := s.spiffeJWTSigner(ctx, c)
	if err != nil {
		return nil, err
	}
	tenant := firstNonEmpty(cfg.TenantID, tenantFallback)
	td := cfg.TrustDomain
	issuer := &spiffe.CAIssuer{
		CACertDER: s.caCertDER,
		CASigner:  s.caSigner, // signer-backed (AN-4)
		JWTSigner: jwtSigner,
		JWTKeyID:  "spiffe-jwt",
	}
	// A default registration entry so the served socket is immediately usable: a
	// local UDS caller (selector "unix") receives an SVID for the trust domain's
	// default workload ID. Production registers per-workload entries.
	entries := []spiffe.RegistrationEntry{{
		SPIFFEID:  "spiffe://" + td + "/workload",
		Selectors: []string{"unix"},
	}}
	wl, err := spiffe.New(spiffe.Config{
		Issuer: issuer, TenantID: tenant, TrustDomain: td, Entries: entries, Pool: pool,
		// AN-2: SVID issuance is audited into the event log (the source of truth),
		// the same adapter the rest of the spine uses.
		Audit: audit.NewAuditor(s.log),
	})
	if err != nil {
		return nil, err
	}
	socket := cfg.SocketPath
	if socket == "" {
		socket = defaultSPIFFESocket
	}
	return &spiffeProtocol{server: spiffe.NewWorkloadAPIServer(wl, []string{"unix"}), socket: socket}, nil
}

// spiffeJWTSigner returns a signer-backed DigestSigner for the SPIFFE JWT-SVID
// signing key (its own handle). The key never leaves the signer (AN-4).
func (s *Server) spiffeJWTSigner(ctx context.Context, c *signing.Client) (crypto.DigestSigner, error) {
	if remote, err := s.signerForPrivilegedHandle(ctx, c, spiffeJWTHandle, signing.PurposeGeneric); err == nil {
		return remote, nil
	}
	return s.generatePrivilegedKeyHandle(ctx, c, crypto.ECDSAP256, spiffeJWTHandle,
		[]signing.KeyPurpose{signing.PurposeGeneric}, signing.PurposeGeneric)
}
