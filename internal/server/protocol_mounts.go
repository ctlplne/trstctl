// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	mdmchallenge "trstctl.com/trstctl/internal/mdm/challenge"
	"trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/protocols/cmp"
	"trstctl.com/trstctl/internal/protocols/est"
	"trstctl.com/trstctl/internal/protocols/scep"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/protocols/ssh"
	"trstctl.com/trstctl/internal/ratelimit"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/tsa"
)

const (
	// protocolRATTL is the validity of the in-process SCEP/CMP transport RA cert.
	protocolRATTL = 365 * 24 * time.Hour
	// sshCAHandle is the fixed signer handle for the SSH CA key (stable across
	// restarts, constrained to PurposeSSHCert).
	sshCAHandle = "ssh-ca"
	// spiffeJWTHandle is the fixed signer handle for the SPIFFE JWT-SVID signing key.
	spiffeJWTHandle = "spiffe-jwt-ca"
	// tsaSignerHandle is the fixed signer handle for the RFC 3161 timestamping key.
	tsaSignerHandle = "tsa-timestamping"
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
	est    http.Handler
	scep   http.Handler
	cmp    *cmp.Server
	tsa    *tsa.Authority
	ssh    *sshProtocol
	spiffe *spiffeProtocol

	estTenant                 string
	acmeTenant                string
	scepTenant                string
	cmpTenant                 string
	tsaTenant                 string
	cmpClientTrustAnchorCount int
	cmpBulkheadReady          bool

	names []string // protocols actually served (logging / assertions)

	// activation is set only for the explicit eval profile. Its first-run action
	// opens every HTTP route and the SPIFFE worker together; normal production
	// protocol toggles leave it nil and retain their existing startup behavior.
	activation *protocolActivationGate
}

func (sp *servedProtocols) Close() {
	if sp == nil {
		return
	}
	if sp.acme != nil {
		sp.acme.Destroy()
	}
}

// buildServedProtocols constructs the enabled protocol servers over the served
// issuance seam. It returns nil (no error) when no issuing CA is provisioned — like
// revocation, protocol serving is then unavailable rather than backed by an
// in-process key. tenantFallback is the platform default tenant a protocol binds when
// its own TenantID is unset.
func (s *Server) buildServedProtocols(ctx context.Context, cfg config.Protocols, tenantFallback string, keyWrapper sealKeyWrapper, acmeValidators *acme.Validators) (*servedProtocols, error) {
	if s.caSigner == nil || len(s.caCertDER) == 0 {
		return nil, nil // no issuing CA → protocols not served (fail closed)
	}
	issuer := s.newProtocolIssuer()
	sp := &servedProtocols{}

	// Protocols run on their own bounded pool (AN-7) so an enrollment burst sheds
	// rather than starving the API/liveness pools; fall back to the API pool when a
	// custom bulkhead set omits a protocols pool.
	pool := s.bulk.Pool(bulkhead.SubsystemProtocols)
	if pool == nil {
		pool = s.bulk.Pool(bulkhead.SubsystemAPI)
	}

	if cfg.ACME.Enabled {
		acmeSrv, err := s.buildServedACME(ctx, cfg, tenantFallback, issuer, acmeValidators)
		if err != nil {
			return nil, err
		}
		sp.acme = acmeSrv
		sp.acmeTenant = firstNonEmpty(cfg.ACME.TenantID, tenantFallback)
		sp.names = append(sp.names, "acme")
	}

	if cfg.EST.Enabled {
		sp.estTenant = firstNonEmpty(cfg.EST.TenantID, tenantFallback)
		estSrv := est.New(est.Config{
			Enroller:     enrollerAdapter{tenantID: sp.estTenant, issuer: issuer},
			Auth:         servedEnrollAuth{store: s.store, tenantID: sp.estTenant},
			CAChainDER:   [][]byte{s.caCertDER},
			Pool:         pool,
			Log:          s.log,
			CSRVerifier:  issuer.verifyCSR,
			CSRInspector: issuer.inspectCSRInfo,
			FailureDiagnosis: func(requestCtx context.Context, diagnosis enrollmentdiag.Diagnosis) {
				if s.api == nil {
					return
				}
				if err := s.api.RecordEnrollmentDiagnosis(requestCtx, sp.estTenant, diagnosis); err != nil && s.logger != nil {
					s.logger.Warn("enrollment diagnosis persistence failed", slog.String("protocol", string(diagnosis.Protocol)), slog.String("error", err.Error()))
				}
			},
		})
		dispatcher, err := est.NewDispatcher([]est.ProfileRoute{{Server: estSrv}})
		if err != nil {
			return nil, fmt.Errorf("server: build served EST dispatcher: %w", err)
		}
		sp.est = dispatcher
		sp.names = append(sp.names, "est")
	}

	// SCEP / CMP need an RSA transport key for CMS transport that is DELIBERATELY NOT
	// the CA key (AN-4): the CA key stays in the signer and the transport key is used
	// only for protocol message protection. The RA identity is sealed at rest and
	// shared by replicas so cached SCEP/CMP clients survive restart/rolling deploys.
	if cfg.SCEP.Enabled || cfg.CMP.Enabled {
		raCertDER, raKeyPKCS8, err := s.protocolTransportKey(cfg.RAKeyFile, keyWrapper)
		if err != nil {
			return nil, fmt.Errorf("server: provision protocol transport key: %w", err)
		}
		if cfg.SCEP.Enabled {
			scepHandler, scepTenant, err := s.buildServedSCEP(cfg, tenantFallback, issuer, raCertDER, raKeyPKCS8, pool, keyWrapper)
			if err != nil {
				return nil, err
			}
			sp.scepTenant = scepTenant
			sp.scep = scepHandler
			sp.names = append(sp.names, "scep")
		}
		if cfg.CMP.Enabled {
			if err := s.buildServedCMP(cfg, tenantFallback, issuer, raCertDER, raKeyPKCS8, pool, sp); err != nil {
				return nil, err
			}
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

	if cfg.TSA.Enabled {
		sp.tsaTenant = firstNonEmpty(cfg.TSA.TenantID, tenantFallback)
		authority, err := s.buildTSA(ctx, sp.tsaTenant, cfg.TSACertFile)
		if err != nil {
			return nil, fmt.Errorf("server: build TSA: %w", err)
		}
		sp.tsa = authority
		sp.names = append(sp.names, "tsa")
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

func (s *Server) newProtocolIssuer() *protocolIssuer {
	return &protocolIssuer{
		issue:              s.IssueLeafWithProfile,
		issueLicensed:      s.IssueLicensedLeafWithProfile,
		inspectLicensedCSR: s.licensedCSRInspector,
		parseLicensedCSR:   s.licensedCSRParser,
		orch:               s.orch,
		idem:               s.idem,
		store:              s.store,
		log:                s.log,
		caID:               IssuingCAID(),
		defaultProfile:     s.defaultProfile,
		leafProfile:        s.leafProfile,
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
		tenantCrypto: s.tenantCrypto,
	}
}

func (s *Server) buildServedACME(ctx context.Context, cfg config.Protocols, tenantFallback string, issuer *protocolIssuer, acmeValidators *acme.Validators) (*acme.Server, error) {
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
	acmeSrv := acme.New(protocolCAAdapter{
		tenantID:  acmeTenant,
		issuer:    issuer,
		caCertDER: append([]byte(nil), s.caCertDER...),
	}, validators).
		WithQuota(acmeQuotaConfig(cfg.ACMEQuota)).
		WithDeviceAttestationPolicy(acmeDeviceAttestationProfiles{
			store:       s.store,
			profileName: s.defaultProfile,
		})
	if s.acmeDNS01 != nil {
		acmeSrv = acmeSrv.WithDNS01Automation(s.acmeDNS01).WithDomainValidationPolicy(s.acmeDNS01)
	}
	// I4: every refusal this server issues becomes a classified diagnosis an
	// operator can read. Wired here rather than left as a library the served
	// binary never calls — which is what it was.
	if s.api != nil {
		acmeSrv.SetFailureDiagnosis(func(requestCtx context.Context, diagnosis enrollmentdiag.Diagnosis) {
			if err := s.api.RecordEnrollmentDiagnosis(requestCtx, acmeTenant, diagnosis); err != nil && s.logger != nil {
				s.logger.Warn("enrollment diagnosis persistence failed", slog.String("protocol", string(diagnosis.Protocol)), slog.String("error", err.Error()))
			}
		})
	}
	eabKeys, err := acmeExternalAccountBindingKeys(cfg.ACMEEAB)
	if err != nil {
		return nil, err
	}
	if cfg.ACMEEAB.Required || len(eabKeys) > 0 {
		acmeSrv, err = acmeSrv.WithExternalAccountBindings(cfg.ACMEEAB.Required, eabKeys)
		destroyACMEEABKeyCopies(eabKeys)
		if err != nil {
			return nil, fmt.Errorf("build served ACME EAB: %w", err)
		}
	}
	if cfg.ACMEQuota.MaxNewOrdersPerAccount > 0 {
		acmeSrv = acmeSrv.WithAccountOrderLimiter(ratelimit.NewACMEAccountOrders(s.store))
	}
	acmeSrv, err = acmeSrv.WithStateLog(ctx, acmeTenant, s.log)
	if err != nil {
		return nil, fmt.Errorf("build served ACME state: %w", err)
	}
	return acmeSrv.WithRevocationHook(func(ctx context.Context, req acme.RevocationRequest) error {
		return issuer.RevokeProtocolLeaf(ctx, acmeTenant, "acme", req.Fingerprint, req.Serial, req.Reason, req.CertDER)
	}), nil
}

func acmeExternalAccountBindingKeys(cfg config.ACMEExternalAccountBinding) ([]acme.ExternalAccountBindingKey, error) {
	if len(cfg.Keys) == 0 {
		return nil, nil
	}
	keys := make([]acme.ExternalAccountBindingKey, 0, len(cfg.Keys))
	for _, in := range cfg.Keys {
		raw := append([]byte(nil), in.HMACKey...)
		if in.HMACKeyFile != "" {
			data, err := os.ReadFile(in.HMACKeyFile)
			if err != nil {
				destroyACMEEABKeyCopies(keys)
				return nil, fmt.Errorf("read protocols.acme_eab key file %q: %w", in.HMACKeyFile, err)
			}
			raw = append(raw[:0], bytes.TrimSpace(data)...)
			secret.Wipe(data)
		}
		notAfter, err := in.NotAfterTime()
		if err != nil {
			destroyACMEEABKeyCopies(keys)
			secret.Wipe(raw)
			return nil, fmt.Errorf("protocols.acme_eab key %q not_after: %w", in.KeyID, err)
		}
		keys = append(keys, acme.ExternalAccountBindingKey{
			KeyID: in.KeyID, HMACKey: raw,
			// The scope travels with the key so a credential is an authorization
			// rather than a doorbell (B4).
			Policy: acme.EABPolicy{
				AllowedIdentifiers: append([]string(nil), in.AllowedIdentifiers...),
				MaxOrders:          in.MaxOrders,
				NotAfter:           notAfter,
				Disabled:           in.Disabled,
			},
		})
	}
	return keys, nil
}

func destroyACMEEABKeyCopies(keys []acme.ExternalAccountBindingKey) {
	for _, key := range keys {
		secret.Wipe(key.HMACKey)
	}
}

func (s *Server) buildServedSCEP(cfg config.Protocols, tenantFallback string, issuer *protocolIssuer, raCertDER, raKeyPKCS8 []byte, pool *bulkhead.Pool, keyWrapper sealKeyWrapper) (http.Handler, string, error) {
	tenantID := firstNonEmpty(cfg.SCEP.TenantID, tenantFallback)
	challengeValidator, err := s.buildSCEPChallengeValidator(cfg.SCEPIntuneChallenge, tenantID, keyWrapper)
	if err != nil {
		return nil, "", err
	}
	// GetCACert returns the RSA RA cert FIRST (the CMS recipient a SCEP client
	// envelops its request to — the issuing CA key is ECDSA in the signer and
	// cannot be a CMS recipient, AN-4), followed by the issuing CA cert so the
	// client can also build the chain. The issued leaf is still signed by the
	// signer via the Enroller and verifies against the issuing CA.
	scepSrv := scep.New(scep.Config{
		Enroller:           enrollerAdapter{tenantID: tenantID, issuer: issuer},
		ProfileName:        s.defaultProfile,
		CAChainDER:         [][]byte{raCertDER, s.caCertDER},
		RACertDER:          raCertDER,
		RAKeyPKCS8:         raKeyPKCS8,
		Pool:               pool,
		Log:                s.log,
		ChallengeValidator: challengeValidator,
		FailureDiagnosis: func(requestCtx context.Context, diagnosis enrollmentdiag.Diagnosis) {
			if s.api == nil {
				return
			}
			if err := s.api.RecordEnrollmentDiagnosis(requestCtx, tenantID, diagnosis); err != nil && s.logger != nil {
				s.logger.Warn("enrollment diagnosis persistence failed", slog.String("protocol", string(diagnosis.Protocol)), slog.String("error", err.Error()))
			}
		},
	})
	dispatcher, err := scep.NewDispatcher([]scep.ProfileRoute{{Server: scepSrv}})
	if err != nil {
		return nil, "", fmt.Errorf("server: build served SCEP dispatcher: %w", err)
	}
	return dispatcher, tenantID, nil
}

// routes mounts the HTTP-served protocols (ACME/EST/SCEP/CMP/SSH) on mux, each on the
// API bulkhead pool. The EST/SCEP/CMP handlers carry their bound tenant into the
// serving context so their protocol audit events are tenant-attributed (AN-1/AN-2);
// the actual mint is already tenant-correct via the Enroller. SPIFFE is not mounted
// here (a gRPC UDS service).
func (sp *servedProtocols) routes(mux *http.ServeMux, bulk *bulkhead.Set) {
	wrap := func(h http.Handler) http.Handler {
		return bulkheadHandler(bulk, bulkhead.SubsystemAPI, protocolActivationHandler(sp.activation, h))
	}
	if sp.acme != nil {
		for _, pattern := range protocolHTTPMountPatterns("acme") {
			mux.Handle(pattern, wrap(sp.acme))
		}
	}
	if sp.est != nil {
		h := tenantCtxHandler(sp.est, func(ctx context.Context) context.Context { return est.WithTenant(ctx, sp.estTenant) })
		for _, pattern := range protocolHTTPMountPatterns("est") {
			mux.Handle(pattern, wrap(h))
		}
	}
	if sp.scep != nil {
		h := tenantCtxHandler(sp.scep, func(ctx context.Context) context.Context { return scep.WithTenant(ctx, sp.scepTenant) })
		for _, pattern := range protocolHTTPMountPatterns("scep") {
			mux.Handle(pattern, wrap(h))
		}
	}
	if sp.cmp != nil {
		h := tenantCtxHandler(sp.cmp, func(ctx context.Context) context.Context { return cmp.WithTenant(ctx, sp.cmpTenant) })
		for _, pattern := range protocolHTTPMountPatterns("cmp") {
			mux.Handle(pattern, wrap(h))
		}
	}
	if sp.tsa != nil {
		for _, pattern := range protocolHTTPMountPatterns("tsa") {
			mux.Handle(pattern, wrap(sp.tsa.Handler()))
		}
	}
	if sp.ssh != nil {
		for _, pattern := range protocolHTTPMountPatterns("ssh") {
			mux.Handle(pattern, wrap(sp.ssh))
		}
	}
}

var httpProtocolNames = []string{"acme", "est", "scep", "cmp", "ssh", "tsa"}

// registerProtocolNamespaceFallbacks owns every HTTP protocol-shaped path that no
// enabled protocol handler owns. Without this layer, the final React handler treats
// a machine URL as a client-side browser route and returns index.html with HTTP 200.
func registerProtocolNamespaceFallbacks(mux *http.ServeMux, sp *servedProtocols) {
	for _, protocol := range httpProtocolNames {
		patterns := protocolHTTPNamespacePatterns(protocol)
		handler := protocolNotServedHandler(protocol)
		if sp.hasHTTPProtocol(protocol) {
			patterns = unmatchedProtocolNamespacePatterns(protocol)
			handler = protocolRouteNotFoundHandler(protocol)
		}
		for _, pattern := range patterns {
			mux.Handle(pattern, handler)
		}
	}
}

func (sp *servedProtocols) hasHTTPProtocol(protocol string) bool {
	if sp == nil {
		return false
	}
	switch protocol {
	case "acme":
		return sp.acme != nil
	case "est":
		return sp.est != nil
	case "scep":
		return sp.scep != nil
	case "cmp":
		return sp.cmp != nil
	case "ssh":
		return sp.ssh != nil
	case "tsa":
		return sp.tsa != nil
	default:
		return false
	}
}

// unmatchedProtocolNamespacePatterns are reservation-only child paths not already
// covered by the enabled protocol's mount. Prefix mounts such as /acme/ delegate
// their own unknown children to a protocol mux, which already returns non-HTML 404.
func unmatchedProtocolNamespacePatterns(protocol string) []string {
	mounted := make(map[string]struct{}, len(protocolHTTPMountPatterns(protocol)))
	for _, pattern := range protocolHTTPMountPatterns(protocol) {
		mounted[pattern] = struct{}{}
	}
	var unmatched []string
	for _, pattern := range protocolHTTPNamespacePatterns(protocol) {
		if _, ok := mounted[pattern]; !ok {
			unmatched = append(unmatched, pattern)
		}
	}
	return unmatched
}

func protocolNotServedHandler(protocol string) http.Handler {
	return protocolNamespaceProblemHandler(protocol, "urn:trstctl:problem:protocol-not-served", "Protocol is not served")
}

func protocolRouteNotFoundHandler(protocol string) http.Handler {
	return protocolNamespaceProblemHandler(protocol, "urn:trstctl:problem:protocol-route-not-found", "Protocol route not found")
}

func protocolNamespaceProblemHandler(protocol, problemType, title string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(struct {
			Type     string `json:"type"`
			Title    string `json:"title"`
			Status   int    `json:"status"`
			Protocol string `json:"protocol"`
		}{Type: problemType, Title: title, Status: http.StatusNotFound, Protocol: protocol})
	})
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

func (s *Server) buildSCEPChallengeValidator(cfg config.SCEPIntuneChallenge, tenantID string, keyWrapper sealKeyWrapper) (scep.ChallengeValidator, error) {
	trust := make([][]byte, 0, len(cfg.TrustAnchorsDER)+len(cfg.TrustAnchorFiles))
	for _, der := range cfg.TrustAnchorsDER {
		trust = append(trust, append([]byte(nil), der...))
	}
	for _, path := range cfg.TrustAnchorFiles {
		der, err := loadSCEPIntuneTrustAnchor(path)
		if err != nil {
			return nil, err
		}
		trust = append(trust, der)
	}
	validator := mdmchallenge.NewIntuneChallengeValidator(tenantID, trust,
		mdmchallenge.WithIntuneAudience(cfg.ExpectedAudience),
		mdmchallenge.WithIntuneClockSkewTolerance(time.Duration(cfg.ClockSkewSeconds)*time.Second),
		mdmchallenge.WithIntuneEventLog(s.log),
		mdmchallenge.WithIntuneTrustConfigResolver(s.mdmSCEPIntuneTrustConfigResolver(keyWrapper)),
	)
	return func(ctx context.Context, req scep.ChallengeRequest) error {
		return validator.Validate(ctx, mdmchallenge.IntuneChallengeRequest{
			TenantID:      req.TenantID,
			Challenge:     req.Challenge,
			CSRDER:        req.CSRDER,
			TransactionID: req.TransactionID,
		})
	}, nil
}

func (s *Server) mdmSCEPIntuneTrustConfigResolver(keyWrapper sealKeyWrapper) mdmchallenge.IntuneTrustConfigResolver {
	if s.store == nil || keyWrapper == nil {
		return nil
	}
	return func(ctx context.Context, req mdmchallenge.IntuneChallengeRequest) ([]mdmchallenge.IntuneTrustConfig, error) {
		tenantID := strings.TrimSpace(req.TenantID)
		if tenantID == "" {
			return nil, nil
		}
		policies, err := s.store.ListMDMSCEPPolicies(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		configs := make([]mdmchallenge.IntuneTrustConfig, 0, len(policies))
		for _, policy := range policies {
			if !policy.Enabled || policy.Provider != "intune" || policy.ChallengeMode != "intune-jws" {
				continue
			}
			anchors, err := s.mdmSCEPPolicyTrustAnchors(ctx, tenantID, policy.TrustAnchorRefs, keyWrapper)
			if err != nil {
				return nil, err
			}
			if len(anchors) == 0 {
				continue
			}
			configs = append(configs, mdmchallenge.IntuneTrustConfig{
				TrustAnchorsDER:  anchors,
				ExpectedAudience: policy.ExpectedAudience,
			})
		}
		return configs, nil
	}
}

func (s *Server) mdmSCEPPolicyTrustAnchors(ctx context.Context, tenantID string, raw json.RawMessage, keyWrapper sealKeyWrapper) ([][]byte, error) {
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "{}" {
		return nil, nil
	}
	var refs map[string]string
	if err := json.Unmarshal(raw, &refs); err != nil {
		return nil, fmt.Errorf("server: MDM SCEP trust_anchor_refs are invalid")
	}
	anchors := make([][]byte, 0, len(refs))
	for key, ref := range refs {
		loaded, err := s.loadMDMSCEPTrustAnchorRef(ctx, tenantID, key, ref, keyWrapper)
		if err != nil {
			return nil, err
		}
		anchors = append(anchors, loaded...)
	}
	return anchors, nil
}

func (s *Server) loadMDMSCEPTrustAnchorRef(ctx context.Context, tenantID, key, ref string, keyWrapper sealKeyWrapper) ([][]byte, error) {
	if keyWrapper == nil {
		return nil, fmt.Errorf("server: MDM SCEP trust-anchor references require a credential KEK")
	}
	name, ok := strings.CutPrefix(strings.TrimSpace(ref), "secret://")
	if !ok {
		return nil, fmt.Errorf("server: MDM SCEP trust anchor %s must use a secret:// reference", key)
	}
	name = strings.TrimSpace(strings.TrimPrefix(name, "/"))
	if name == "" {
		return nil, fmt.Errorf("server: MDM SCEP trust anchor %s has an empty secret reference", key)
	}
	rec, err := s.store.GetSecret(ctx, tenantID, name)
	if err != nil {
		return nil, fmt.Errorf("server: MDM SCEP trust anchor %s is not readable", key)
	}
	plain, err := openTenantValue(ctx, s.tenantCrypto, keyWrapper, tenantID, rec.Sealed, secretStoreAADForMDMSCEP(tenantID, name))
	if err != nil {
		return nil, fmt.Errorf("server: MDM SCEP trust anchor %s is not openable", key)
	}
	defer secret.Wipe(plain)
	anchors, err := decodeMDMSCEPTrustAnchorSecret(plain)
	if err != nil {
		return nil, fmt.Errorf("server: MDM SCEP trust anchor %s is invalid: %w", key, err)
	}
	return anchors, nil
}

func secretStoreAADForMDMSCEP(tenantID, name string) []byte {
	return []byte(tenantID + "/secret-store/" + name)
}

func decodeMDMSCEPTrustAnchorSecret(raw []byte) ([][]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty certificate")
	}
	var anchors [][]byte
	rest := trimmed
	for len(rest) > 0 {
		blk, after := pem.Decode(rest)
		if blk == nil {
			if len(anchors) > 0 {
				return nil, errors.New("trailing non-PEM data")
			}
			break
		}
		if blk.Type != "CERTIFICATE" || len(blk.Bytes) == 0 {
			return nil, errors.New("PEM block is not a certificate")
		}
		anchors = append(anchors, append([]byte(nil), blk.Bytes...))
		rest = bytes.TrimSpace(after)
	}
	if len(anchors) > 0 {
		return anchors, nil
	}
	return [][]byte{append([]byte(nil), trimmed...)}, nil
}

func loadSCEPIntuneTrustAnchor(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured local file path from deployment config (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("server: read SCEP Intune trust anchor %q: %w", path, err)
	}
	if blk, _ := pem.Decode(raw); blk != nil {
		if blk.Type != "CERTIFICATE" || len(blk.Bytes) == 0 {
			return nil, fmt.Errorf("server: SCEP Intune trust anchor %q is not a PEM certificate", path)
		}
		return append([]byte(nil), blk.Bytes...), nil
	}
	return append([]byte(nil), raw...), nil
}

func acmeQuotaConfig(q config.ACMEQuota) acme.QuotaConfig {
	return acme.QuotaConfig{
		MaxNonces:                  q.MaxNonces,
		MaxAccounts:                q.MaxAccounts,
		MaxPendingOrders:           q.MaxPendingOrders,
		MaxPendingAuthorizations:   q.MaxPendingAuthorizations,
		MaxPendingChallenges:       q.MaxPendingChallenges,
		MaxPendingOrdersPerAccount: q.MaxPendingOrdersPerAccount,
		MaxNewOrdersPerAccount:     q.MaxNewOrdersPerAccount,
		MaxNewNoncesPerSource:      q.MaxNewNoncesPerSource,
		MaxNewAccountsPerSource:    q.MaxNewAccountsPerSource,
		MaxNewOrdersPerSource:      q.MaxNewOrdersPerSource,
		SourceWindow:               time.Duration(q.SourceWindowSeconds) * time.Second,
		NonceTTL:                   time.Duration(q.NonceTTLSeconds) * time.Second,
		StateTTL:                   time.Duration(q.StateTTLSeconds) * time.Second,
	}
}

func (s *Server) buildTSA(ctx context.Context, tenantID, certFile string) (*tsa.Authority, error) {
	if tenantID == "" {
		return nil, errors.New("tenant id required")
	}
	if s.signer == nil || s.signer.Client() == nil {
		return nil, errors.New("signer is required")
	}
	c := s.signer.Client()
	tsaSigner, err := c.SignerForHandleWithPurpose(ctx, tsaSignerHandle, signing.PurposeGeneric)
	replacedKey := false
	if err != nil {
		generated, genErr := c.GenerateConstrainedKeyHandle(ctx, crypto.RSA2048, tsaSignerHandle,
			[]signing.KeyPurpose{signing.PurposeGeneric}, signing.PurposeGeneric)
		if genErr != nil {
			if status.Code(genErr) == codes.AlreadyExists {
				generated, genErr = c.SignerForHandleWithPurpose(ctx, tsaSignerHandle, signing.PurposeGeneric)
			}
			if genErr != nil {
				return nil, fmt.Errorf("provision timestamping key in signer: %w", genErr)
			}
		} else {
			replacedKey = true
		}
		tsaSigner = generated
	}
	certDER, err := s.tsaCertificate(ctx, tsaSigner, certFile, replacedKey)
	if err != nil {
		return nil, err
	}
	return tsa.New(tsa.Config{
		TenantID:   tenantID,
		TSACertDER: certDER,
		TSASigner:  tsaSigner,
		Audit:      audit.NewAuditor(s.log),
	})
}

func (s *Server) tsaCertificate(_ context.Context, tsaSigner crypto.DigestSigner, certFile string, allowReplace bool) ([]byte, error) {
	if certFile != "" {
		certDER, found, err := readCertPEM(certFile)
		if err != nil {
			return nil, fmt.Errorf("load TSA certificate: %w", err)
		}
		if found {
			pub, err := crypto.PublicKeyDERFromCert(certDER)
			if err != nil {
				return nil, fmt.Errorf("parse TSA certificate public key: %w", err)
			}
			if bytes.Equal(pub, tsaSigner.Public().DER) {
				return certDER, nil
			}
			if !allowReplace {
				return nil, errors.New("persisted TSA certificate does not match signer-held timestamping key")
			}
		}
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:    "trstctl TSA",
		RequestedEKUs: []string{"timeStamping"},
	}, tsaSigner)
	if err != nil {
		return nil, fmt.Errorf("create TSA CSR: %w", err)
	}
	certDER, err := crypto.SignTimestampingCertFromCSR(s.caCertDER, s.caSigner, csr, protocolRATTL)
	if err != nil {
		return nil, fmt.Errorf("sign TSA certificate: %w", err)
	}
	if certFile != "" {
		if err := writeCertPEM(certFile, certDER); err != nil {
			return nil, fmt.Errorf("persist TSA certificate: %w", err)
		}
	}
	return certDER, nil
}

func readCertPEM(path string) ([]byte, bool, error) {
	pemBytes, err := os.ReadFile(path) // #nosec G304 -- operator-configured local file path from deployment config (CWE-22)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Bytes) == 0 {
		return nil, false, fmt.Errorf("%s is not a PEM certificate", path)
	}
	return append([]byte(nil), blk.Bytes...), true, nil
}

const (
	protocolRAAAD   = "trstctl-protocol-ra-transport-v1"
	protocolRAMagic = "TRRA1"
)

// protocolTransportKey loads or creates the RSA transport key SCEP/CMP use for CMS
// transport. It is NOT the CA key (AN-4: the CA key stays in the signer). The key is
// sealed at rest under keyFile and memoized so SCEP and CMP in this process share one.
func (s *Server) protocolTransportKey(keyFile string, wrapper sealKeyWrapper) (certDER, keyPKCS8 []byte, err error) {
	if s.protoRACertDER != nil && s.protoRAKeyPKCS8 != nil {
		return s.protoRACertDER, s.protoRAKeyPKCS8, nil
	}
	if keyFile == "" {
		return nil, nil, errors.New("protocol RA key file is required")
	}
	if wrapper == nil {
		return nil, nil, errors.New("protocol RA key requires a KEK")
	}
	if certDER, keyPKCS8, err := loadProtocolTransportKey(keyFile, wrapper); err == nil {
		s.protoRACertDER = certDER
		s.protoRAKeyPKCS8 = keyPKCS8
		return certDER, keyPKCS8, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		return nil, nil, err
	}
	defer signer.Destroy()
	der, err := crypto.SelfSignedCACert(signer, "trstctl Protocol RA", protocolRATTL)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := signer.PKCS8()
	if err != nil {
		return nil, nil, err
	}
	if err := saveProtocolTransportKey(keyFile, wrapper, der, pkcs8); err != nil {
		secret.Wipe(pkcs8)
		if errors.Is(err, os.ErrExist) {
			return s.protocolTransportKey(keyFile, wrapper)
		}
		return nil, nil, err
	}
	s.protoRACertDER = der
	s.protoRAKeyPKCS8 = pkcs8
	return der, pkcs8, nil
}

func loadProtocolTransportKey(path string, wrapper sealKeyWrapper) (certDER, keyPKCS8 []byte, err error) {
	sealed, err := os.ReadFile(path) // #nosec G304 -- operator-configured local file path from deployment config (CWE-22)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := seal.Open(wrapper, sealed, []byte(protocolRAAAD))
	if err != nil {
		return nil, nil, fmt.Errorf("open sealed protocol RA identity: %w", err)
	}
	defer secret.Wipe(plaintext)
	return decodeProtocolTransportKey(plaintext)
}

func saveProtocolTransportKey(path string, wrapper sealKeyWrapper, certDER, keyPKCS8 []byte) error {
	plaintext := encodeProtocolTransportKey(certDER, keyPKCS8)
	defer secret.Wipe(plaintext)
	sealed, err := seal.Seal(wrapper, plaintext, []byte(protocolRAAAD))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".protocol-ra-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(sealed); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, path); err != nil {
		return err
	}
	return nil
}

func encodeProtocolTransportKey(certDER, keyPKCS8 []byte) []byte {
	out := make([]byte, 0, len(protocolRAMagic)+8+len(certDER)+len(keyPKCS8))
	out = append(out, protocolRAMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(certDER))) // #nosec G115 -- DER lengths of certificates/keys are orders of magnitude under the uint32 bound (CWE-190)
	out = append(out, certDER...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(keyPKCS8))) // #nosec G115 -- DER lengths of certificates/keys are orders of magnitude under the uint32 bound (CWE-190)
	out = append(out, keyPKCS8...)
	return out
}

func decodeProtocolTransportKey(b []byte) (certDER, keyPKCS8 []byte, err error) {
	if len(b) < len(protocolRAMagic)+8 || string(b[:len(protocolRAMagic)]) != protocolRAMagic {
		return nil, nil, errors.New("protocol RA identity is malformed")
	}
	off := len(protocolRAMagic)
	certLen := int(binary.BigEndian.Uint32(b[off:]))
	off += 4
	if certLen <= 0 || len(b) < off+certLen+4 {
		return nil, nil, errors.New("protocol RA identity has invalid certificate length")
	}
	certDER = append([]byte(nil), b[off:off+certLen]...)
	off += certLen
	keyLen := int(binary.BigEndian.Uint32(b[off:]))
	off += 4
	if keyLen <= 0 || len(b) != off+keyLen {
		secret.Wipe(certDER)
		return nil, nil, errors.New("protocol RA identity has invalid key length")
	}
	keyPKCS8 = append([]byte(nil), b[off:off+keyLen]...)
	return certDER, keyPKCS8, nil
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
	// The mutating SSH routes require certs:issue, the authority the protocol
	// authz manifest already names for this surface. It is deliberately the
	// ISSUE authority rather than EST's REQUEST authority: an SSH user
	// certificate names its own principals, so minting one is an issuance
	// decision, not a request for someone else to approve.
	protocol, err := newSSHProtocol(ca, tenantID, servedEnrollAuth{
		store:    s.store,
		tenantID: tenantID,
		perm:     authz.CertsIssue,
	})
	if err != nil {
		return nil, err
	}
	if err := protocol.restoreRevocations(ctx, s.log); err != nil {
		return nil, err
	}
	return protocol, nil
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
	var workloadOpts []spiffe.WorkloadAPIOption
	if s.licensedSPIFFESVIDFactory != nil {
		additional, err := s.licensedSPIFFESVIDFactory(s.caCertDER, s.caSigner)
		if err != nil {
			return nil, fmt.Errorf("server: build licensed SPIFFE X509-SVID issuer: %w", err)
		}
		if additional == nil {
			return nil, errors.New("server: licensed SPIFFE X509-SVID factory returned nil (fail closed)")
		}
		workloadOpts = append(workloadOpts, spiffe.WithAdditionalX509SVIDIssuer(additional))
	}
	return &spiffeProtocol{
		server:                 spiffe.NewWorkloadAPIServer(wl, []string{"unix"}, workloadOpts...),
		socket:                 socket,
		tenantID:               tenant,
		registrationEntryCount: len(entries),
		bulkheadReady:          pool != nil,
		// B3: the agent channel issues through the SAME server, so a workload
		// gets the same identity whichever socket it reached — the control
		// plane's during the deprecation window, or its own host's after.
		wl:          wl,
		trustDomain: td,
	}, nil
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

// acmeEABPosture reads the mounted ACME server's external account binding state
// for a tenant (B4). It is a read-time seam rather than a value captured at
// construction because API construction precedes protocol construction, and
// because the counters it exposes are live.
//
// The tenant check is the AN-1 boundary for this surface: one ACME mount binds
// one tenant, so a caller authenticated for a different tenant sees an unserved
// posture rather than another tenant's credentials.
func (s *Server) acmeEABPosture(_ context.Context, tenantID string) (api.ACMEEABPosture, error) {
	out := api.ACMEEABPosture{GeneratedAt: time.Now().UTC(), Items: []api.ACMEEABCredential{}}
	sp := s.protocols
	if sp == nil || sp.acme == nil || sp.acmeTenant == "" || sp.acmeTenant != tenantID {
		return out, nil
	}
	out.Served = true
	out.Required = sp.acme.ExternalAccountRequired()
	for _, cred := range sp.acme.EABCredentials() {
		out.Items = append(out.Items, toAPIACMEEABCredential(cred))
	}
	return out, nil
}

// setACMEEABDisabled applies an operator's runtime enable/disable decision to one
// credential on this tenant's ACME mount.
func (s *Server) setACMEEABDisabled(_ context.Context, tenantID, keyID string, disabled bool) (api.ACMEEABCredential, bool, error) {
	sp := s.protocols
	if sp == nil || sp.acme == nil || sp.acmeTenant == "" || sp.acmeTenant != tenantID {
		return api.ACMEEABCredential{}, false, nil
	}
	status, ok := sp.acme.SetEABDisabled(keyID, disabled)
	if !ok {
		return api.ACMEEABCredential{}, false, nil
	}
	return toAPIACMEEABCredential(status), true, nil
}

func toAPIACMEEABCredential(in acme.EABCredentialStatus) api.ACMEEABCredential {
	return api.ACMEEABCredential{
		KeyID: in.KeyID, State: in.State, Reason: in.Reason,
		AllowedIdentifiers: append([]string(nil), in.AllowedIdentifiers...),
		MaxOrders:          in.MaxOrders, NotAfter: in.NotAfter,
		AccountsBound: in.AccountsBound, OrdersCreated: in.OrdersCreated, OrdersDenied: in.OrdersDenied,
		DisabledInConfig: in.DisabledInConfig, DisabledByOperator: in.DisabledByOperator,
		LastUsedAt: in.LastUsedAt,
	}
}

// auditTimestamper resolves the TSA at CALL time for audit-chain anchoring
// (epic J1).
//
// Lazy on purpose. The API surface is constructed before the protocol mounts
// are, so a value passed at construction would always be nil — and a nil
// timestamper does not fail loudly, it produces exports that quietly say
// "unanchored" forever. That is the shape of defect this workstream exists to
// remove: a capability wired in the wrong order, shipping as a permanent
// downgrade nobody notices.
type auditTimestamper struct{ srv *Server }

// Timestamp countersigns an audit chain head, or reports that it cannot.
func (a auditTimestamper) Timestamp(ctx context.Context, hashedMessage []byte) (tsa.Token, error) {
	if a.srv == nil || a.srv.protocols == nil || a.srv.protocols.tsa == nil {
		return tsa.Token{}, fmt.Errorf(
			"server: the timestamp authority is not served, so audit exports cannot be anchored; " +
				"enable protocols.tsa to countersign audit chain heads")
	}
	return a.srv.protocols.tsa.Timestamp(ctx, hashedMessage)
}

// loadCMPClientTrustAnchors reads the PEM bundle whose certificates a CMP
// client's PKIMessage protection identity must chain to. An unset path yields no
// anchors, which leaves the served CMP mount refusing to enrol (fail closed)
// rather than accepting a self-signed protection identity.
func loadCMPClientTrustAnchors(path string) ([][]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(path) // #nosec G304 -- operator-configured trust bundle path (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("server: read CMP client trust anchors: %w", err)
	}
	var anchors [][]byte
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			anchors = append(anchors, append([]byte(nil), block.Bytes...))
		}
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("server: CMP client trust anchor file %q contains no certificates", path)
	}
	return anchors, nil
}
