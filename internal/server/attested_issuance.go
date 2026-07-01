package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/attest/awsiid"
	"trstctl.com/trstctl/internal/attest/azureimds"
	"trstctl.com/trstctl/internal/attest/gcpmeta"
	"trstctl.com/trstctl/internal/attest/githuboidc"
	"trstctl.com/trstctl/internal/attest/k8ssat"
	"trstctl.com/trstctl/internal/attest/tpmquote"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

const (
	defaultAttestedSVIDTTL = 10 * time.Minute
	maxAttestedSVIDTTL     = time.Hour
)

var requiredAttestedIssuanceMethods = []string{
	"aws_iid",
	"azure_imds",
	"gcp_iit",
	"github_oidc",
	"k8s_sat",
	"tpm",
}

// AttestedIssuanceConfig turns on the served F30 attestation-gated SVID mint.
// Process-supplied attestors remain supported for operator-managed deployments,
// but tenants can also self-serve public trust sources through the workload
// attester-trust API. Each request builds a tenant-scoped verifier from the
// enabled trust source(s) for the requested method and fails closed when none are
// available.
type AttestedIssuanceConfig struct {
	Enabled     bool
	TrustDomain string
	DefaultTTL  time.Duration
	MaxTTL      time.Duration
	Attestors   []attest.Attestor
}

type attestedIssuerService struct {
	trustDomain string
	defaultTTL  time.Duration
	maxTTL      time.Duration
	attestors   []attest.Attestor
	methods     map[string]struct{}
	audit       auditsink.Auditor
	store       *store.Store
	log         *events.Log
	orch        *orchestrator.Orchestrator
	caSigner    crypto.DigestSigner
	caCertDER   []byte
	caID        string
}

type attestedIssuerDeps struct {
	Config    AttestedIssuanceConfig
	Store     *store.Store
	Log       *events.Log
	Orch      *orchestrator.Orchestrator
	CASigner  crypto.DigestSigner
	CACertDER []byte
	CAID      string
	Audit     auditsink.Auditor
}

func newAttestedIssuerService(d attestedIssuerDeps) (*attestedIssuerService, error) {
	cfg := d.Config
	if !cfg.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(cfg.TrustDomain) == "" {
		return nil, errors.New("server: attested issuance enabled but trust domain is empty")
	}
	if d.Store == nil || d.Log == nil || d.Orch == nil {
		return nil, errors.New("server: attested issuance enabled without the event-sourced mutation spine")
	}
	if d.CASigner == nil || len(d.CACertDER) == 0 {
		return nil, errors.New("server: attested issuance enabled but no signer-backed issuing CA is available")
	}
	methods := map[string]struct{}{}
	for _, a := range cfg.Attestors {
		if a == nil || a.Method() == "" {
			return nil, errors.New("server: attested issuance configured with an empty attestor")
		}
		if _, dup := methods[a.Method()]; dup {
			return nil, fmt.Errorf("server: attested issuance configured duplicate attestor %q", a.Method())
		}
		methods[a.Method()] = struct{}{}
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = defaultAttestedSVIDTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = maxAttestedSVIDTTL
	}
	if cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}
	if d.Audit == nil {
		d.Audit = auditsink.Nop{}
	}
	return &attestedIssuerService{
		trustDomain: strings.TrimSpace(cfg.TrustDomain),
		defaultTTL:  cfg.DefaultTTL,
		maxTTL:      cfg.MaxTTL,
		attestors:   append([]attest.Attestor(nil), cfg.Attestors...),
		methods:     methods,
		audit:       d.Audit,
		store:       d.Store,
		log:         d.Log,
		orch:        d.Orch,
		caSigner:    d.CASigner,
		caCertDER:   append([]byte(nil), d.CACertDER...),
		caID:        d.CAID,
	}, nil
}

func (s *Server) IssueAttestedSVID(ctx context.Context, tenantID, idempotencyKey string, req api.AttestedSVIDRequest) (api.AttestedSVID, error) {
	if s.attestedIssuance == nil {
		return api.AttestedSVID{}, api.ErrAttestedIssuanceUnavailable
	}
	return s.attestedIssuance.IssueAttestedSVID(ctx, tenantID, idempotencyKey, req)
}

func (s *attestedIssuerService) IssueAttestedSVID(ctx context.Context, tenantID, idempotencyKey string, req api.AttestedSVIDRequest) (api.AttestedSVID, error) {
	if tenantID == "" {
		return api.AttestedSVID{}, fmt.Errorf("%w: tenant is required", api.ErrAttestedIssuanceInvalid)
	}
	if idempotencyKey == "" {
		return api.AttestedSVID{}, fmt.Errorf("%w: idempotency key is required", api.ErrAttestedIssuanceInvalid)
	}
	if len(req.PublicKeyDER) == 0 {
		return api.AttestedSVID{}, fmt.Errorf("%w: public key is required", api.ErrAttestedIssuanceInvalid)
	}
	method := strings.TrimSpace(req.Method)
	if !supportedAttestedIssuanceMethod(method) {
		return api.AttestedSVID{}, fmt.Errorf("%w: unknown attestation method %q", api.ErrAttestedIssuanceInvalid, method)
	}
	attestors, err := s.attestorsForMethod(ctx, tenantID, method)
	if err != nil {
		return api.AttestedSVID{}, fmt.Errorf("%w: %v", api.ErrAttestedIssuanceInvalid, err)
	}
	if len(attestors) == 0 {
		return api.AttestedSVID{}, fmt.Errorf("%w: no enabled trust source for attestation method %q", api.ErrAttestedIssuanceInvalid, method)
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: attestors,
		Audit:     s.audit,
	})
	if err != nil {
		return api.AttestedSVID{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrAttestedIssuanceInvalid, err)
	}
	att, err := verifier.Verify(ctx, method, req.Payload)
	if err != nil {
		return api.AttestedSVID{}, fmt.Errorf("%w: %v", api.ErrAttestedIssuanceRejected, err)
	}

	ttl := s.ttl(req.TTLSeconds)
	idemKey := "attested-issue:" + idempotencyKey
	recovered, err := recoverCertificatesByIssuanceKey(ctx, s.store, s.log, tenantID, idemKey)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	if len(recovered) > 0 {
		if len(recovered) != 1 {
			return api.AttestedSVID{}, fmt.Errorf("server: attested issuance key %q recovered %d certificates, want 1", idemKey, len(recovered))
		}
		return s.finish(ctx, tenantID, verifier, att, recovered[0].CertificateDER, ttl, false)
	}

	spiffeID, err := attestedSPIFFEID(s.trustDomain, att.Subject)
	if err != nil {
		return api.AttestedSVID{}, fmt.Errorf("%w: %v", api.ErrAttestedIssuanceInvalid, err)
	}
	certDER, err := crypto.SignSVID(s.caCertDER, s.caSigner, req.PublicKeyDER, spiffeID, ttl)
	if err != nil {
		return api.AttestedSVID{}, fmt.Errorf("server: sign attested SVID: %w", err)
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	nb, na := info.NotBefore, info.NotAfter
	if _, err := s.orch.RecordCertificate(ctx, tenantID, store.Certificate{
		CAID: s.caID, Subject: info.Subject, SANs: sansOf(info), Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "attested:" + att.Method, CertificateDER: append([]byte(nil), certDER...),
		IssuanceIdempotencyKey: idemKey,
	}); err != nil {
		return api.AttestedSVID{}, err
	}
	return s.finish(ctx, tenantID, verifier, att, certDER, ttl, true)
}

func (s *attestedIssuerService) ttl(seconds int64) time.Duration {
	if seconds <= 0 {
		return s.defaultTTL
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl <= 0 {
		return s.defaultTTL
	}
	if s.maxTTL > 0 && ttl > s.maxTTL {
		return s.maxTTL
	}
	return ttl
}

func (s *attestedIssuerService) attestorsForMethod(ctx context.Context, tenantID, method string) ([]attest.Attestor, error) {
	var candidates []attest.Attestor
	for _, a := range s.attestors {
		if a != nil && a.Method() == method {
			candidates = append(candidates, a)
		}
	}
	if s.store != nil {
		sources, err := s.store.ListEnabledWorkloadAttesterTrustSources(ctx, tenantID, method)
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			a, err := attestorFromTrustSource(source)
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, a)
		}
	}
	switch len(candidates) {
	case 0:
		return nil, nil
	case 1:
		return candidates, nil
	default:
		return []attest.Attestor{multiAttestor{method: method, attestors: candidates}}, nil
	}
}

type multiAttestor struct {
	method    string
	attestors []attest.Attestor
}

func (m multiAttestor) Method() string { return m.method }

func (m multiAttestor) Attest(ctx context.Context, payload []byte) (attest.Attestation, error) {
	var failures []string
	for _, a := range m.attestors {
		att, err := a.Attest(ctx, payload)
		if err == nil {
			return att, nil
		}
		failures = append(failures, err.Error())
	}
	return attest.Attestation{}, fmt.Errorf("%s: no trust source accepted proof: %s", m.method, strings.Join(failures, "; "))
}

func attestorFromTrustSource(source store.WorkloadAttesterTrustSource) (attest.Attestor, error) {
	switch source.Method {
	case "k8s_sat":
		jwks, err := crypto.ParseJWKS(source.JWKS)
		if err != nil {
			return nil, fmt.Errorf("trust source %s jwks: %w", source.ID, err)
		}
		return &k8ssat.Attestor{JWKS: jwks, Issuer: source.Issuer, Audience: source.Audience}, nil
	case "gcp_iit":
		jwks, err := crypto.ParseJWKS(source.JWKS)
		if err != nil {
			return nil, fmt.Errorf("trust source %s jwks: %w", source.ID, err)
		}
		return &gcpmeta.Attestor{JWKS: jwks, Issuer: source.Issuer, Audience: source.Audience}, nil
	case "github_oidc":
		jwks, err := crypto.ParseJWKS(source.JWKS)
		if err != nil {
			return nil, fmt.Errorf("trust source %s jwks: %w", source.ID, err)
		}
		return &githuboidc.Attestor{JWKS: jwks, Issuer: source.Issuer, Audience: source.Audience}, nil
	case "aws_iid":
		roots, err := trustSourceRootCertDER(source)
		if err != nil {
			return nil, err
		}
		return &awsiid.Attestor{Roots: roots}, nil
	case "azure_imds":
		roots, err := trustSourceRootCertDER(source)
		if err != nil {
			return nil, err
		}
		return &azureimds.Attestor{Roots: roots}, nil
	case "tpm":
		roots, err := trustSourceRootCertDER(source)
		if err != nil {
			return nil, err
		}
		nonce, err := trustSourceNonce(source)
		if err != nil {
			return nil, err
		}
		return &tpmquote.Attestor{ManufacturerRoots: roots, ExpectedNonce: nonce}, nil
	default:
		return nil, fmt.Errorf("trust source %s has unsupported method %q", source.ID, source.Method)
	}
}

func trustSourceRootCertDER(source store.WorkloadAttesterTrustSource) ([][]byte, error) {
	roots := make([][]byte, 0, len(source.RootCertsPEM))
	for _, pemText := range source.RootCertsPEM {
		block, rest := pem.Decode([]byte(pemText))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 || strings.TrimSpace(string(rest)) != "" {
			return nil, fmt.Errorf("trust source %s root_certs_pem must contain one CERTIFICATE PEM block per item", source.ID)
		}
		roots = append(roots, append([]byte(nil), block.Bytes...))
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("trust source %s has no root certificates", source.ID)
	}
	return roots, nil
}

func trustSourceNonce(source store.WorkloadAttesterTrustSource) ([]byte, error) {
	if strings.TrimSpace(source.ExpectedNonceBase64) == "" {
		return nil, nil
	}
	nonce, err := base64.StdEncoding.DecodeString(source.ExpectedNonceBase64)
	if err != nil {
		return nil, fmt.Errorf("trust source %s expected_nonce_base64: %w", source.ID, err)
	}
	return nonce, nil
}

func supportedAttestedIssuanceMethod(method string) bool {
	for _, supported := range requiredAttestedIssuanceMethods {
		if method == supported {
			return true
		}
	}
	return false
}

func (s *attestedIssuerService) finish(ctx context.Context, tenantID string, verifier *attest.Verifier, att attest.Attestation, certDER []byte, ttl time.Duration, minted bool) (api.AttestedSVID, error) {
	if len(certDER) == 0 {
		return api.AttestedSVID{}, errors.New("server: attested issuance recovered certificate without DER")
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	credentialID := "cred:" + crypto.SHA256Hex(certDER)
	if err := verifier.Bind(ctx, att, credentialID); err != nil {
		return api.AttestedSVID{}, fmt.Errorf("server: bind attestation: %w", err)
	}
	s.emitIssued(ctx, tenantID, att, ttl, info.NotAfter, minted)
	return api.AttestedSVID{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		CredentialID:   credentialID,
		Subject:        att.Subject,
		NotAfter:       info.NotAfter,
		Attestation:    att,
	}, nil
}

func (s *attestedIssuerService) emitIssued(ctx context.Context, tenantID string, att attest.Attestation, ttl time.Duration, notAfter time.Time, minted bool) {
	payload, err := json.Marshal(struct {
		Subject    string `json:"subject"`
		Method     string `json:"method"`
		TTLSeconds int    `json:"ttl_seconds"`
		NotAfter   string `json:"not_after"`
		Recovered  bool   `json:"recovered"`
	}{
		Subject:    att.Subject,
		Method:     att.Method,
		TTLSeconds: int(ttl.Seconds()),
		NotAfter:   notAfter.UTC().Format(time.RFC3339),
		Recovered:  !minted,
	})
	if err != nil {
		return
	}
	_ = auditsink.Emit(ctx, s.audit, nil, "ephemeral.issued", tenantID, payload)
}

func attestedSPIFFEID(trustDomain, subject string) (string, error) {
	trustDomain = strings.TrimSpace(trustDomain)
	subject = strings.Trim(subject, "/")
	if trustDomain == "" {
		return "", errors.New("trust domain is required")
	}
	if subject == "" {
		return "", errors.New("attestation subject is required")
	}
	parts := strings.Split(subject, "/")
	for i, part := range parts {
		if part == "" {
			return "", fmt.Errorf("attestation subject %q contains an empty path segment", subject)
		}
		parts[i] = url.PathEscape(part)
	}
	id := "spiffe://" + trustDomain + "/" + strings.Join(parts, "/")
	if _, err := crypto.ParseSPIFFEID(id); err != nil {
		return "", err
	}
	return id, nil
}

func attestedIssuanceAuditor(log *events.Log) auditsink.Auditor {
	if log == nil {
		return auditsink.Nop{}
	}
	return audit.NewAuditor(log)
}
