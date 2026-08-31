// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
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
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
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
	identity, err := s.attestedIssuance.IssueAttestedSVID(ctx, tenantID, idempotencyKey, req)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	if err := s.ensureIssuedCredentialCRL(ctx, tenantID); err != nil {
		return api.AttestedSVID{}, err
	}
	return identity, nil
}

func (s *Server) PreviewAttestedSVID(ctx context.Context, tenantID, requester string, req api.AttestedSVIDRequest) (api.AttestedSVIDPreview, error) {
	if s.attestedIssuance == nil {
		return api.AttestedSVIDPreview{}, api.ErrAttestedIssuanceUnavailable
	}
	return s.attestedIssuance.PreviewAttestedSVID(ctx, tenantID, requester, req)
}

// PreviewAttestedSVID reads configured trust and hashes the exact input. It does
// not call a verifier, signer, orchestrator, event log, or external worker.
func (s *attestedIssuerService) PreviewAttestedSVID(ctx context.Context, tenantID, requester string, req api.AttestedSVIDRequest) (api.AttestedSVIDPreview, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(requester) == "" {
		return api.AttestedSVIDPreview{}, fmt.Errorf("%w: tenant and requester are required", api.ErrAttestedIssuanceInvalid)
	}
	methods, err := s.availableMethods(ctx, tenantID)
	if err != nil {
		return api.AttestedSVIDPreview{}, fmt.Errorf("%w: resolve attestation trust: %v", api.ErrAttestedIssuanceInvalid, err)
	}
	method := strings.TrimSpace(req.Method)
	blockers := []string{}
	configured := false
	for _, available := range methods {
		configured = configured || available == method
	}
	if !supportedAttestedIssuanceMethod(method) || !configured {
		blockers = append(blockers, fmt.Sprintf("Attestation method %q is not configured for this tenant. Enable a matching trust source before issuing.", method))
	}
	if len(req.Payload) == 0 {
		blockers = append(blockers, "Provide the workload's attestation proof before issuing.")
	}
	if err := crypto.ValidatePublicKeyDER(req.PublicKeyDER); err != nil {
		blockers = append(blockers, "Provide a valid workload public key. Keep the matching private key on the workload.")
	}
	return api.AttestedSVIDPreview{
		Capability: "workload_attested_issuance", Ready: len(blockers) == 0, EffectFree: true,
		Method: method, Requester: strings.TrimSpace(requester), TrustDomain: s.trustDomain, SupportedMethods: methods,
		RequestedTTLSeconds: req.TTLSeconds, EffectiveTTLSeconds: int64(s.ttl(req.TTLSeconds) / time.Second),
		DefaultTTLSeconds: int64(s.defaultTTL / time.Second), MaxTTLSeconds: int64(s.maxTTL / time.Second),
		TTLDefaulted: req.TTLSeconds <= 0, TTLClamped: req.TTLSeconds > int64(s.maxTTL/time.Second),
		RequiredPermission: "certs:issue", AttestationVerification: "execution_only",
		PayloadSHA256: crypto.SHA256Hex(req.Payload), PublicKeySHA256: crypto.SHA256Hex(req.PublicKeyDER),
		PreviewWrites: []string{}, PreviewExternalEffects: []string{}, PreviewSignerCalls: []string{},
		ExecutionWrites: []string{
			"Record the proof verification result, then append a certificate-recorded event and project its inventory row after signing.",
			"Bind the verified workload to the credential, append issuance audit evidence, and record the idempotent result.",
			"Publish the issuing CA's initial certificate revocation list, or refresh it when due, before reporting successful issuance.",
		},
		ExecutionExternalEffects: []string{},
		ExecutionSignerCalls: []string{
			"Ask the isolated signer to sign one X.509-SVID for the verified workload subject and effective lifetime.",
			"Sign the public certificate revocation list when it is missing or due for refresh; this does not sign another workload certificate.",
		},
		Steps: []string{
			"Review the exact method, request digests, and effective lifetime. This preview does not verify the proof or reserve a subject.",
			"Issue explicitly. The server rechecks your permission and enabled tenant trust, verifies the proof, and derives the SPIFFE identity from its verified subject.",
			"Read the issued credential and audit evidence. Your workload keeps the matching private key; trstctl returns only the public certificate.",
		},
		Blockers: blockers,
		RecoverySteps: []string{
			"If a response is lost, retry the exact request with the same Idempotency-Key to recover the original result instead of minting twice.",
			"If proof verification fails, correct the trust configuration or obtain fresh proof, then review a new request. Never disable verification to continue.",
			"If the signer is unavailable, restore the isolated signer and retry the unchanged request. An expired proof requires a fresh preview.",
			"If initial revocation-list publication fails after the certificate was recorded, retry the same command. The server recovers that certificate and completes publication instead of issuing another leaf.",
		},
		DataHandling: []string{
			"The preview returns only SHA-256 digests and operational metadata, never the raw proof or public-key body. Decoded proof buffers are wiped after the response.",
			"Proof verification happens only during issuance so preview cannot consume one-time evidence or create verification audit events.",
			"No private key is uploaded, generated, stored, or returned by this workflow.",
		},
	}, nil
}

func (s *attestedIssuerService) availableMethods(ctx context.Context, tenantID string) ([]string, error) {
	return availableWorkloadAttestationMethods(ctx, s.store, s.methods, tenantID)
}

func availableWorkloadAttestationMethods(ctx context.Context, st *store.Store, processMethods map[string]struct{}, tenantID string) ([]string, error) {
	methods := make(map[string]struct{}, len(processMethods))
	for method := range processMethods {
		methods[method] = struct{}{}
	}
	sources, err := st.ListWorkloadAttesterTrustSources(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		if !source.Enabled || source.RevokedAt != nil {
			continue
		}
		if _, err := attestorFromTrustSource(source); err != nil {
			return nil, err
		}
		methods[source.Method] = struct{}{}
	}
	out := make([]string, 0, len(methods))
	for method := range methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out, nil
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
	// The attested subject is folded into the recovery key, not just the caller's
	// Idempotency-Key. Today the only caller is the API handler, which runs this
	// behind mutateDurableBound — that rejects an empty key and binds it to
	// (principal, method, payload, public key, TTL), so a mismatched replay never
	// reaches here. This lookup is the second line for the case where the durable
	// record is gone but certificates remain, and on its own it trusted the raw
	// key alone: any future caller reaching the service without that outer
	// binding could recover a certificate minted for a DIFFERENT workload in the
	// same tenant. Binding the subject costs nothing — a genuine retry presents
	// the same attestation and so derives the same key.
	idemKey := "attested-issue:" + att.Subject + ":" + idempotencyKey
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

	spiffeID, err := attestedSPIFFEID(s.trustDomain, tenantID, att.Method, att.Subject)
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
		// The workload supplied only its public key. Record that custody fact
		// through the certificate event; storage and exportability stay unknown.
		KeyOrigin: string(custody.OriginRequester),
	}); err != nil {
		return api.AttestedSVID{}, err
	}
	return s.finish(ctx, tenantID, verifier, att, certDER, ttl, true)
}

func (s *attestedIssuerService) ttl(seconds int64) time.Duration {
	if seconds <= 0 {
		return s.defaultTTL
	}
	// Compare seconds before converting: a hostile int64 must not overflow a
	// nanosecond duration and silently fall back to a different lifetime.
	if s.maxTTL > 0 && seconds > int64(s.maxTTL/time.Second) {
		return s.maxTTL
	}
	return time.Duration(seconds) * time.Second
}

func (s *attestedIssuerService) attestorsForMethod(ctx context.Context, tenantID, method string) ([]attest.Attestor, error) {
	return resolveWorkloadAttestors(ctx, s.store, s.attestors, tenantID, method)
}

// resolveWorkloadAttestors is shared by direct, approved and brokered issuance.
// Only enabled public trust in the requesting tenant participates in verification.
func resolveWorkloadAttestors(ctx context.Context, st *store.Store, processAttestors []attest.Attestor, tenantID, method string) ([]attest.Attestor, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("tenant is required to resolve workload attestation trust")
	}
	var candidates []attest.Attestor
	for _, a := range processAttestors {
		if a != nil && a.Method() == method {
			candidates = append(candidates, a)
		}
	}
	if st != nil {
		sources, err := st.ListEnabledWorkloadAttesterTrustSources(ctx, tenantID, method)
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
		SPIFFEID:       certificateSPIFFEID(certDER),
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

func attestedSPIFFEID(trustDomain, tenantID, method, subject string) (string, error) {
	return workloadSPIFFEID(trustDomain, workloadIdentityScope{TenantID: tenantID, Method: method, Kind: "attested"}, subject)
}

func attestedIssuanceAuditor(log *events.Log) auditsink.Auditor {
	if log == nil {
		return auditsink.Nop{}
	}
	return audit.NewAuditor(log)
}

// attestedIssuanceFromConfig maps the operator's config onto the served mint.
//
// The attestors are NOT process-supplied here. Each request builds a
// tenant-scoped verifier from that tenant's enabled workload attester trust
// sources, which is the self-serve path the trust-source API already exists to
// feed. Baking a process-wide attestor list into config would make one tenant's
// trust decision every tenant's.
func attestedIssuanceFromConfig(c config.AttestedIssuance) AttestedIssuanceConfig {
	out := AttestedIssuanceConfig{Enabled: c.Enabled, TrustDomain: strings.TrimSpace(c.TrustDomain)}
	// A malformed duration is left at zero so newAttestedIssuerService applies
	// the built-in bound. config validation reports the parse error; silently
	// substituting a LONGER lifetime than the operator wrote would be the
	// dangerous direction, and zero cannot do that.
	if d, err := time.ParseDuration(strings.TrimSpace(c.DefaultTTL)); err == nil {
		out.DefaultTTL = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.MaxTTL)); err == nil {
		out.MaxTTL = d
	}
	return out
}
