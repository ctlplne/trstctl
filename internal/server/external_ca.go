// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/enrollmentdiag"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// ExternalCAFactory constructs one short-lived upstream CA client for one outbox
// delivery. cleanup MUST destroy every credential buffer and close idle network
// connections. The registry stores the factory, never the authority-bearing
// material used by the client (AN-8).
type ExternalCAFactory func(context.Context) (implementation ca.CA, cleanup func(), err error)

// ExternalCA is one configured upstream CA registry entry served by the control
// plane. ID is the operator-facing stable selector; Type is the integration kind
// (for example "letsencrypt", "digicert", "adcs", "awspca"). Production wiring
// uses Name+Factory so credentials are loaded just in time. CA remains as a
// deliberate injection seam for already-constructed test and signed-WASM CAs.
type ExternalCA struct {
	ID       string
	Type     string
	Name     string
	TenantID string
	// Endpoint is non-secret operator routing metadata used to bind refusal
	// diagnostics to the exact D2 prove-fixed target.
	Endpoint string
	CA       ca.CA
	Factory  ExternalCAFactory
	// ReplaySafety may opt a custom adapter into retry-after-ambiguous-failure
	// only when its receiver enforces ca.ProviderIdempotencyKey.
	ReplaySafety ca.ExternalIssueReplaySafety
	// UpstreamDNS01 records that this ACME authority validates names through the
	// tenant's DNS-01 provider configs. It is non-secret routing metadata used by
	// the endpoint-lifecycle preview to fail closed when no provider config can
	// publish a challenge for the requested name.
	UpstreamDNS01 bool
}

type factoryExternalCA struct {
	name    string
	factory ExternalCAFactory
}

func (c factoryExternalCA) Name() string { return c.name }

func (c factoryExternalCA) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	implementation, cleanup, err := c.factory(ctx)
	if err != nil {
		return ca.Certificate{}, err
	}
	if cleanup != nil {
		defer cleanup()
	}
	if implementation == nil {
		return ca.Certificate{}, errors.New("external CA factory returned no implementation")
	}
	return implementation.Issue(ctx, req)
}

type externalCAOperationRefContextKey struct{}

// diagnosticExternalCA observes the raw provider refusal before AD CS's
// at-most-once guard intentionally turns every ambiguous error into
// ErrEffectIndeterminate. After that guard, the stable HRESULT is gone.
type diagnosticExternalCA struct {
	inner       ca.CA
	authorityID string
	endpoint    string
	orch        *orchestrator.Orchestrator
}

func (c diagnosticExternalCA) Name() string { return c.inner.Name() }

func (c diagnosticExternalCA) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	certificate, err := c.inner.Issue(ctx, req)
	if err == nil || c.orch == nil {
		return certificate, err
	}
	operationKey, _ := ctx.Value(externalCAOperationRefContextKey{}).(string)
	if operationKey == "" {
		operationKey = req.ProviderIdempotencyKey
	}
	diagnosis := enrollmentdiag.ClassifyADCS(enrollmentdiag.StepAuthorize, err.Error(), err).WithEvidence(enrollmentdiag.Evidence{
		OperationRef: "external-ca:" + c.authorityID + ":" + operationKey,
		IdentityRef:  externalCAIdentityRef(req), EndpointRef: strings.TrimSpace(c.endpoint),
	})
	if diagnosticErr := c.orch.RecordEnrollmentDiagnosis(ctx, req.TenantID, diagnosis); diagnosticErr != nil {
		return ca.Certificate{}, errors.Join(err, fmt.Errorf("server: persist AD CS refusal diagnosis: %w", diagnosticErr))
	}
	return ca.Certificate{}, err
}

type externalCARegistry struct {
	items []api.ExternalCA
	byID  map[string]externalCAEntry
}

type externalCAEntry struct {
	meta     api.ExternalCA
	tenantID string
	svc      *ca.IssuanceService
}

func (s *Server) buildExternalCAService(d Deps, idem *orchestrator.Idempotency) (api.ExternalCAService, error) {
	externalCAs := append([]ExternalCA(nil), d.ExternalCAs...)
	if s.plugins != nil {
		externalCAs = append(externalCAs, s.plugins.ExternalCAs()...)
	}
	if len(externalCAs) == 0 {
		return nil, nil
	}
	if d.Store == nil || idem == nil || s.outbox == nil {
		return nil, fmt.Errorf("server: external CA registry requires store, idempotency, and outbox")
	}
	reg := &externalCARegistry{byID: map[string]externalCAEntry{}}
	for _, cfg := range externalCAs {
		id := strings.TrimSpace(cfg.ID)
		if id == "" {
			return nil, fmt.Errorf("server: external CA registry entry has empty id")
		}
		if (cfg.CA == nil) == (cfg.Factory == nil) {
			return nil, fmt.Errorf("server: external CA %q must configure exactly one CA implementation or factory", id)
		}
		if _, exists := reg.byID[id]; exists {
			return nil, fmt.Errorf("server: duplicate external CA id %q", id)
		}
		implementation := cfg.CA
		name := strings.TrimSpace(cfg.Name)
		if cfg.Factory != nil {
			if name == "" {
				return nil, fmt.Errorf("server: external CA %q factory has no display name", id)
			}
			implementation = factoryExternalCA{name: name, factory: cfg.Factory}
		} else if name == "" {
			name = cfg.CA.Name()
		}
		typ := strings.TrimSpace(cfg.Type)
		if typ == "" {
			typ = implementation.Name()
		}
		if strings.EqualFold(typ, "adcs") && s.orch != nil {
			implementation = diagnosticExternalCA{
				inner: implementation, authorityID: id, endpoint: strings.TrimSpace(cfg.Endpoint), orch: s.orch,
			}
		}
		meta := api.ExternalCA{ID: id, Type: typ, Name: name, Status: "available", UpstreamDNS01: cfg.UpstreamDNS01}
		replaySafety := cfg.ReplaySafety
		if externalCATypeHasReceiverIdempotency(typ) {
			replaySafety = ca.ExternalIssueReconciled
		}
		reg.byID[id] = externalCAEntry{
			meta: meta, tenantID: strings.TrimSpace(cfg.TenantID),
			svc: ca.NewIssuanceService(implementation, idem, s.outbox, d.Store, ca.WithAuditLog(d.Log),
				ca.WithOutboxIssueWorker(id, s.wakeOutbox), ca.WithExternalIssueReplaySafety(replaySafety)),
		}
		reg.items = append(reg.items, meta)
	}
	sort.Slice(reg.items, func(i, j int) bool { return reg.items[i].ID < reg.items[j].ID })
	s.externalCAs = reg
	return reg, nil
}

func externalCATypeHasReceiverIdempotency(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "awspca", "aws-pca", "gcpcas", "gcp-cas":
		return true
	default:
		return false
	}
}

func (r *externalCARegistry) ListExternalCAs(_ context.Context, tenantID string) ([]api.ExternalCA, error) {
	out := make([]api.ExternalCA, 0, len(r.items))
	for _, item := range r.items {
		entry := r.byID[item.ID]
		if entry.tenantID == "" || entry.tenantID == tenantID {
			out = append(out, item)
		}
	}
	return out, nil
}

func (r *externalCARegistry) IssueExternalCA(ctx context.Context, tenantID, id, idempotencyKey, requestBinding string, req api.ExternalCAIssueRequest) (api.ExternalCAIssuedCertificate, error) {
	id = strings.TrimSpace(id)
	entry, ok := r.byID[id]
	if !ok {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: %s", api.ErrExternalCANotFound, id)
	}
	if entry.tenantID != "" && entry.tenantID != tenantID {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: %s", api.ErrExternalCANotFound, id)
	}
	if tenantID == "" {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: missing tenant", api.ErrExternalCAInvalid)
	}
	if idempotencyKey == "" {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: missing idempotency key", api.ErrExternalCAInvalid)
	}
	if requestBinding == "" {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: missing authenticated request binding", api.ErrExternalCAInvalid)
	}
	if len(req.CSRDER) == 0 {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: csr_pem is required", api.ErrExternalCAInvalid)
	}
	if len(req.DNSNames) == 0 {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: dns_names is required", api.ErrExternalCAInvalid)
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if req.TTLSeconds < 0 {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: ttl_seconds cannot be negative", api.ErrExternalCAInvalid)
	}
	cert, err := entry.svc.Issue(ctx, ca.IssueRequest{
		TenantID:       tenantID,
		CSR:            req.CSRDER,
		DNSNames:       req.DNSNames,
		TTL:            ttl,
		ProfileName:    req.ProfileName,
		Protocol:       "api",
		RequestedEKUs:  req.RequestedEKUs,
		RequestBinding: requestBinding,
	}, idempotencyKey+":external-ca:"+id)
	if err != nil {
		if errors.Is(err, store.ErrIdempotencyConflict) || errors.Is(err, orchestrator.ErrIdempotencyConflict) {
			return api.ExternalCAIssuedCertificate{}, orchestrator.ErrIdempotencyConflict
		}
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: %s", api.ErrExternalCAUpstream, externalCAUpstreamDetail(err))
	}
	return api.ExternalCAIssuedCertificate{
		CertificatePEM: string(cert.CertificatePEM),
		Serial:         cert.Serial,
		NotAfter:       cert.NotAfter,
		Issuer:         cert.Issuer,
	}, nil
}

func (r *externalCARegistry) DeliverExternalCAIssue(ctx context.Context, m orchestrator.Message) error {
	var payload ca.ExternalIssuePayload
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return fmt.Errorf("server: decode external CA issue payload: %w", err)
	}
	entry, ok := r.byID[payload.AuthorityID]
	if !ok {
		return fmt.Errorf("server: external CA outbox authority %q is not configured", payload.AuthorityID)
	}
	if entry.tenantID != "" && entry.tenantID != m.TenantID {
		return fmt.Errorf("server: external CA outbox tenant is not bound to authority %q", payload.AuthorityID)
	}
	ctx = context.WithValue(ctx, externalCAOperationRefContextKey{}, m.IdempotencyKey)
	return entry.svc.DeliverExternalIssue(ctx, m)
}

func externalCAIdentityRef(req ca.IssueRequest) string {
	for _, name := range req.DNSNames {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			return "dns:" + name
		}
	}
	if info, err := crypto.InspectCSR(req.CSR); err == nil {
		for _, name := range info.DNSNames {
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				return "dns:" + name
			}
		}
	}
	return "csr-sha256:" + crypto.SHA256Hex(req.CSR)
}

func externalCAUpstreamDetail(err error) string {
	switch {
	case errors.Is(err, netsec.ErrSSRFBlocked):
		return "external CA upstream endpoint blocked by outbound network policy"
	case errors.Is(err, context.DeadlineExceeded):
		return "external CA upstream request timed out"
	case errors.Is(err, context.Canceled):
		return "external CA upstream request canceled"
	default:
		return "external CA upstream request failed"
	}
}
