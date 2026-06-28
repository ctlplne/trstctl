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
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
)

// ExternalCA is one configured upstream CA registry entry served by the control
// plane. ID is the operator-facing stable selector; Type is the integration kind
// (for example "letsencrypt", "digicert", "adcs", "awspca"). CA is the already
// constructed built-in integration and may hold provider credentials internally.
type ExternalCA struct {
	ID   string
	Type string
	CA   ca.CA
}

type externalCARegistry struct {
	items []api.ExternalCA
	byID  map[string]externalCAEntry
}

type externalCAEntry struct {
	meta api.ExternalCA
	svc  *ca.IssuanceService
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
		if cfg.CA == nil {
			return nil, fmt.Errorf("server: external CA %q has no CA implementation", id)
		}
		if _, exists := reg.byID[id]; exists {
			return nil, fmt.Errorf("server: duplicate external CA id %q", id)
		}
		typ := strings.TrimSpace(cfg.Type)
		if typ == "" {
			typ = cfg.CA.Name()
		}
		drain := func(ctx context.Context) error {
			if s.obHandler == nil {
				return fmt.Errorf("server: external CA outbox handler is not configured")
			}
			return s.Drain(ctx)
		}
		meta := api.ExternalCA{ID: id, Type: typ, Name: cfg.CA.Name(), Status: "available"}
		reg.byID[id] = externalCAEntry{
			meta: meta,
			svc:  ca.NewIssuanceService(cfg.CA, idem, s.outbox, d.Store, ca.WithAuditLog(d.Log), ca.WithOutboxIssueWorker(id, drain)),
		}
		reg.items = append(reg.items, meta)
	}
	sort.Slice(reg.items, func(i, j int) bool { return reg.items[i].ID < reg.items[j].ID })
	s.externalCAs = reg
	return reg, nil
}

func (r *externalCARegistry) ListExternalCAs(_ context.Context, _ string) ([]api.ExternalCA, error) {
	out := make([]api.ExternalCA, len(r.items))
	copy(out, r.items)
	return out, nil
}

func (r *externalCARegistry) IssueExternalCA(ctx context.Context, tenantID, id, idempotencyKey string, req api.ExternalCAIssueRequest) (api.ExternalCAIssuedCertificate, error) {
	id = strings.TrimSpace(id)
	entry, ok := r.byID[id]
	if !ok {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: %s", api.ErrExternalCANotFound, id)
	}
	if tenantID == "" {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: missing tenant", api.ErrExternalCAInvalid)
	}
	if idempotencyKey == "" {
		return api.ExternalCAIssuedCertificate{}, fmt.Errorf("%w: missing idempotency key", api.ErrExternalCAInvalid)
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
		TenantID:      tenantID,
		CSR:           req.CSRDER,
		DNSNames:      req.DNSNames,
		TTL:           ttl,
		ProfileName:   req.ProfileName,
		Protocol:      "api",
		RequestedEKUs: req.RequestedEKUs,
	}, idempotencyKey+":external-ca:"+id)
	if err != nil {
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
	return entry.svc.DeliverExternalIssue(ctx, m)
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
