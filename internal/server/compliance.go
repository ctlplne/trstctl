package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

type complianceEvidenceService struct {
	audit  *audit.Service
	store  *store.Store
	signer crypto.DigestSigner
}

func (s *Server) buildComplianceEvidenceService(d Deps, auditSvc *audit.Service) (api.ComplianceEvidenceService, error) {
	if auditSvc == nil || d.Store == nil {
		return nil, nil
	}
	signer := d.ComplianceSigner
	if signer == nil {
		generated, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			return nil, fmt.Errorf("server: generate compliance evidence signing key: %w", err)
		}
		s.complianceSigner = generated
		signer = generated
	}
	return &complianceEvidenceService{audit: auditSvc, store: d.Store, signer: signer}, nil
}

func (s *complianceEvidenceService) ExportEvidencePack(ctx context.Context, tenantID string, framework compliance.Framework) (api.ComplianceEvidencePack, error) {
	if tenantID == "" {
		return api.ComplianceEvidencePack{}, errors.New("server: compliance evidence requires a tenant")
	}
	records, err := s.audit.Search(ctx, audit.Query{TenantID: tenantID})
	if err != nil {
		return api.ComplianceEvidencePack{}, fmt.Errorf("server: read audit evidence: %w", err)
	}
	g, err := graph.Build(ctx, s.store, tenantID)
	if err != nil {
		return api.ComplianceEvidencePack{}, fmt.Errorf("server: build compliance graph: %w", err)
	}
	reporter := compliance.New(tenantID, s.signer)
	report, err := reporter.Generate(framework, complianceAuditRecords(records), g)
	if err != nil {
		return api.ComplianceEvidencePack{}, fmt.Errorf("server: generate compliance report: %w", err)
	}
	signed, err := reporter.Export(report)
	if err != nil {
		return api.ComplianceEvidencePack{}, fmt.Errorf("server: sign compliance evidence: %w", err)
	}
	return api.ComplianceEvidencePack{
		Format:       api.ComplianceEvidencePackFormat,
		Framework:    string(framework),
		SignedExport: json.RawMessage(append([]byte(nil), signed...)),
		PublicKeyDER: append([]byte(nil), s.signer.Public().DER...),
	}, nil
}

func complianceAuditRecords(records []audit.Record) []auditsink.Record {
	out := make([]auditsink.Record, 0, len(records))
	for _, r := range records {
		out = append(out, auditsink.Record{
			Type:     r.Type,
			TenantID: r.TenantID,
			Data:     append([]byte(nil), r.Data...),
		})
	}
	return out
}
