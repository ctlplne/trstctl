package server

import (
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// GovernanceFactory is supplied by the tagged EE attach seam when Enterprise
// governance is licensed. Nil leaves compliance evidence-pack routes unmounted.
type GovernanceFactory func(GovernanceFactoryDeps) (api.ComplianceEvidenceService, error)

// GovernanceFactoryDeps are the core mechanisms a licensed governance surface may
// use. Audit, graph/store, and signing stay core; ee/governance owns the report
// policy/templates and evidence-pack implementation.
type GovernanceFactoryDeps struct {
	Audit  *audit.Service
	Store  *store.Store
	Signer crypto.DigestSigner
}

func (s *Server) buildComplianceEvidenceService(d Deps, auditSvc *audit.Service) (api.ComplianceEvidenceService, error) {
	if d.GovernanceFactory == nil || auditSvc == nil || d.Store == nil {
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
	return d.GovernanceFactory(GovernanceFactoryDeps{Audit: auditSvc, Store: d.Store, Signer: signer})
}
