// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

const complianceEvidenceHandle = "compliance-evidence"

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

func (s *Server) buildComplianceEvidenceService(ctx context.Context, d Deps, auditSvc *audit.Service) (api.ComplianceEvidenceService, error) {
	if d.GovernanceFactory == nil || auditSvc == nil || d.Store == nil {
		return nil, nil
	}
	signer := d.ComplianceSigner
	if signer == nil {
		if d.Signer == nil || d.Signer.Client() == nil {
			return nil, errors.New("server: governance requires the isolated signer for compliance evidence")
		}
		var err error
		signer, err = bindComplianceEvidenceSigner(ctx, d.Signer.Client())
		if err != nil {
			return nil, fmt.Errorf("server: bind compliance evidence signer: %w", err)
		}
	}
	return d.GovernanceFactory(GovernanceFactoryDeps{Audit: auditSvc, Store: d.Store, Signer: signer})
}

// bindComplianceEvidenceSigner gives every restart the same independently
// constrained signer-keystore handle. The audit-export key is a separate
// authority: governance cannot reuse it to make a report appear to be a core
// history export. The signer enforces the evidence purpose on this handle.
func bindComplianceEvidenceSigner(ctx context.Context, client *signing.Client) (crypto.DigestSigner, error) {
	remote, err := client.SignerForHandleWithPurpose(ctx, complianceEvidenceHandle, signing.PurposeAuditEvidence)
	if status.Code(err) == codes.NotFound {
		remote, err = client.GenerateConstrainedKeyHandle(ctx, crypto.ECDSAP256, complianceEvidenceHandle,
			[]signing.KeyPurpose{signing.PurposeAuditEvidence}, signing.PurposeAuditEvidence)
		if status.Code(err) == codes.AlreadyExists {
			remote, err = client.SignerForHandleWithPurpose(ctx, complianceEvidenceHandle, signing.PurposeAuditEvidence)
		}
	}
	if err != nil {
		return nil, err
	}
	if remote.Algorithm() != crypto.ECDSAP256 {
		return nil, fmt.Errorf("compliance evidence handle has unexpected algorithm %s", remote.Algorithm())
	}
	return remote, nil
}
