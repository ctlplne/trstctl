// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/store"
)

// assuranceAssembler builds credential assurance records (A179) from this
// server's store, audit chain and orchestrator. The API serves them one at a
// time and compliance evidence packs carry the recent ones.
func (s *Server) assuranceAssembler(st *store.Store, auditSvc *audit.Service) *assurance.Assembler {
	if st == nil {
		return nil
	}
	assembler := &assurance.Assembler{Store: st, Audit: auditSvc}
	if s.orch != nil {
		assembler.Issuance = func(ctx context.Context, tenantID string, cert store.Certificate) (assurance.IssuanceEvidence, error) {
			issued, err := s.orch.CertificateIssuanceEvidence(ctx, tenantID, cert)
			return assurance.IssuanceEvidence{EventID: issued.EventID, Binding: issued.Binding, Approval: issued.Approval}, err
		}
	}
	return assembler
}
