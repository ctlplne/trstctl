// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/store"
)

// NewFactory adapts Enterprise governance evidence packs to the core server seam.
func NewFactory() server.GovernanceFactory {
	return func(d server.GovernanceFactoryDeps) (api.ComplianceEvidenceService, error) {
		if d.Audit == nil || d.Store == nil {
			return nil, nil
		}
		if d.Signer == nil {
			return nil, errors.New("governance: compliance evidence signer is required")
		}
		return &evidenceService{audit: d.Audit, store: d.Store, signer: d.Signer}, nil
	}
}

type evidenceService struct {
	audit      *audit.Service
	store      *store.Store
	signer     crypto.DigestSigner
	now        func() time.Time
	buildGraph func(context.Context, *store.Store, string) (*graph.Graph, error)
}

func (s *evidenceService) ExportEvidencePack(ctx context.Context, tenantID string, framework api.ComplianceFramework) (api.ComplianceEvidencePack, error) {
	if tenantID == "" {
		return api.ComplianceEvidencePack{}, errors.New("governance: compliance evidence requires a tenant")
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	through := now().UTC()
	window := EvidenceWindow{From: through.Add(-DefaultEvidenceWindow), Through: through}
	records, err := s.audit.Search(ctx, audit.Query{TenantID: tenantID, Since: window.From, Until: window.Through})
	if err != nil {
		return api.ComplianceEvidencePack{}, fmt.Errorf("governance: read audit evidence: %w", err)
	}
	buildGraph := graph.Build
	if s.buildGraph != nil {
		buildGraph = s.buildGraph
	}
	g, err := buildGraph(ctx, s.store, tenantID)
	if err != nil {
		return api.ComplianceEvidencePack{}, fmt.Errorf("governance: build compliance graph: %w", err)
	}
	reporter := New(tenantID, s.signer)
	report, err := reporter.Generate(framework, records, g, window)
	if err != nil {
		return api.ComplianceEvidencePack{}, fmt.Errorf("governance: generate compliance report: %w", err)
	}
	signed, err := reporter.Export(report)
	if err != nil {
		return api.ComplianceEvidencePack{}, fmt.Errorf("governance: sign compliance evidence: %w", err)
	}
	return api.ComplianceEvidencePack{
		Format:       api.ComplianceEvidencePackFormat,
		Framework:    string(framework),
		SignedExport: json.RawMessage(append([]byte(nil), signed...)),
		PublicKeyDER: append([]byte(nil), s.signer.Public().DER...),
		Custody:      report.Custody,
	}, nil
}

// PolicySource is the Enterprise governance policy source consulted by core
// privacy retention. A nil or empty override set means core defaults apply.
type PolicySource struct {
	retention map[string]privacy.RetentionPolicy
}

// NewPolicySource builds a source with optional tenant-specific retention
// overrides. The map is copied so callers can discard or mutate their input.
func NewPolicySource(retention map[string]privacy.RetentionPolicy) *PolicySource {
	cp := map[string]privacy.RetentionPolicy{}
	for tenantID, policy := range retention {
		cp[tenantID] = policy.WithDefaults()
	}
	return &PolicySource{retention: cp}
}

func (s *PolicySource) RetentionPolicy(_ context.Context, tenantID string, base privacy.RetentionPolicy) (privacy.RetentionPolicy, bool, error) {
	if s == nil {
		return base.WithDefaults(), false, nil
	}
	policy, ok := s.retention[tenantID]
	if !ok {
		return base.WithDefaults(), false, nil
	}
	return policy.WithDefaults(), true, nil
}
