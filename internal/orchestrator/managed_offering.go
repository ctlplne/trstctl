// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

const ManagedOfferingDeploymentModel = "managed_provider"

// ManagedTenantProvisionRequest is the provider-plane command body for creating
// a hosted tenant. It is intentionally non-secret: credential handoff for a
// managed service happens through the normal tenant-scoped token/session paths,
// not through this topology command.
type ManagedTenantProvisionRequest struct {
	TenantID      string `json:"tenant_id"`
	Name          string `json:"name"`
	Region        string `json:"region,omitempty"`
	DataResidency string `json:"data_residency,omitempty"`
	Plan          string `json:"plan,omitempty"`
	SupportTier   string `json:"support_tier,omitempty"`
	SLOTier       string `json:"slo_tier,omitempty"`
}

type ManagedTenant struct {
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	ProviderTenantID string    `json:"provider_tenant_id"`
	DeploymentModel  string    `json:"deployment_model"`
	Managed          bool      `json:"managed"`
	Region           string    `json:"region,omitempty"`
	DataResidency    string    `json:"data_residency,omitempty"`
	Plan             string    `json:"plan,omitempty"`
	SupportTier      string    `json:"support_tier,omitempty"`
	SLOTier          string    `json:"slo_tier,omitempty"`
	ProvisionedBy    string    `json:"provisioned_by,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	EventSequence    uint64    `json:"event_sequence"`
}

// ProvisionManagedTenant appends the hosted tenant's tenant.registered event and
// lets the projector build the tenant row. The provider tenant is recorded as
// event metadata; it is not used as the row's tenant_id, so the hosted tenant gets
// its own RLS boundary from the first projected row.
func (o *Orchestrator) ProvisionManagedTenant(
	ctx context.Context,
	providerTenantID, idempotencyKey string,
	in ManagedTenantProvisionRequest,
) (ManagedTenant, error) {
	if o == nil || o.log == nil || o.proj == nil || o.store == nil || o.durableIdem == nil {
		return ManagedTenant{}, errors.New("orchestrator: managed offering is not configured")
	}
	providerTenantID = strings.TrimSpace(providerTenantID)
	if providerTenantID == "" {
		return ManagedTenant{}, errors.New("orchestrator: provider tenant id is required")
	}
	in = normalizeManagedTenantProvision(in)
	if err := validateManagedTenantProvision(in); err != nil {
		return ManagedTenant{}, err
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return ManagedTenant{}, errors.New("orchestrator: managed tenant idempotency key is required")
	}
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	requestMaterial, err := json.Marshal(struct {
		ProviderTenantID string                        `json:"provider_tenant_id"`
		Request          ManagedTenantProvisionRequest `json:"request"`
	}{
		ProviderTenantID: providerTenantID,
		Request:          in,
	})
	if err != nil {
		return ManagedTenant{}, err
	}
	ev, err := ExecuteTenantRegistration(
		ctx, o.log, o.store, o.proj, o.durableIdem,
		TenantRegistrationCommand{
			TenantID: in.TenantID, Name: in.Name, IdempotencyKey: idempotencyKey,
			RequestMaterial: requestMaterial,
			PayloadAt: func(eventTime time.Time) ([]byte, error) {
				return json.Marshal(projections.ManagedTenantRegistered{
					Name: in.Name,
					ManagedOffering: projections.ManagedOfferingMetadata{
						Enabled:          true,
						DeploymentModel:  ManagedOfferingDeploymentModel,
						ProviderTenantID: providerTenantID,
						Region:           in.Region,
						DataResidency:    in.DataResidency,
						Plan:             in.Plan,
						SupportTier:      in.SupportTier,
						SLOTier:          in.SLOTier,
						ProvisionedBy:    actor,
						ProvisionedAt:    eventTime.UTC().Truncate(time.Second),
					},
				})
			},
		},
	)
	if err != nil {
		return ManagedTenant{}, err
	}
	projected, err := o.store.GetTenant(ctx, in.TenantID)
	if err != nil {
		return ManagedTenant{}, fmt.Errorf("orchestrator: load projected managed tenant %s: %w", in.TenantID, err)
	}
	return ManagedTenant{
		TenantID:         projected.TenantID,
		Name:             projected.Name,
		ProviderTenantID: providerTenantID,
		DeploymentModel:  ManagedOfferingDeploymentModel,
		Managed:          true,
		Region:           in.Region,
		DataResidency:    in.DataResidency,
		Plan:             in.Plan,
		SupportTier:      in.SupportTier,
		SLOTier:          in.SLOTier,
		ProvisionedBy:    actor,
		CreatedAt:        projected.CreatedAt,
		EventSequence:    ev.Sequence,
	}, nil
}

func normalizeManagedTenantProvision(in ManagedTenantProvisionRequest) ManagedTenantProvisionRequest {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.Name = strings.TrimSpace(in.Name)
	in.Region = strings.TrimSpace(in.Region)
	in.DataResidency = strings.TrimSpace(in.DataResidency)
	in.Plan = strings.TrimSpace(in.Plan)
	in.SupportTier = strings.TrimSpace(in.SupportTier)
	in.SLOTier = strings.TrimSpace(in.SLOTier)
	return in
}

func validateManagedTenantProvision(in ManagedTenantProvisionRequest) error {
	if in.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if _, err := uuid.Parse(in.TenantID); err != nil {
		return errors.New("tenant_id must be a UUID")
	}
	if in.Name == "" {
		return errors.New("name is required")
	}
	if len(in.Name) > 120 {
		return errors.New("name must be 120 characters or fewer")
	}
	for label, value := range map[string]string{
		"region":         in.Region,
		"data_residency": in.DataResidency,
		"plan":           in.Plan,
		"support_tier":   in.SupportTier,
		"slo_tier":       in.SLOTier,
	} {
		if len(value) > 80 {
			return fmt.Errorf("%s must be 80 characters or fewer", label)
		}
	}
	return nil
}
