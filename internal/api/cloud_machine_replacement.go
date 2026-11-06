// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/store"
)

type CloudReplacementPreparation struct {
	CommandID  string
	LeaseID    string
	Phase      string
	Version    int
	ExpiresAt  *time.Time
	VerifyMode string
}

func cloudReplacementBinding(plan change.Record) string {
	return change.PublicationBinding(plan)
}

// PrepareCloudReplacement is an internal outbox seam. It reuses the existing
// durable publication command and returns public progress, never credentials.
func (a *API) PrepareCloudReplacement(ctx context.Context, tenantID, id string) (CloudReplacementPreparation, error) {
	plan, err := a.store.GetCloudMachineChange(ctx, tenantID, id)
	if err != nil {
		return CloudReplacementPreparation{}, err
	}
	if plan.Intent.Action != change.ReplaceKey || (plan.State != change.Queued && plan.State != change.Preparing) {
		return CloudReplacementPreparation{}, errors.New("cloud replacement is not in its approved preparation phase")
	}
	ttl := plan.Intent.ReplacementTTLSeconds
	command, err := a.queueDynamicLeaseRotationBound(ctx, tenantID, "cloud-replacement:"+id, cloudReplacementBinding(plan), secretRotationRequest{Provider: "dynamic-lease:" + plan.Intent.ReplacementProviderID, Key: plan.Intent.ReplacementRole, OldRef: staticRotationNoPredecessor, TTLSeconds: &ttl}, plan.Intent.ReplacementExpectedVersion, plan.ID)
	if err != nil {
		return CloudReplacementPreparation{}, err
	}
	if command.ExpectedVersion != plan.Intent.ReplacementExpectedVersion {
		return CloudReplacementPreparation{}, errors.New("replacement publication command has another predecessor version")
	}
	return CloudReplacementPreparation{CommandID: command.ID, LeaseID: command.NewRef, Phase: command.Phase, Version: command.ResultVersion, ExpiresAt: command.NewExpiresAt, VerifyMode: command.VerifyMode}, nil
}

// cloudReplacementStageParent bounds the native issuance by the original exact
// approval deadline. Ordinary dynamic-lease publication retains its own rules.
func (a *API) cloudReplacementStageParent(ctx context.Context, command store.SecretStaticRotationCommand) (*change.Record, error) {
	if command.CloudChangeID == "" {
		return nil, nil
	}
	plan, err := a.store.GetCloudMachineChange(ctx, command.TenantID, command.CloudChangeID)
	if err != nil {
		return nil, err
	}
	if cloudReplacementBinding(plan) != command.RequestBinding || plan.Intent.Action != change.ReplaceKey || (plan.State != change.Queued && plan.State != change.Preparing) || command.Provider != "dynamic-lease:"+plan.Intent.ReplacementProviderID || command.Key != plan.Intent.ReplacementRole || command.ExpectedVersion != plan.Intent.ReplacementExpectedVersion || command.TTLSeconds != plan.Intent.ReplacementTTLSeconds {
		return nil, errors.New("cloud replacement publication authority changed")
	}
	configured, found := a.secrets.configuredDynamicSecretProvider(command.TenantID, plan.Intent.ReplacementProviderID)
	if !found || configured.ConfigurationRevision != plan.Intent.ReplacementProviderRevision {
		return nil, errors.New("approved replacement provider revision changed before publication")
	}
	if !time.Now().Before(plan.ExpiresAt) {
		return nil, errors.New("cloud replacement approval deadline expired before native issuance")
	}
	if command.Phase == store.SecretStaticRotationQueued && !time.Now().Add(time.Duration(command.TTLSeconds)*time.Second).Before(plan.ExpiresAt) {
		operation, err := a.store.GetDynamicSecretOperationByIdempotencyKey(ctx, command.TenantID, "dlrot-issue:"+command.ID)
		if err != nil {
			return nil, errors.New("cloud replacement native TTL cannot fit its remaining approval window")
		}
		lease, err := a.store.GetDynamicSecretLease(ctx, command.TenantID, operation.LeaseID)
		if err != nil || lease.HardExpiresAt.After(plan.ExpiresAt) || !time.Now().Before(lease.HardExpiresAt) {
			return nil, errors.New("cloud replacement native TTL cannot fit its remaining approval window")
		}
	}
	return &plan, nil
}
