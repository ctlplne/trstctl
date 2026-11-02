// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"

	"trstctl.com/trstctl/internal/projections"
)

// The secrets workspace (A235): each change is one event.

// CreateSecretProject records a project and its first environments.
func (o *Orchestrator) CreateSecretProject(ctx context.Context, tenantID string, created projections.SecretProjectCreated) error {
	return o.emitSecretProjectEvent(ctx, tenantID, projections.EventSecretProjectCreated, created)
}

// AddSecretProjectEnvironment records a new environment of a project.
func (o *Orchestrator) AddSecretProjectEnvironment(ctx context.Context, tenantID string, added projections.SecretProjectEnvironmentAdded) error {
	return o.emitSecretProjectEvent(ctx, tenantID, projections.EventSecretProjectEnvironmentAdded, added)
}

// GrantSecretProjectMember records a subject's access to a project.
func (o *Orchestrator) GrantSecretProjectMember(ctx context.Context, tenantID string, granted projections.SecretProjectMemberGranted) error {
	return o.emitSecretProjectEvent(ctx, tenantID, projections.EventSecretProjectMemberGranted, granted)
}

// RevokeSecretProjectMember records that a subject no longer has access.
func (o *Orchestrator) RevokeSecretProjectMember(ctx context.Context, tenantID string, revoked projections.SecretProjectMemberRevoked) error {
	return o.emitSecretProjectEvent(ctx, tenantID, projections.EventSecretProjectMemberRevoked, revoked)
}

func (o *Orchestrator) emitSecretProjectEvent(ctx context.Context, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, eventType, tenantID, data)
	return err
}
